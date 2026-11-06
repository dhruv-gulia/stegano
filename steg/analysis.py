"""Steganalysis: chi-square LSB-pair test, RS asymmetry, and a legacy scan."""

from __future__ import annotations

import io
import math
from collections import Counter
from pathlib import Path

from PIL import Image

from .core import StegError

RS_THRESHOLD = 0.02
_RS_MAX_GROUPS = 250_000


def _load_rgb(image: bytes | bytearray | str | Path) -> Image.Image:
    if isinstance(image, (bytes, bytearray)):
        source = io.BytesIO(image)
    else:
        source = Path(image)
        if not source.is_file():
            raise StegError(f"file not found: {source}")
    try:
        with Image.open(source) as img:
            return img.convert("RGB")
    except Exception as exc:
        raise StegError("unsupported or corrupt image file") from exc


def _upper_tail(chi: float, df: int) -> float:
    """Wilson-Hilferty normal approximation of the chi-square survival function."""
    z = ((chi / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    return 0.5 * math.erfc(z / math.sqrt(2))


def _discrimination(group: list[int]) -> int:
    return sum(abs(group[index + 1] - group[index]) for index in range(len(group) - 1))


def _flip(value: int, positive: bool) -> int:
    """F1 moves even values up and odd values down; F-1 is the reverse."""
    if positive:
        flipped = value + 1 if value % 2 == 0 else value - 1
    else:
        flipped = value - 1 if value % 2 == 0 else value + 1
    return max(0, min(255, flipped))


def _rs_analysis(img: Image.Image) -> dict:
    """Regular-singular asymmetry on non-overlapping groups of four luminance pixels."""
    data = img.convert("L").tobytes()
    groups = len(data) // 4
    if not groups:
        return {
            "groups": 0,
            "regular_pos": 0.0,
            "singular_pos": 0.0,
            "regular_neg": 0.0,
            "singular_neg": 0.0,
            "delta": 0.0,
            "flagged": False,
        }
    step = max(1, groups // _RS_MAX_GROUPS)
    regular = {True: 0, False: 0}
    singular = {True: 0, False: 0}
    seen = 0
    for index in range(0, groups, step):
        group = list(data[index * 4 : index * 4 + 4])
        base = _discrimination(group)
        seen += 1
        for positive in (True, False):
            flipped = _discrimination([_flip(value, positive) for value in group])
            if flipped > base:
                regular[positive] += 1
            elif flipped < base:
                singular[positive] += 1
    delta = abs(regular[True] - regular[False]) + abs(singular[True] - singular[False])
    safe = max(seen, 1)
    return {
        "groups": seen,
        "regular_pos": round(regular[True] / safe, 4),
        "singular_pos": round(singular[True] / safe, 4),
        "regular_neg": round(regular[False] / safe, 4),
        "singular_neg": round(singular[False] / safe, 4),
        "delta": round(delta / safe, 4),
        "flagged": delta / safe > RS_THRESHOLD,
    }


def analyze(image: bytes | str | Path) -> dict:
    """Measure chi-square and RS structure and look for the old STEG1 header."""
    img = _load_rgb(image)
    pixels = img.tobytes()
    counts = Counter(pixels)
    chi = 0.0
    pairs = 0
    for low in range(0, 256, 2):
        even, odd = counts.get(low, 0), counts.get(low + 1, 0)
        total = even + odd
        if total == 0:
            continue
        expected = total / 2
        chi += ((even - expected) ** 2 + (odd - expected) ** 2) / expected
        pairs += 1
    df = max(pairs - 1, 1)
    p_value = _upper_tail(chi, df)

    header = bytearray()
    for index in range(5):
        byte = 0
        for bit in range(8):
            byte = (byte << 1) | (pixels[index * 8 + bit] & 1)
        header.append(byte)
    legacy = bytes(header) == b"STEG1"

    rs = _rs_analysis(img)
    chi_hit = p_value > 0.05
    if legacy:
        verdict = "Sequential STEG1 payload found. This image was produced by the old v1 format."
    elif chi_hit and rs["flagged"]:
        verdict = "Both chi-square and RS asymmetry flag replacement-style structure."
    elif chi_hit:
        verdict = "LSB pairs are as uniform as replacement-style embedding would make them. Flagged by chi-square."
    elif rs["flagged"]:
        verdict = "Chi-square is inconclusive, but the RS regular/singular asymmetry is elevated."
    else:
        verdict = "Neither chi-square nor RS crossed the screening thresholds."
    flagged = bool(legacy or chi_hit or rs["flagged"])

    return {
        "width": img.width,
        "height": img.height,
        "channels": img.width * img.height * 3,
        "chi_square": round(chi, 2),
        "dof": df,
        "p_value": round(p_value, 4),
        "pair_ratio": round(chi / df, 3),
        "lsb_ones": round(sum(pixels[i] & 1 for i in range(0, len(pixels), 97)) / len(range(0, len(pixels), 97)), 3),
        "legacy_header": legacy,
        "chi_flagged": chi_hit,
        "rs_delta": rs["delta"],
        "rs_regular_pos": rs["regular_pos"],
        "rs_singular_pos": rs["singular_pos"],
        "rs_regular_neg": rs["regular_neg"],
        "rs_singular_neg": rs["singular_neg"],
        "rs_groups": rs["groups"],
        "rs_flagged": rs["flagged"],
        "flagged": flagged,
        "verdict": verdict,
    }
