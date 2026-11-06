"""Steganalysis: the chi-square LSB-pair test and a legacy header scan."""

from __future__ import annotations

import io
import math
from collections import Counter
from pathlib import Path

from PIL import Image

from .core import StegError


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


def analyze(image: bytes | str | Path) -> dict:
    """Measure LSB-pair uniformity and look for the old sequential STEG1 header."""
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

    if legacy:
        verdict = "Sequential STEG1 payload found. This image was produced by the old v1 format."
        flagged = True
    elif p_value > 0.05:
        verdict = "LSB pairs are as uniform as replacement-style embedding would make them. Flagged as suspicious."
        flagged = True
    elif p_value < 0.01:
        verdict = "No LSB-pair equalisation detected. The image looks natural under this test."
        flagged = False
    else:
        verdict = "Inconclusive: the pairs sit between natural and replacement-style uniformity."
        flagged = False

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
        "flagged": flagged,
        "verdict": verdict,
    }
