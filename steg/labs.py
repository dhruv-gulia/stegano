"""Repeatable experiments behind the detector, robustness, and damage labs."""

from __future__ import annotations

import io
import random

from PIL import Image

from .analysis import analyze
from .core import StegError, damage_payload, decode_with_stats, encode


def _cover_size(image: bytes) -> tuple[int, int]:
    with Image.open(io.BytesIO(image)) as img:
        return img.size


def detector_sweep(image: bytes, ecc: bool = True) -> tuple[list[dict], dict]:
    """Embed two incompressible payload sizes with noise off and on."""
    width, height = _cover_size(image)
    capacity = width * height * 3 // 8
    sizes = sorted({max(32, capacity // 20), max(64, capacity // 4)})
    rows = []
    for size in sizes:
        payload = random.Random(0xC0FFEE + size).randbytes(size)
        for noise in (False, True):
            stego, stats = encode(
                image, payload, "lab-detector-password", noise=noise, ecc=ecc
            )
            report = analyze(stego)
            rows.append(
                {
                    "message_bytes": size,
                    "noise": noise,
                    "psnr_db": stats["psnr_db"],
                    "fill_percent": stats["fill_percent"],
                    "chi_square": report["chi_square"],
                    "p_value": report["p_value"],
                    "chi_flagged": report["chi_flagged"],
                    "rs_delta": report["rs_delta"],
                    "rs_flagged": report["rs_flagged"],
                    "flagged": report["flagged"],
                    "ecc": stats["ecc"],
                    "ecc_bytes": stats["ecc_bytes"],
                }
            )
    hits = sum(1 for row in rows if row["flagged"])
    summary = {
        "rows": len(rows),
        "flagged": hits,
        "rate": round(100 * hits / len(rows), 1) if rows else 0.0,
        "width": width,
        "height": height,
        "chosen_ecc": ecc,
    }
    return rows, summary


def robustness_sweep(
    image: bytes,
    message: str | bytes,
    password: str,
    ecc: bool = True,
    noise: bool = True,
) -> list[dict]:
    """Encode once, apply lossy edits, then attempt the real decoder on each."""
    stego, stats = encode(image, message, password, noise=noise, ecc=ecc)
    with Image.open(io.BytesIO(stego)) as opened:
        rgb = opened.convert("RGB")

    variants: list[tuple[str, bytes]] = []
    buffer = io.BytesIO()
    rgb.save(buffer, "PNG")
    variants.append(("PNG re-save (control)", buffer.getvalue()))
    for quality in (95, 85, 70):
        buffer = io.BytesIO()
        rgb.save(buffer, "JPEG", quality=quality)
        variants.append((f"JPEG q{quality}", buffer.getvalue()))
    half = rgb.resize((max(1, rgb.width // 2), max(1, rgb.height // 2)), Image.Resampling.LANCZOS)
    buffer = io.BytesIO()
    half.save(buffer, "PNG")
    variants.append(("Resize 50%", buffer.getvalue()))
    restored = half.resize(rgb.size, Image.Resampling.LANCZOS)
    buffer = io.BytesIO()
    restored.save(buffer, "PNG")
    variants.append(("Resize 50% and back", buffer.getvalue()))
    left, top = rgb.width // 20, rgb.height // 20
    cropped = rgb.crop((left, top, rgb.width - left, rgb.height - top))
    buffer = io.BytesIO()
    cropped.save(buffer, "PNG")
    variants.append(("Crop 10%", buffer.getvalue()))

    wanted = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    rows = []
    for label, data in variants:
        row = {"transform": label, "recovered": False, "detail": "", "corrected": 0}
        try:
            decoded, meta = decode_with_stats(data, password)
            row["recovered"] = decoded == wanted
            row["corrected"] = meta["ecc_corrected"]
            row["detail"] = "message recovered" if row["recovered"] else "decoded a different message"
        except StegError as exc:
            row["detail"] = str(exc)
        rows.append(row)
    return rows, stats


def damage_demo(
    image: bytes,
    message: str | bytes,
    password: str,
    flips: int,
) -> list[dict]:
    """Encode with ECC on and off, flip the same number of payload bits, then decode."""
    wanted = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    rows = []
    for ecc in (True, False):
        stego, stats = encode(image, message, password, noise=False, ecc=ecc)
        damaged, info = damage_payload(stego, password, flips, seed=11)
        row = {
            "ecc": ecc,
            "flips": info["flips"],
            "correctable": info["ecc_correct"],
            "recovered": False,
            "corrected": 0,
            "detail": "",
            "psnr_db": stats["psnr_db"],
        }
        try:
            decoded, meta = decode_with_stats(damaged, password)
            row["recovered"] = decoded == wanted
            row["corrected"] = meta["ecc_corrected"]
            row["detail"] = "message recovered" if row["recovered"] else "decoded a different message"
        except StegError as exc:
            row["detail"] = str(exc)
        rows.append(row)
    return rows
