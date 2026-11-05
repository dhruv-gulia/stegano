"""LSB steganography: payload bits replace the least significant bit of each
RGB channel. The payload is AES-GCM encrypted, so a wrong password fails
authentication instead of returning garbage.

Layout (bytes, MSB first):
    magic(5) | salt(16) | nonce(12) | plaintext_length(4) | ciphertext+tag
"""

from __future__ import annotations

import io
import os
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

from .metrics import mse, psnr

MAGIC = b"STEG1"
SALT_LEN = 16
NONCE_LEN = 12
LEN_LEN = 4
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + SALT_LEN + NONCE_LEN + LEN_LEN
KDF_ITERATIONS = 390_000


class StegError(Exception):
    """User-facing encode/decode failure."""


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
    except Exception as exc:  # Pillow raises several types for malformed files
        raise StegError("unsupported or corrupt image file") from exc


def capacity_bytes(image: bytes | str | Path | Image.Image) -> int:
    """Raw payload bytes the image can hold (53 bytes go to header + tag)."""
    img = image if isinstance(image, Image.Image) else _load_rgb(image)
    return (img.width * img.height * 3) // 8


def _key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    ).derive(password.encode("utf-8"))


def _write_lsb(pixels: bytearray, payload: bytes) -> None:
    for index, byte in enumerate(payload):
        base = index * 8
        for bit in range(8):
            pixels[base + bit] = (pixels[base + bit] & 0xFE) | ((byte >> (7 - bit)) & 1)


def _read_lsb(pixels: bytes, length: int) -> bytes:
    out = bytearray(length)
    for index in range(length):
        base = index * 8
        value = 0
        for bit in range(8):
            value = (value << 1) | (pixels[base + bit] & 1)
        out[index] = value
    return bytes(out)


def encode(
    image: bytes | str | Path,
    message: str | bytes,
    password: str,
) -> tuple[bytes, dict]:
    """Return (stego PNG bytes, metrics). Raises StegError on bad input."""
    if not password:
        raise StegError("password must not be empty")
    data = message.encode("utf-8") if isinstance(message, str) else message
    img = _load_rgb(image)
    capacity = (img.width * img.height * 3) // 8
    max_message = capacity - HEADER_LEN - TAG_LEN
    if len(data) > max_message:
        raise StegError(
            f"message too large: {len(data)} bytes given, {max(0, max_message)} bytes fit "
            f"in a {img.width}x{img.height} image"
        )

    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    ciphertext = AESGCM(_key(password, salt)).encrypt(nonce, data, MAGIC)
    payload = MAGIC + salt + nonce + struct.pack(">I", len(data)) + ciphertext

    pixels = bytearray(img.tobytes())
    _write_lsb(pixels, payload)
    stego = Image.frombytes("RGB", img.size, bytes(pixels))

    buffer = io.BytesIO()
    stego.save(buffer, "PNG")
    result = {
        "width": img.width,
        "height": img.height,
        "capacity_bytes": capacity,
        "message_bytes": len(data),
        "payload_bytes": len(payload),
        "fill_percent": round(100 * len(payload) / capacity, 2),
        "mse": round(mse(img, stego), 4),
        "psnr_db": round(psnr(img, stego), 2),
    }
    return buffer.getvalue(), result


def decode(image: bytes | str | Path, password: str) -> bytes:
    """Return the hidden message. Raises StegError if absent or password wrong."""
    if not password:
        raise StegError("password must not be empty")
    img = _load_rgb(image)
    capacity = (img.width * img.height * 3) // 8
    if capacity < HEADER_LEN:
        raise StegError("image is too small to contain a payload")

    pixels = img.tobytes()
    header = _read_lsb(pixels, HEADER_LEN)
    if header[: len(MAGIC)] != MAGIC:
        raise StegError("no hidden message found in this image")

    salt = header[5:21]
    nonce = header[21:33]
    length = struct.unpack(">I", header[33:37])[0]
    total = HEADER_LEN + length + TAG_LEN
    if total > capacity:
        raise StegError("payload header is corrupt or the image was resized")

    payload = _read_lsb(pixels, total)
    try:
        return AESGCM(_key(password, salt)).decrypt(nonce, payload[HEADER_LEN:], MAGIC)
    except InvalidTag as exc:
        raise StegError("wrong password or corrupted payload") from exc
