"""Steganography v2: AES-GCM payload scattered by a password-derived key.

Payload layout (not stored contiguously; every byte is split into bits and each
bit is written to a keyed channel position):
    salt(16) | nonce(12) | ciphertext_length(4) | flags(1) | ciphertext+tag

The key is stretched with scrypt, the header is located by a keyed XOF stream,
and the payload is scattered across the remaining RGB channels. Bits are written
with LSB matching (the channel moves by at most one) and unused channels get a
random low bit, so the whole LSB plane looks uniformly touched. No magic bytes
are stored: a wrong password fails the GCM tag instead of finding a signature.
"""

from __future__ import annotations

import array
import hashlib
import io
import os
import random
import struct
import zlib
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from PIL import Image

from .metrics import mse, psnr

SALT_LEN = 16
NONCE_LEN = 12
LEN_LEN = 4
FLAG_LEN = 1
TAG_LEN = 16
HEADER_LEN = SALT_LEN + NONCE_LEN + LEN_LEN + FLAG_LEN
FLAG_COMPRESSED = 1

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
_AAD = b"steg-v2"
_NO_MESSAGE = "no hidden message found, or wrong password"


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
    """Raw payload bytes the image can hold (49 bytes go to header + tag)."""
    img = image if isinstance(image, Image.Image) else _load_rgb(image)
    return (img.width * img.height * 3) // 8


def _master_key(password: str, width: int, height: int) -> bytes:
    """Stretch the password once per image size; the per-image salt refines it."""
    salt = struct.pack(">II", width, height) + b"steg-v2-master"
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        password.encode("utf-8")
    )


def _image_keys(master: bytes, salt: bytes) -> tuple[bytes, bytes]:
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=_AAD).derive(master)
    return okm[:32], okm[32:]


def _pick(seed: bytes, total: int, count: int, used: bytearray | None = None) -> array.array:
    """Deterministically sample `count` distinct channel indices from `total`."""
    bitmap = used if used is not None else bytearray(total)
    if count > total - sum(bitmap):
        raise StegError("payload does not fit in this image")
    out = array.array("I")
    block = 0
    while len(out) < count:
        chunk = hashlib.shake_256(seed + block.to_bytes(4, "big")).digest(4 * 4096)
        block += 1
        for offset in range(0, len(chunk), 4):
            index = int.from_bytes(chunk[offset : offset + 4], "big") % total
            if bitmap[index]:
                continue
            bitmap[index] = 1
            out.append(index)
            if len(out) == count:
                break
    return out


def _match(pixels: bytearray, index: int, bit: int, rng: random.Random) -> None:
    """Set the LSB by moving the channel by one instead of overwriting it."""
    value = pixels[index]
    if value & 1 == bit:
        return
    if value == 0:
        pixels[index] = 1
    elif value == 255:
        pixels[index] = 254
    elif rng.getrandbits(1):
        pixels[index] = value + 1
    else:
        pixels[index] = value - 1


def _write_bits(pixels: bytearray, positions: array.array, payload: bytes, rng: random.Random) -> None:
    cursor = 0
    for byte in payload:
        for shift in range(7, -1, -1):
            _match(pixels, positions[cursor], (byte >> shift) & 1, rng)
            cursor += 1


def _read_bits(pixels: bytes, positions: array.array, length: int) -> bytes:
    out = bytearray(length)
    cursor = 0
    for index in range(length):
        byte = 0
        for _ in range(8):
            byte = (byte << 1) | (pixels[positions[cursor]] & 1)
            cursor += 1
        out[index] = byte
    return bytes(out)


def _noise_fill(pixels: bytearray, used: bytearray, rng: random.Random) -> None:
    """Randomize every unused low bit with LSB matching so fill is not a flat region."""
    bits = rng.randbytes((len(pixels) + 7) // 8)
    for index, value in enumerate(pixels):
        if used[index]:
            continue
        bit = (bits[index >> 3] >> (index & 7)) & 1
        if value & 1 == bit:
            continue
        if value == 0:
            pixels[index] = 1
        elif value == 255:
            pixels[index] = 254
        elif rng.getrandbits(1):
            pixels[index] = value + 1
        else:
            pixels[index] = value - 1


def encode(
    image: bytes | str | Path,
    message: str | bytes,
    password: str,
    fmt: str = "PNG",
    noise: bool = True,
) -> tuple[bytes, dict]:
    """Return (stego bytes, metrics). Raises StegError on bad input."""
    if not password:
        raise StegError("password must not be empty")
    fmt = fmt.upper()
    if fmt not in {"PNG", "BMP"}:
        raise StegError("output format must be PNG or BMP")

    data = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    img = _load_rgb(image)
    total = img.width * img.height * 3
    capacity = total // 8
    max_blob = capacity - HEADER_LEN - TAG_LEN
    if max_blob <= 0:
        raise StegError(f"image is too small to carry a payload: {img.width}x{img.height}")

    flags = 0
    blob = data
    compressed = zlib.compress(data, 9)
    if len(compressed) < len(data):
        blob = compressed
        flags |= FLAG_COMPRESSED
    if len(blob) > max_blob:
        raise StegError(
            f"message too large: {len(data)} bytes given, {max_blob} bytes fit "
            f"in a {img.width}x{img.height} image"
        )

    master = _master_key(password, img.width, img.height)
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    header = salt + nonce + struct.pack(">I", len(blob)) + bytes([flags])
    key, body_seed = _image_keys(master, salt)
    ciphertext = AESGCM(key).encrypt(nonce, blob, _AAD + bytes([flags]))
    body = ciphertext  # includes the 16-byte GCM tag

    header_positions = _pick(hashlib.shake_256(master + b"header").digest(32), total, HEADER_LEN * 8)
    used = bytearray(total)
    for position in header_positions:
        used[position] = 1
    body_positions = _pick(body_seed + b"body", total, len(body) * 8, used)

    pixels = bytearray(img.tobytes())
    rng = random.Random(hashlib.sha256(master + salt).digest())
    _write_bits(pixels, header_positions, header, rng)
    _write_bits(pixels, body_positions, body, rng)
    if noise:
        _noise_fill(pixels, used, rng)

    stego = Image.frombytes("RGB", img.size, bytes(pixels))
    buffer = io.BytesIO()
    stego.save(buffer, fmt)

    payload_bytes = HEADER_LEN + len(ciphertext)
    result = {
        "width": img.width,
        "height": img.height,
        "capacity_bytes": capacity,
        "message_bytes": len(data),
        "payload_bytes": payload_bytes,
        "fill_percent": round(100 * payload_bytes / capacity, 2),
        "mse": round(mse(img, stego), 4),
        "psnr_db": round(psnr(img, stego), 2),
        "compressed": bool(flags & FLAG_COMPRESSED),
        "format": fmt,
        "noise": noise,
    }
    return buffer.getvalue(), result


def decode(image: bytes | str | Path, password: str) -> bytes:
    """Return the hidden message. Raises StegError if absent or password wrong."""
    if not password:
        raise StegError("password must not be empty")
    img = _load_rgb(image)
    total = img.width * img.height * 3
    capacity = total // 8
    if capacity < HEADER_LEN + TAG_LEN:
        raise StegError("image is too small to contain a payload")

    pixels = img.tobytes()
    master = _master_key(password, img.width, img.height)
    header_positions = _pick(hashlib.shake_256(master + b"header").digest(32), total, HEADER_LEN * 8)
    header = _read_bits(pixels, header_positions, HEADER_LEN)

    salt = header[:SALT_LEN]
    nonce = header[SALT_LEN : SALT_LEN + NONCE_LEN]
    length = struct.unpack(">I", header[SALT_LEN + NONCE_LEN : HEADER_LEN - 1])[0]
    flags = header[-1]
    max_blob = capacity - HEADER_LEN - TAG_LEN
    if length > max_blob:
        raise StegError(_NO_MESSAGE)

    key, body_seed = _image_keys(master, salt)
    used = bytearray(total)
    for position in header_positions:
        used[position] = 1
    body_positions = _pick(body_seed + b"body", total, (length + TAG_LEN) * 8, used)
    body = _read_bits(pixels, body_positions, length + TAG_LEN)

    try:
        blob = AESGCM(key).decrypt(nonce, body, _AAD + bytes([flags]))
    except InvalidTag as exc:
        raise StegError(_NO_MESSAGE) from exc
    if flags & FLAG_COMPRESSED:
        try:
            blob = zlib.decompress(blob)
        except zlib.error as exc:
            raise StegError("payload is corrupt") from exc
    return blob
