import io
import os

import pytest
from PIL import Image

from steg import StegError, capacity_bytes, decode, encode


def test_round_trip_text(cover):
    stego, stats = encode(cover, "meet me at 5", "correct horse")
    assert decode(stego, "correct horse") == b"meet me at 5"
    assert stats["psnr_db"] > 40
    assert stats["message_bytes"] == 12
    assert stats["fill_percent"] < 5


def test_round_trip_binary(cover):
    payload = bytes(range(256)) * 2
    stego, _ = encode(cover, payload, "pw")
    assert decode(stego, "pw") == payload


def test_wrong_password_is_rejected(cover):
    stego, _ = encode(cover, "secret", "right")
    with pytest.raises(StegError, match="wrong password"):
        decode(stego, "wrong")


def test_plain_image_has_no_payload(cover):
    with pytest.raises(StegError, match="no hidden message"):
        decode(cover, "pw")


def test_message_larger_than_capacity(cover):
    with pytest.raises(StegError, match="message too large"):
        encode(cover, os.urandom(6000), "pw")


def test_compression_lets_repetitive_message_fit(cover):
    message = b"a" * 5000
    stego, stats = encode(cover, message, "pw")
    assert stats["compressed"] is True
    assert decode(stego, "pw") == message


def test_bmp_output_round_trip(cover):
    stego, stats = encode(cover, "bmp test", "pw", fmt="BMP")
    assert stats["format"] == "BMP"
    assert stego[:2] == b"BM"
    assert decode(stego, "pw") == b"bmp test"


def test_no_sequential_magic_header(cover):
    stego, _ = encode(cover, "hidden", "pw")
    pixels = Image.open(io.BytesIO(stego)).convert("RGB").tobytes()
    first = bytearray()
    for index in range(5):
        byte = 0
        for bit in range(8):
            byte = (byte << 1) | (pixels[index * 8 + bit] & 1)
        first.append(byte)
    assert bytes(first) != b"STEG1"


def test_corrupt_image_is_rejected():
    with pytest.raises(StegError, match="unsupported or corrupt"):
        encode(b"not an image", "hi", "pw")


def test_capacity_counts_rgb_channels():
    img = Image.new("RGB", (10, 10))
    assert capacity_bytes(img) == (10 * 10 * 3) // 8


def test_empty_password_is_rejected(cover):
    with pytest.raises(StegError, match="password"):
        encode(cover, "hi", "")
