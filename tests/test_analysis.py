import io
import random
from pathlib import Path

from PIL import Image

from steg import analyze, encode
from steg.analysis import RS_THRESHOLD, _upper_tail


def test_upper_tail_is_a_probability():
    assert 0.0 <= _upper_tail(255, 255) <= 1.0
    assert 0.4 < _upper_tail(255, 255) < 0.6
    assert _upper_tail(2000, 255) < 0.001


def test_plain_cover_is_not_legacy(cover):
    report = analyze(cover)
    assert report["legacy_header"] is False
    assert 0.0 <= report["p_value"] <= 1.0


def test_v2_output_has_no_legacy_header(cover):
    stego, _ = encode(cover, "detector test", "pw")
    report = analyze(stego)
    assert report["legacy_header"] is False


def test_sequential_magic_is_flagged(cover):
    img = Image.open(io.BytesIO(cover)).convert("RGB")
    pixels = bytearray(img.tobytes())
    payload = b"STEG1" + bytes(44)
    cursor = 0
    for byte in payload:
        for shift in range(7, -1, -1):
            pixels[cursor] = (pixels[cursor] & 0xFE) | ((byte >> shift) & 1)
            cursor += 1
    buffer = io.BytesIO()
    Image.frombytes("RGB", img.size, bytes(pixels)).save(buffer, "PNG")
    report = analyze(buffer.getvalue())
    assert report["legacy_header"] is True
    assert report["flagged"] is True


def test_full_lsb_replacement_is_flagged(cover):
    img = Image.open(io.BytesIO(cover)).convert("RGB")
    pixels = bytearray(img.tobytes())
    rng = random.Random(7)
    for index in range(len(pixels)):
        pixels[index] = (pixels[index] & 0xFE) | rng.getrandbits(1)
    buffer = io.BytesIO()
    Image.frombytes("RGB", img.size, bytes(pixels)).save(buffer, "PNG")
    report = analyze(buffer.getvalue())
    assert report["flagged"] is True
    assert report["p_value"] > 0.05


def test_rs_report_is_bounded(cover):
    report = analyze(cover)
    for key in ("rs_regular_pos", "rs_singular_pos", "rs_regular_neg", "rs_singular_neg"):
        assert 0.0 <= report[key] <= 1.0
    assert report["rs_delta"] >= 0.0
    assert report["rs_flagged"] == (report["rs_delta"] > RS_THRESHOLD)
    assert report["rs_groups"] > 0


def test_rs_catches_noise_fill_on_a_photo_cover():
    raw = Path("docs/cover.png").read_bytes()
    stego, _ = encode(raw, "RS noise-fill sample " * 100, "pw", noise=True)
    report = analyze(stego)
    assert report["p_value"] <= 0.05
    assert report["rs_flagged"] is True
    assert report["flagged"] is True
