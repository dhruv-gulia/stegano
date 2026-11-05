import re

import pytest
from fastapi.testclient import TestClient

from steg import features
from steg.web import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("STEG_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ADMIN_TOKEN", "test-token")
    with TestClient(app) as test_client:
        yield test_client


def _encode(client, cover, message="meet at 5", password="secret"):
    return client.post(
        "/encode",
        files={"image": ("cover.png", cover, "image/png")},
        data={"message": message, "password": password},
    )


def test_web_round_trip(client, cover):
    response = _encode(client, cover, "hello from the web", "hunter22")
    assert response.status_code == 200
    output_id = re.search(r"/download/([A-Za-z0-9_-]+)", response.text).group(1)

    download = client.get(f"/download/{output_id}")
    assert download.status_code == 200
    assert download.headers["content-type"] == "image/png"

    decoded = client.post(
        "/decode",
        files={"image": ("stego.png", download.content, "image/png")},
        data={"password": "hunter22"},
    )
    assert decoded.status_code == 200
    assert "hello from the web" in decoded.text


def test_wrong_password_shows_error(client, cover):
    response = _encode(client, cover)
    output_id = re.search(r"/download/([A-Za-z0-9_-]+)", response.text).group(1)
    stego = client.get(f"/download/{output_id}").content
    decoded = client.post(
        "/decode",
        files={"image": ("stego.png", stego, "image/png")},
        data={"password": "nope"},
    )
    assert decoded.status_code == 400
    assert "wrong password" in decoded.text


def test_upload_limit_rejects_large_file(client, cover, monkeypatch):
    features.update({"max_upload_mb": 1})
    big = cover + b"\0" * (1024 * 1024)
    response = _encode(client, big)
    assert response.status_code == 400
    assert "1 MB limit" in response.text


def test_admin_requires_login(client):
    page = client.get("/admin")
    assert "Admin login" in page.text
    denied = client.post("/admin/flags", data={"max_upload_mb": "5"})
    assert denied.status_code == 403


def test_admin_can_toggle_features(client, cover):
    login = client.post("/admin/login", data={"token": "test-token"}, follow_redirects=False)
    assert login.status_code == 303

    # Nothing checked means every feature is turned off.
    saved = client.post("/admin/flags", data={"max_upload_mb": "5"}, follow_redirects=False)
    assert saved.status_code == 303

    flags = features.load()
    assert flags["encode_enabled"] is False
    assert flags["max_upload_mb"] == 5

    encode_page = client.get("/")
    assert encode_page.status_code == 403
    blocked = _encode(client, cover)
    assert blocked.status_code == 403

    client.post("/admin/flags", data={"max_upload_mb": "5", "decode_enabled": "on"})
    assert features.load()["decode_enabled"] is True


def test_research_page_lists_recent_encode(client, cover):
    _encode(client, cover, "abc")
    _encode(client, cover, "a" * 100, "secret")
    page = client.get("/research")
    assert page.status_code == 200
    assert "Encodes shown" in page.text
    assert "PSNR" in page.text
    assert "Capacity per encode" in page.text
    widths = [float(w) for w in re.findall(r'chart-fill" style="width:([\d.]+)%', page.text)]
    assert len(widths) == 2
    assert max(widths) == 100.0 and min(widths) < 100.0


def test_vercel_encode_inlines_download(client, cover, monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    response = _encode(client, cover)
    assert response.status_code == 200
    assert "data:image/png;base64," in response.text
    assert "/download/" not in response.text


def test_download_rejects_bad_ids(client):
    assert client.get("/download/..%2Ffeatures").status_code == 404
    assert client.get("/download/does-not-exist").status_code == 404
