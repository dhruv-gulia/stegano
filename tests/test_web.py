import re

import pytest
from fastapi.testclient import TestClient

from steg import features, web
from steg.web import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("STEG_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ADMIN_PASSWORD", "test-password")
    web._FAILS.clear()
    with TestClient(app) as test_client:
        yield test_client
    web._FAILS.clear()


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
    login = client.post("/admin/login", data={"password": "test-password"}, follow_redirects=False)
    assert login.status_code == 303

    # Nothing checked means every feature is turned off.
    saved = client.post("/admin/flags", data={"max_upload_mb": "5"}, follow_redirects=False)
    assert saved.status_code == 303

    flags = features.load()
    assert flags["encode_enabled"] is False
    assert flags["detection_enabled"] is False
    assert flags["diff_enabled"] is False
    assert flags["noise_fill_enabled"] is False
    assert flags["ecc_enabled"] is False
    assert flags["lab_enabled"] is False
    assert flags["robustness_enabled"] is False
    assert flags["damage_enabled"] is False
    assert flags["max_upload_mb"] == 5

    encode_page = client.get("/")
    assert encode_page.status_code == 403
    blocked = _encode(client, cover)
    assert blocked.status_code == 403
    assert client.get("/detect").status_code == 403
    assert client.get("/lab").status_code == 403

    client.post("/admin/flags", data={"max_upload_mb": "5", "decode_enabled": "on"})
    assert features.load()["decode_enabled"] is True


def test_admin_login_rejects_wrong_password(client):
    response = client.post("/admin/login", data={"password": "nope"})
    assert response.status_code == 401
    assert "did not match" in response.text


def test_admin_default_password_is_1234(client, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD")
    login = client.post("/admin/login", data={"password": "1234"}, follow_redirects=False)
    assert login.status_code == 303


def test_admin_pages_do_not_reveal_password(client):
    assert "1234" not in client.get("/admin").text
    client.post("/admin/login", data={"password": "test-password"}, follow_redirects=False)
    assert "1234" not in client.get("/admin").text


def test_admin_login_rate_limit(client):
    for _ in range(5):
        response = client.post("/admin/login", data={"password": "wrong"})
        assert response.status_code == 401
    blocked = client.post("/admin/login", data={"password": "test-password"})
    assert blocked.status_code == 429
    assert "Too many failed attempts" in blocked.text


def test_detector_runs_before_and_after(client, cover):
    response = client.post(
        "/detect",
        files={"image": ("cover.png", cover, "image/png")},
        data={"message": "chi square test", "password": "secret"},
    )
    assert response.status_code == 200
    assert "Original image" in response.text
    assert "After embedding" in response.text
    assert "Chi-square" in response.text
    assert "p-value" in response.text


def test_detector_plain_image(client, cover):
    response = client.post(
        "/detect",
        files={"image": ("cover.png", cover, "image/png")},
        data={},
    )
    assert response.status_code == 200
    assert "Single image" in response.text


def test_bmp_download_round_trip(client, cover):
    response = client.post(
        "/encode",
        files={"image": ("cover.png", cover, "image/png")},
        data={"message": "bmp in the web", "password": "secret", "fmt": "BMP"},
    )
    assert response.status_code == 200
    assert "Download stego BMP" in response.text
    output_id = re.search(r"/download/([A-Za-z0-9_-]+)", response.text).group(1)
    download = client.get(f"/download/{output_id}")
    assert download.headers["content-type"] == "image/bmp"
    assert download.content[:2] == b"BM"
    decoded = client.post(
        "/decode",
        files={"image": ("stego.bmp", download.content, "image/bmp")},
        data={"password": "secret"},
    )
    assert decoded.status_code == 200
    assert "bmp in the web" in decoded.text


def test_research_page_lists_recent_encode(client, cover):
    _encode(client, cover, "abc")
    _encode(client, cover, "a" * 100, "secret")
    page = client.get("/research")
    assert page.status_code == 200
    assert "Encodes shown" in page.text
    assert "PSNR" in page.text
    assert "Capacity per encode" in page.text
    capacity_section = page.text.split('id="capacity-chart"')[1].split("</section>")[0]
    widths = [float(w) for w in re.findall(r'chart-fill" style="width:([\d.]+)%', capacity_section)]
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


def test_encode_result_reports_ecc(client, cover):
    response = _encode(client, cover)
    assert response.status_code == 200
    assert "Reed–Solomon" in response.text
    assert "ECC parity" in response.text


def test_labs_page_lists_experiments(client):
    page = client.get("/lab")
    assert page.status_code == 200
    assert "Detector Lab" in page.text
    assert "Robustness Lab" in page.text
    assert "Damage Lab" in page.text


def test_detector_lab_sweep_and_csv(client, cover):
    response = client.post(
        "/lab/detector",
        files={"image": ("cover.png", cover, "image/png")},
    )
    assert response.status_code == 200
    assert "Detection rate" in response.text
    assert "RS delta" in response.text
    assert "Download CSV" in response.text


def test_robustness_lab_runs_real_transforms(client, cover):
    response = client.post(
        "/lab/robustness",
        files={"image": ("cover.png", cover, "image/png")},
        data={"message": "robustness test payload", "password": "secret"},
    )
    assert response.status_code == 200
    assert "JPEG q95" in response.text
    assert "PNG re-save (control)" in response.text
    assert "recovered" in response.text


def test_damage_lab_shows_ecc_recovery(client, cover):
    response = client.post(
        "/lab/damage",
        files={"image": ("cover.png", cover, "image/png")},
        data={"message": "Reed-Solomon damage test", "password": "secret", "flips": "8"},
    )
    assert response.status_code == 200
    assert "recovered" in response.text
    assert "failed" in response.text
    assert "no hidden message found" in response.text


def test_audit_log_and_csv(client):
    client.post("/admin/login", data={"password": "test-password"}, follow_redirects=False)
    page = client.get("/admin")
    assert "Audit log" in page.text
    assert "login" in page.text

    csv_response = client.get("/admin/audit.csv")
    assert csv_response.status_code == 200
    assert "text/csv" in csv_response.headers["content-type"]
    assert "action,detail" in csv_response.text
    assert "login" in csv_response.text


def test_audit_csv_requires_login(client):
    response = client.get("/admin/audit.csv")
    assert response.status_code == 403
