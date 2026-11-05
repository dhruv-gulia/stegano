import pytest

from steg import features


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    monkeypatch.setenv("STEG_DATA_DIR", str(tmp_path))


def test_defaults_when_nothing_saved():
    flags = features.load()
    assert flags == features.DEFAULTS


def test_update_persists():
    features.update({"decode_enabled": False, "max_upload_mb": 7})
    flags = features.load()
    assert flags["decode_enabled"] is False
    assert flags["max_upload_mb"] == 7
    assert flags["encode_enabled"] is True


def test_invalid_max_upload_rejected():
    for bad in (0, 51, True, "10"):
        with pytest.raises(ValueError):
            features.update({"max_upload_mb": bad})


def test_unknown_flag_rejected():
    with pytest.raises(ValueError, match="unknown flag"):
        features.update({"backdoor": True})


def test_non_boolean_toggle_rejected():
    with pytest.raises(ValueError, match="true or false"):
        features.update({"encode_enabled": "yes"})
