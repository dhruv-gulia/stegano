"""Runtime feature flags for the web app, stored as JSON and edited in /admin."""

from __future__ import annotations

import json
import os
import threading

from .config import data_dir

DEFAULTS = {
    "encode_enabled": True,
    "decode_enabled": True,
    "metrics_enabled": True,
    "research_enabled": True,
    "detection_enabled": True,
    "diff_enabled": True,
    "noise_fill_enabled": True,
    "ecc_enabled": True,
    "lab_enabled": True,
    "robustness_enabled": True,
    "damage_enabled": True,
    "max_upload_mb": 10,
}

BOOL_FLAGS = (
    "encode_enabled",
    "decode_enabled",
    "metrics_enabled",
    "research_enabled",
    "detection_enabled",
    "diff_enabled",
    "noise_fill_enabled",
    "ecc_enabled",
    "lab_enabled",
    "robustness_enabled",
    "damage_enabled",
)
_lock = threading.RLock()


def _path():
    return data_dir() / "features.json"


def load() -> dict:
    with _lock:
        try:
            saved = json.loads(_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            saved = {}
        return {key: saved.get(key, default) for key, default in DEFAULTS.items()}


def update(changes: dict) -> dict:
    """Validate and persist changes, then return the full flag set."""
    merged = load()
    for key, value in changes.items():
        if key in BOOL_FLAGS:
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be true or false")
        elif key == "max_upload_mb":
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 50:
                raise ValueError("max_upload_mb must be an integer from 1 to 50")
        else:
            raise ValueError(f"unknown flag: {key}")
        merged[key] = value

    with _lock:
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        os.replace(temp, path)
    return merged
