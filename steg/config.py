import os
from pathlib import Path


def data_dir() -> Path:
    """Runtime data directory; override with STEG_DATA_DIR."""
    override = os.environ.get("STEG_DATA_DIR")
    if override:
        return Path(override)
    if os.environ.get("VERCEL"):
        # Vercel functions can only write to /tmp; it is per-instance and ephemeral.
        return Path("/tmp/steg")
    return Path(__file__).resolve().parent.parent / "data"
