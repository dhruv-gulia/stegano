import os
from pathlib import Path


def data_dir() -> Path:
    """Runtime data directory; override with STEG_DATA_DIR."""
    return Path(os.environ.get("STEG_DATA_DIR") or Path(__file__).resolve().parent.parent / "data")
