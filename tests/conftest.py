import io

import pytest
from PIL import Image


@pytest.fixture
def cover() -> bytes:
    """120x120 textured PNG, 5400 bytes of raw LSB capacity."""
    img = Image.new("RGB", (120, 120))
    pixels = img.load()
    for x in range(120):
        for y in range(120):
            pixels[x, y] = ((x * 7 + y * 3) % 256, (x * 5 + y * 11) % 256, (x * 13 + y * 2) % 256)
    buffer = io.BytesIO()
    img.save(buffer, "PNG")
    return buffer.getvalue()
