"""Image quality metrics used to judge how invisible the payload is."""

import math

from PIL import Image, ImageChops, ImageStat


def mse(original: Image.Image, stego: Image.Image) -> float:
    a, b = original.convert("RGB"), stego.convert("RGB")
    if a.size != b.size:
        raise ValueError("images must have the same dimensions")
    diff = ImageStat.Stat(ImageChops.difference(a, b))
    return sum(diff.sum2) / (a.width * a.height * 3)


def psnr(original: Image.Image, stego: Image.Image) -> float:
    error = mse(original, stego)
    if error == 0:
        return math.inf
    return 10 * math.log10((255 ** 2) / error)
