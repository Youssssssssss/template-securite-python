"""Tests de la résolution du CAPTCHA (OCR sur image synthétique)."""

import io
import os
import shutil

import pytest
from PIL import Image, ImageDraw, ImageFont

from src.tp3.utils.captcha import Captcha

_FONT_PATHS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
)


def _font(size: int):
    for path in _FONT_PATHS:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _make_captcha_png(code: str) -> bytes:
    """Reproduit le rendu de la cible : texte noir sur blanc, léger bruit."""
    img = Image.new("RGB", (220, 90), "white")
    dr = ImageDraw.Draw(img)
    dr.text((25, 22), code, fill="black", font=_font(48))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def test_captcha_init():
    captcha = Captcha("http://example.com/captcha.png")
    assert captcha.url == "http://example.com/captcha.png"
    assert captcha.image == b""
    assert captcha.value == ""


def test_get_value():
    captcha = Captcha("http://example.com/captcha.png")
    captcha.value = "TEST1"
    assert captcha.get_value() == "TEST1"


@pytest.mark.skipif(
    shutil.which("tesseract") is None or not any(os.path.exists(p) for p in _FONT_PATHS),
    reason="tesseract ou police DejaVu absents",
)
def test_solve_reads_synthetic_code():
    code = "A7K9Q"
    captcha = Captcha("http://example.com/captcha.png")
    captcha.image = _make_captcha_png(code)

    captcha.solve()

    assert captcha.get_value() == code
