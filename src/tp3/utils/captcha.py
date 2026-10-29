import io
import requests
from PIL import Image, ImageOps, ImageFilter
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


class Captcha:
    def __init__(self, url: str, http: requests.Session | None = None):
        self.url = url.rstrip("/")
        self.http = http or requests.Session()
        self.image: Image.Image | None = None
        self.value = ""

    def capture(self) -> None:
        resp = self.http.get(f"{self.url}/captcha", timeout=5)  # endpoint à adapter
        resp.raise_for_status()
        self.image = Image.open(io.BytesIO(resp.content))

    def solve(self) -> None:
        if self.image is None:
            raise RuntimeError("capture() doit être appelé avant solve()")
        img = self.image.convert("L")
        img = ImageOps.autocontrast(img)
        img = img.resize((img.width * 3, img.height * 3))
        img = img.point(lambda p: 0 if p < 140 else 255)   # seuil à calibrer
        img = img.filter(ImageFilter.MedianFilter(3))
        raw = pytesseract.image_to_string(
            img,
            config="--psm 7 -c tessedit_char_whitelist="
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        )
        self.value = "".join(raw.split())

    def get_value(self) -> str:
        return self.value