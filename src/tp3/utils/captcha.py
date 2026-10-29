"""Capture et résolution du CAPTCHA image.

L'image est un code de 5 caractères (A-Z, 0-9) en noir sur fond blanc avec un
bruit léger. Prétraitement PIL (niveaux de gris, agrandissement, seuillage,
filtre médian) puis OCR pytesseract restreint à l'alphabet attendu.
"""

from __future__ import annotations

import io
import re
from collections import Counter

import pytesseract
import requests
from PIL import Image, ImageFilter, ImageOps

from tp3.utils.config import logger

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
CODE_LEN = 5
# Plusieurs seuils + modes de segmentation : on vote sur les lectures et on
# privilégie celles de longueur attendue (robustesse ~95 % au premier essai).
_THRESHOLDS = (110, 128, 145)
_PSM_MODES = (7, 8)


class Captcha:
    """Télécharge l'image du CAPTCHA et en extrait le code par OCR."""

    def __init__(self, url: str, http: requests.Session | None = None):
        """Initialise le CAPTCHA.

        Args:
            url: URL de l'image du CAPTCHA (ex. http://cible/captcha.png).
            http: session HTTP partagée (indispensable : l'image dépend du
                cookie de session posé par la page interne).
        """
        self.url = url
        self.http = http or requests.Session()
        self.image: bytes = b""
        self.value: str = ""

    def capture(self) -> None:
        """Télécharge les octets PNG de l'image du CAPTCHA."""
        resp = self.http.get(self.url, timeout=5)
        resp.raise_for_status()
        self.image = resp.content

    def _preprocess(self, threshold: int) -> Image.Image:
        """Niveaux de gris, agrandissement, autocontraste, seuillage, débruitage."""
        img = Image.open(io.BytesIO(self.image)).convert("L")
        img = img.resize((img.width * 4, img.height * 4), Image.LANCZOS)
        img = ImageOps.autocontrast(img)
        img = img.point(lambda p: 0 if p < threshold else 255)
        return img.filter(ImageFilter.MedianFilter(3))

    def solve(self) -> None:
        """Résout le CAPTCHA : OCR multi-variantes puis vote majoritaire."""
        if not self.image:
            self.capture()
        candidates: list[str] = []
        for threshold in _THRESHOLDS:
            img = self._preprocess(threshold)
            for psm in _PSM_MODES:
                cfg = f"--psm {psm} --oem 3 -c tessedit_char_whitelist={ALPHABET}"
                guess = re.sub(f"[^{ALPHABET}]", "", pytesseract.image_to_string(img, config=cfg).upper())
                if guess:
                    candidates.append(guess)
        # On privilégie les lectures de la longueur attendue, puis on vote.
        well_sized = [c for c in candidates if len(c) == CODE_LEN]
        pool = well_sized or candidates
        self.value = Counter(pool).most_common(1)[0][0] if pool else ""
        logger.debug(f"OCR captcha -> {self.value!r} (candidats: {candidates})")

    def get_value(self) -> str:
        """Retourne la valeur résolue du CAPTCHA."""
        return self.value
