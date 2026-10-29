import concurrent.futures as cf
from pathlib import Path

import requests

from tp3.utils.config import get_logger

logger = get_logger(__name__)

WORDLIST = Path(__file__).parent / "wordlist.txt"   # SecLists common.txt, embarquée ici


def find_hidden_endpoint(target: str, http: requests.Session,
                         workers: int = 40) -> str:
    """Fuzze les endpoints depuis la wordlist, retourne l'URL de la première
    page qui répond autre chose qu'un 404/400."""
    target = target.rstrip("/")
    words = WORDLIST.read_text(encoding="utf-8").split()

    def probe(word: str):
        try:
            r = http.get(f"{target}/{word}", timeout=3, allow_redirects=False)
            return word, r.status_code
        except requests.RequestException:
            return word, None

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        for word, status in pool.map(probe, words):
            if status and status not in (404, 400):
                url = f"{target}/{word}"
                logger.info("endpoint trouvé: %s (HTTP %d)", url, status)
                return url

    raise RuntimeError("aucun endpoint caché trouvé dans la wordlist")