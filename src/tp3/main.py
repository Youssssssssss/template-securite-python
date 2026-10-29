"""TP3 - Breach the target.

    poetry run tp3 --target http://127.0.0.1:8080
"""

import argparse

from tp3.utils.config import logger
from tp3.session import Session          # notre classe captcha+submit+retry


def breach_web(target: str) -> tuple[str, int, bytes]:
    """Fuzz, casse le CAPTCHA, AFFICHE flag1, retourne (host, port, key)."""
    session = Session(target)
    flag1 = session.run()                # fuzzing + captcha + submit + retry

    print(f"[+] FLAG1: {flag1}")         # ← stdout, format exact

    r = session.reveal                   # rempli par process_response
    return r["host"], int(r["port"]), r["key"].encode()


def breach_network(host: str, port: int, key: bytes) -> str:
    """Décode le flux base64+XOR en boucle, retourne le flag final."""
    raise NotImplementedError            # ← la brique qu'il nous reste à écrire


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")   # stderr : progression
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key)

    print(f"[+] FLAG_FINAL: {flag}")                  # ← stdout, format exact


if __name__ == "__main__":
    main()