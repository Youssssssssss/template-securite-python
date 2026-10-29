"""TP3 - Breach the target.

Enchaîne une phase web (fuzzing + CAPTCHA) et une phase réseau (décodage
chronométré) pour récupérer deux drapeaux.

    poetry run tp3 --target http://127.0.0.1:8080
"""

import argparse

from tp3.utils.config import logger
from tp3.utils.netcode import solve_rounds
from tp3.utils.session import Session


def breach_web(target: str) -> tuple[str, int, bytes]:
    """Fuzz les endpoints, casse le CAPTCHA, retourne (host, port, key).

    Affiche aussi Flag 1.
    """
    session = Session(target)
    data = session.process_response()
    if not data:
        raise RuntimeError("phase web échouée : CAPTCHA non résolu")
    print(f"[+] FLAG1: {session.get_flag()}")
    return data["host"], int(data["port"]), bytes.fromhex(data["key"])


def breach_network(host: str, port: int, key: bytes, target: str | None = None) -> str:
    """Décode le flux base64+XOR en boucle sous l'échéance et rend le flag final."""
    return solve_rounds(host, port, key, target=target)


def main() -> None:
    ap = argparse.ArgumentParser(prog="tp3", description="TP3 - breach the target")
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key, target=args.target)
    print(f"[+] FLAG_FINAL: {flag}")
    logger.info(f"FLAG_FINAL: {flag}")


if __name__ == "__main__":
    main()
