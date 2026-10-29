"""TP3 - Breach the target.

    poetry run tp3 --target http://127.0.0.1:8080
"""

import argparse
import base64
import re
import socket

from tp3.utils.config import get_logger, setup_logging
from tp3.utils.session import Session

logger = get_logger(__name__)

FLAG_RE = re.compile(rb"ESGI\{[^}]+\}")


def breach_web(target: str) -> tuple[str, int, bytes]:
    """Fuzz, casse le CAPTCHA, AFFICHE flag1, retourne (host, port, key)."""
    session = Session(target)
    flag1 = session.run()                # fuzzing + captcha + submit + retry

    print(f"[+] FLAG1: {flag1}")         # ← stdout, format exact

    r = session.reveal                   # rempli par process_response
    return r["host"], int(r["port"]), r["key"].encode()


def xor(data: bytes, key: bytes) -> bytes:
    """XOR à clé répétée."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decode_token(line: bytes, key: bytes) -> bytes:
    """base64-decode puis XOR (ordre à confirmer sur un vrai jeton local)."""
    return xor(base64.b64decode(line), key)


def breach_network(host: str, port: int, key: bytes, timeout: int = 30) -> str:
    """Connexion TCP unique, décode le flux en boucle, retourne le flag final."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        buf = b""

        while True:
            while b"\n" not in buf:                  # lire jusqu'à une ligne complète
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("serveur a fermé la connexion")
                buf += chunk
            line, buf = buf.split(b"\n", 1)          # garde le reste pour le tour suivant
            line = line.strip()
            if not line:
                continue

            m = FLAG_RE.search(line)                 # flag final ? on sort
            if m:
                return m.group(0).decode()

            token = decode_token(line, key)          # sinon : décoder et répondre
            sock.sendall(token + b"\n")
            logger.info("round ok (%d octets)", len(token))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    setup_logging()
    logger.info("Starting TP3 - breach the target")   # stderr : progression
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key)

    print(f"[+] FLAG_FINAL: {flag}")                  # ← stdout, format exact


if __name__ == "__main__":
    main()
