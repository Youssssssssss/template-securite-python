"""TP3 - Breach the target.

    poetry run tp3 --target http://127.0.0.1:8080
"""

import argparse
import base64
import re
import socket

import requests

from tp3.utils.config import logger
from tp3.utils.fuzzer import find_hidden_endpoint
from tp3.session import Session


# ───────────────────────── PHASE WEB ─────────────────────────
def breach_web(target: str) -> tuple[str, int, bytes]:
    """Fuzz → CAPTCHA → parse. Affiche flag1, retourne (host, port, key)."""
    http = requests.Session()                        # session partagée partout
    page_url = find_hidden_endpoint(target, http)    # 1) fuzzing
    session = Session(page_url, http=http)           # 2+3) captcha + submit + parse
    flag1 = session.run()

    print(f"[+] FLAG1: {flag1}")                     # stdout, format exact

    r = session.reveal
    return r["host"], int(r["port"]), r["key"].encode()


# ──────────────────────── PHASE RÉSEAU ───────────────────────
FLAG_RE = re.compile(rb"ESGI\{[^}]+\}")


def xor(data: bytes, key: bytes) -> bytes:
    """XOR à clé répétée, en octets bruts."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decode_token(line: bytes, key: bytes) -> bytes:
    """base64-decode puis XOR (ordre à confirmer sur un vrai jeton local)."""
    return xor(base64.b64decode(line), key)


def breach_network(host: str, port: int, key: bytes, timeout: int = 30) -> str:
    """Connexion TCP unique, décode le flux base64+XOR en boucle, retourne le flag."""
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


# ────────────────────────── ENTRÉE ───────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key)

    print(f"[+] FLAG_FINAL: {flag}")                 # stdout, format exact


if __name__ == "__main__":
    main()