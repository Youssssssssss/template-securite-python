"""Phase réseau : décodage chronométré du service TCP.

À chaque round le serveur envoie ``base64(XOR(token, key))``. Il faut renvoyer
le token en clair (base64-decode puis XOR avec la clé) avant l'échéance
(~5 s/round). Après les rounds réussis, le serveur renvoie le flag final.
"""

from __future__ import annotations

import base64
import re
import socket
from urllib.parse import urlparse

from tp3.utils.config import logger

_FLAG_RE = re.compile(r"ESGI\{[^}]*\}")
_ROUND_TIMEOUT = 5.0
_MAX_ROUNDS = 64  # garde-fou ; le serveur en impose 3


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR répété de ``data`` avec ``key``."""
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def decode_token(line: bytes, key: bytes) -> bytes:
    """Décode un jeton : base64 puis XOR avec la clé."""
    return xor_bytes(base64.b64decode(line.strip()), key)


def _candidate_hosts(host: str, target: str | None) -> list[str]:
    """Hôtes à essayer : celui annoncé, puis celui du --target en secours.

    Sur l'instance hébergée l'hôte annoncé peut être une boucle locale alors
    que le service est en réalité joignable via l'hôte du ``--target``.
    """
    hosts = [host]
    if target:
        thost = urlparse(target).hostname
        if thost and thost not in hosts:
            if host in ("127.0.0.1", "localhost", "0.0.0.0"):
                hosts.insert(0, thost)
            else:
                hosts.append(thost)
    return hosts


def solve_rounds(host: str, port: int, key: bytes, target: str | None = None) -> str:
    """Se connecte au service TCP, résout la boucle et retourne le flag final."""
    last_err: Exception | None = None
    for cand in _candidate_hosts(host, target):
        try:
            logger.info(f"Connexion TCP {cand}:{port}")
            with socket.create_connection((cand, port), timeout=10) as sock:
                sock.settimeout(_ROUND_TIMEOUT)
                reader = sock.makefile("rb")
                greeting = reader.readline()
                logger.debug(f"greeting: {greeting!r}")
                for rnd in range(1, _MAX_ROUNDS + 1):
                    line = reader.readline()
                    if not line:
                        break
                    text = line.decode(errors="replace").strip()
                    flag = _FLAG_RE.search(text)
                    if flag:  # ligne finale "OK ESGI{...}"
                        logger.info(f"Flag final reçu après {rnd - 1} round(s)")
                        return flag.group(0)
                    if text in ("WRONG", "TIMEOUT"):
                        raise RuntimeError(f"serveur TCP : {text}")
                    token = decode_token(line, key)
                    sock.sendall(token + b"\n")
                    logger.debug(f"round {rnd}: token {token!r} renvoyé")
                raise RuntimeError("fin de flux sans flag")
        except OSError as exc:
            last_err = exc
            logger.info(f"Échec sur {cand}:{port} ({exc})")
            continue
    raise RuntimeError(f"connexion TCP impossible : {last_err}")
