"""Tests de la phase réseau (décodage base64+XOR, fallback d'hôte)."""

import base64

from src.tp3.utils.netcode import _candidate_hosts, decode_token, xor_bytes


def test_xor_involutif():
    data = b"token-1234567890"
    key = bytes.fromhex("26c0d591")
    assert xor_bytes(xor_bytes(data, key), key) == data


def test_decode_token_round_trip():
    token = b"abcdef0123456789"
    key = bytes.fromhex("deadbeef")
    wire = base64.b64encode(xor_bytes(token, key))
    assert decode_token(wire, key) == token


def test_candidate_hosts_loopback_prefere_target():
    # Hôte annoncé en boucle locale -> on essaie d'abord l'hôte du --target.
    hosts = _candidate_hosts("127.0.0.1", "http://cible.exemple:8080")
    assert hosts[0] == "cible.exemple"
    assert "127.0.0.1" in hosts


def test_candidate_hosts_public_garde_annonce_en_premier():
    hosts = _candidate_hosts("10.0.0.5", "http://cible.exemple:8080")
    assert hosts[0] == "10.0.0.5"
    assert "cible.exemple" in hosts
