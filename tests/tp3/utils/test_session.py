"""Tests de la phase web (fuzzing + orchestration CAPTCHA)."""

from src.tp3.utils.session import Session, load_wordlist


def test_wordlist_embarquee_contient_endpoint():
    words = load_wordlist()
    assert "internal-panel" in words
    assert all(not w.startswith("#") for w in words)


def test_session_init():
    session = Session("http://example.com:8080/")
    assert session.url == "http://example.com:8080"
    assert session.captcha_value == ""
    assert session.flag_value == ""
    assert session.valid_flag == ""


def test_get_flag():
    session = Session("http://example.com")
    session.valid_flag = "ESGI{web_x}"
    assert session.get_flag() == "ESGI{web_x}"


def test_find_hidden_endpoint(monkeypatch):
    """Le fuzzing retient la page qui renvoie 200 + formulaire CAPTCHA."""

    class FakeResp:
        def __init__(self, status, text=""):
            self.status_code = status
            self.text = text

    class FakeHTTP:
        def get(self, url, allow_redirects=True, timeout=None):
            if url.endswith("/internal-panel"):
                return FakeResp(200, '<img src="/captcha.png">')
            return FakeResp(404)

    from src.tp3.utils import session as session_mod

    monkeypatch.setattr(session_mod, "load_wordlist", lambda: ["admin", "internal-panel", "login"])
    endpoint = session_mod.find_hidden_endpoint("http://t:8080", FakeHTTP())
    assert endpoint == "internal-panel"
