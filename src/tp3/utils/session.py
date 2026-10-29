import re
import requests
from src.tp3.utils.captcha import Captcha


class CaptchaError(RuntimeError):
    pass


class Session:
    FLAG_RE = re.compile(r"ESGI\{[^}]+\}")

    def __init__(self, url: str, max_attempts: int = 5):
        self.url = url.rstrip("/")
        self.http = requests.Session()
        self.max_attempts = max_attempts
        self.captcha_value = ""
        self.valid_flag = ""
        self.reveal = {}

    def _attempt(self) -> str | None:
        captcha = Captcha(self.url, http=self.http)
        captcha.capture()
        captcha.solve()
        self.captcha_value = captcha.get_value()

        resp = self.http.post(
            f"{self.url}/submit",                  # endpoint à adapter
            data={"captcha": self.captcha_value},
            timeout=5,
        )
        resp.raise_for_status()

        m = self.FLAG_RE.search(resp.text)
        if m:
            # self.reveal = parse_reveal(resp.text)  # host, port, key
            return m.group(0)
        return None

    def run(self) -> str:
        for _ in range(self.max_attempts):
            flag = self._attempt()
            if flag:
                self.valid_flag = flag
                return flag
        raise CaptchaError(f"échec après {self.max_attempts} essais")

    def get_flag(self) -> str:
        return self.valid_flag