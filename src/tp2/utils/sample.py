import hashlib
import math
import re
from collections import Counter

import magic

# On récupère d'abord toutes les chaînes ASCII imprimables du fichier, puis on
# cherche les IOC dedans avec des regex. C'est l'approche "strings" classique.
STRINGS_RE = re.compile(rb"[\x20-\x7e]{4,}")

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
MUTEX_RE = re.compile(r"(?:Global|Local)\\[^\s\"']+")
REGISTRY_RE = re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s\"']+")
# Le flag du TP est caché dans l'échantillon, au format ESGI{...}.
FLAG_RE = re.compile(r"ESGI\{[^}]{1,200}\}")

# Extensions courantes : on s'en sert pour éviter que "payload.bin" ou "cmd.exe"
# soient pris pour des noms de domaine.
FILE_EXTENSIONS = {
    "exe", "dll", "bin", "dat", "sys", "txt", "log", "tmp", "png", "jpg",
    "gif", "json", "pdf", "zip", "ps1", "vbs", "bat", "scr", "ini", "cfg",
}


def looks_like_domain(candidate):
    # Un vrai domaine ne finit pas par une extension de fichier connue.
    tld = candidate.rsplit(".", 1)[-1].lower()
    return tld not in FILE_EXTENSIONS


class Sample:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        # On calcule les chaînes une seule fois, elles resservent partout.
        self.strings = [m.decode("ascii") for m in STRINGS_RE.findall(self.data)]

    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()

    def md5(self):
        return hashlib.md5(self.data).hexdigest()

    def shannon_entropy(self):
        # Entropie de Shannon sur les octets, entre 0 et 8.
        # Proche de 8 => données chiffrées ou packées (souvent suspect).
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def file_type(self):
        # magic lit les premiers octets : "PE32 executable...", "ELF 64-bit...", etc.
        return magic.from_buffer(self.data)

    def get_file_metadata(self):
        return {
            "sha256": self.sha256(),
            "md5": self.md5(),
            "size": len(self.data),
            "type": self.file_type(),
            "entropy": round(self.shannon_entropy(), 3),
        }

    def extract_iocs(self):
        blob = "\n".join(self.strings)

        urls = sorted(set(URL_RE.findall(blob)))
        ips = sorted(set(IP_RE.findall(blob)))

        # Pour les domaines on enlève ce qui est en fait une IP ou un nom de fichier.
        domains = []
        for d in DOMAIN_RE.findall(blob):
            if IP_RE.fullmatch(d):
                continue
            if not looks_like_domain(d):
                continue
            domains.append(d)
        domains = sorted(set(domains))

        mutex = sorted(set(MUTEX_RE.findall(blob)))
        registry = sorted(set(REGISTRY_RE.findall(blob)))

        return {
            "domains": domains,
            "ips": ips,
            "urls": urls,
            "mutex": mutex,
            "registry": registry,
        }

    def extract_flag(self):
        # On cherche le flag dans les chaînes du fichier ; None si absent.
        match = FLAG_RE.search("\n".join(self.strings))
        if match:
            return match.group(0)
        return None
