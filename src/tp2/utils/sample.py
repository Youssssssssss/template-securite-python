import hashlib
import math
from collections import Counter

import magic


class Sample:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()

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
