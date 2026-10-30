import hashlib


class Sample:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()

    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()

    def md5(self):
        return hashlib.md5(self.data).hexdigest()

    def get_file_metadata(self):
        return {
            "sha256": self.sha256(),
            "md5": self.md5(),
            "size": len(self.data),
        }
