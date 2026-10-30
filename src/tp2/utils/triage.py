from tp2.utils.config import logger
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner


class Triage:
    def __init__(self, path, backend):
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner()

    def run(self):
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        flag = sample.extract_flag()
        yara_matches = self.scanner.scan(sample.data)
        bininfo = sample.parse_binary()

        return {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "size": meta["size"],
            "type": meta["type"],
            "entropy": meta["entropy"],
            "iocs": iocs,
            "yara_matches": yara_matches,
            "flag": flag,
            "bin": bininfo,
        }
