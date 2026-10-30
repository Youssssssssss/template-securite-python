from tp2.utils.config import logger
from tp2.utils.sample import Sample


class Triage:
    def __init__(self, path, backend):
        self.path = path
        self.backend = backend

    def run(self):
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        return {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "size": meta["size"],
            "entropy": meta["entropy"],
        }
