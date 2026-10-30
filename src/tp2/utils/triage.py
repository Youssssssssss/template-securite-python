from tp2.utils.config import logger
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner


def guess_family(yara_matches, iocs, imports):
    """Petite heuristique de famille à partir des règles YARA et des imports.

    Ce n'est pas parfait, mais ça donne une première étiquette lisible.
    """
    rules = " ".join(yara_matches).lower()
    imps = " ".join(imports).lower()

    if "ransom" in rules or "cryptencrypt" in imps or "cryptacquirecontext" in imps:
        return "ransomware"
    if "cred" in rules or "steal" in rules or "keylog" in rules:
        return "stealer"
    if "download" in rules or "urlmon" in imps or "urldownloadtofile" in imps or iocs["urls"]:
        return "downloader"
    if "inject" in rules or "createremotethread" in imps or "wsasocket" in imps:
        return "rat"
    if "persist" in rules or "run_key" in rules or iocs["registry"]:
        return "dropper"
    return "unknown"


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

        imports = bininfo.get("imports", [])
        family = guess_family(yara_matches, iocs, imports)

        return {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "size": meta["size"],
            "type": meta["type"],
            "entropy": meta["entropy"],
            "iocs": iocs,
            "yara_matches": yara_matches,
            "family_guess": family,
            "flag": flag,
            "bin": bininfo,
        }
