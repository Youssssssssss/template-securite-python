import json

import requests

from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
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


def fallback_summary(meta, iocs, yara_matches, family):
    """Résumé lisible quand le LLM n'est pas disponible (pas de clé / hors-ligne)."""
    rules = ", ".join(yara_matches) if yara_matches else "aucune"
    return (
        f"Famille probable: {family}. "
        f"Entropie {meta['entropy']} (0-8). "
        f"{len(iocs['domains'])} domaine(s), {len(iocs['ips'])} IP, "
        f"{len(iocs['urls'])} URL. Règles YARA: {rules}."
    )


class Triage:
    def __init__(self, path, backend):
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner()
        self.llm = LLMTriage(backend)

    def run(self):
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        bininfo = sample.parse_binary()
        yara_matches = self.scanner.scan(sample.data)
        flag = sample.extract_flag()

        imports = bininfo.get("imports", [])
        family = guess_family(yara_matches, iocs, imports)

        # On tente le verdict LLM, mais on ne bloque jamais dessus : s'il échoue
        # on garde un résumé construit à partir de l'analyse statique.
        llm_summary = fallback_summary(meta, iocs, yara_matches, family)
        summary_input = json.dumps(
            {"meta": meta, "iocs": iocs, "yara": yara_matches, "bin": bininfo},
            ensure_ascii=False,
        )
        try:
            verdict = json.loads(self.llm.triage(summary_input))
            llm_summary = verdict.get("capacites") or verdict.get("famille") or llm_summary
            if isinstance(llm_summary, (list, dict)):
                llm_summary = json.dumps(llm_summary, ensure_ascii=False)
            if verdict.get("famille"):
                family = str(verdict["famille"])
        except (requests.RequestException, ValueError, RuntimeError) as exc:
            logger.warning(f"Verdict LLM indisponible, résumé statique utilisé: {exc}")

        # Format de sortie attendu par le correcteur (cf. slide "Format de sortie").
        return {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "size": meta["size"],
            "type": meta["type"],
            "entropy": meta["entropy"],
            "iocs": iocs,
            "yara_matches": yara_matches,
            "family_guess": family,
            "llm_summary": llm_summary,
            "flag": flag,
            "bin": bininfo,
        }
