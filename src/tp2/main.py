import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.report import Report
from tp2.utils.triage import Triage


def collect_samples(paths):
    """Transforme une liste de chemins (fichiers ou dossiers) en liste de fichiers."""
    samples = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            # Si on passe un dossier, on traite tous les fichiers qu'il contient.
            for child in sorted(p.iterdir()):
                if child.is_file():
                    samples.append(child)
        elif p.is_file():
            samples.append(p)
        else:
            logger.warning(f"Chemin ignoré (introuvable): {raw}")
    return samples


def main():
    ap = argparse.ArgumentParser(description="TP2 - triage de malware")
    # On accepte le fichier aussi bien en positionnel (tp2 sample.bin) qu'avec
    # -f/--file (tp2 -f sample.bin). Ça évite de planter selon la façon d'appeler.
    ap.add_argument("samples", nargs="*", help="fichier(s) ou dossier(s) à analyser")
    ap.add_argument("-f", "--file", action="append", default=[], help="échantillon à analyser")
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    args = ap.parse_args()

    targets = collect_samples(list(args.file) + list(args.samples))
    if not targets:
        ap.error("aucun échantillon fourni (en positionnel ou avec -f/--file)")

    for sample in targets:
        result = Triage(str(sample), args.llm).run()
        Report(result).generate_json(f"{sample}.triage.json")
        logger.info(f"Rapport écrit: {sample}.triage.json")


if __name__ == "__main__":
    main()
