from pathlib import Path

import yara

from tp2.utils.config import logger

# Le dossier rules/ est à la racine du dépôt. On remonte depuis ce fichier
# (src/tp2/utils/scanner.py) pour le retrouver même si l'outil est lancé
# depuis un autre répertoire (c'est le cas du correcteur).
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_RULES = REPO_ROOT / "rules" / "course_rules.yar"


def find_rules(rules_path):
    # On teste plusieurs emplacements courants avant d'abandonner.
    candidates = [
        Path(rules_path),
        DEFAULT_RULES,
        Path.cwd() / "rules" / "course_rules.yar",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


class YaraScanner:
    def __init__(self, rules_path="rules/course_rules.yar"):
        self.rules = None
        found = find_rules(rules_path)
        if found is not None:
            self.rules = yara.compile(filepath=str(found))
            logger.info(f"Règles YARA chargées depuis {found}")
        else:
            logger.warning(f"Règles YARA introuvables (cherché: {rules_path})")

    def scan(self, data):
        """Retourne les noms des règles YARA déclenchées."""
        if self.rules is None:
            return []
        return [str(match.rule) for match in self.rules.match(data=data)]
