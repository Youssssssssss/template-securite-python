import json


class Report:
    def __init__(self, result):
        self.result = result

    def generate_json(self, out_json):
        """Écrit le rapport JSON lisible par le correcteur."""
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(self.result, f, ensure_ascii=False, indent=2)
