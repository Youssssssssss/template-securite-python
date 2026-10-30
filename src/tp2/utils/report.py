import json

from fpdf import FPDF
from fpdf.enums import XPos, YPos


class Report:
    def __init__(self, result):
        self.result = result

    def generate_json(self, out_json):
        """Écrit le rapport JSON lisible par le correcteur."""
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(self.result, f, ensure_ascii=False, indent=2)

    def generate_pdf(self, out_pdf):
        """Rapport PDF : le livrable 'humain' pour un analyste."""
        r = self.result
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 16)
        self._write(pdf, "Rapport de triage malware")

        pdf.set_font("Helvetica", size=11)
        self._write(pdf, f"Flag: {r.get('flag') or 'non trouvé'}")

        self._section(pdf, "Empreintes", [
            f"sha256: {r.get('sha256', '')}",
            f"md5: {r.get('md5', '')}",
            f"taille: {r.get('size', '')} octets",
            f"type: {r.get('type', '')}",
            f"entropie: {r.get('entropy', '')} (0-8)",
            f"famille probable: {r.get('family_guess', '')}",
        ])

        yara = r.get("yara_matches", [])
        self._section(pdf, "Règles YARA déclenchées", yara or ["aucune"])

        iocs = r.get("iocs", {})
        lines = [f"{k}: {', '.join(v) if v else 'aucun'}" for k, v in iocs.items()]
        self._section(pdf, "Indicateurs de compromission", lines or ["aucun"])

        bininfo = r.get("bin", {})
        if bininfo:
            self._section(pdf, "Analyse binaire", [
                f"format: {bininfo.get('format')}",
                f"sections: {', '.join(bininfo.get('sections', []))}",
                f"imports: {len(bininfo.get('imports', []))}",
            ])

        self._section(pdf, "Résumé LLM", [r.get("llm_summary", "non disponible")])

        pdf.output(out_pdf)

    def _section(self, pdf, title, lines):
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 13)
        self._write(pdf, title)
        pdf.set_font("Helvetica", size=10)
        for line in lines:
            self._write(pdf, line)

    def _write(self, pdf, text):
        # fpdf2 ne gère que le latin-1 avec les polices de base ; on nettoie.
        safe = str(text).encode("latin-1", "replace").decode("latin-1")
        # new_x/new_y : on repart à la marge gauche, sinon la cellule suivante a
        # une largeur nulle et fpdf2 lève une erreur.
        pdf.multi_cell(0, 7, safe, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
