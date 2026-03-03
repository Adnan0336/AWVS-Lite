from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from datetime import datetime

def render_pdf(out_path: str, target: str, findings: list, summary: dict):
    c = canvas.Canvas(out_path, pagesize=A4)
    w, h = A4

    y = h - 2*cm
    c.setFont("Helvetica-Bold", 16)
    c.drawString(2*cm, y, "AWVS-Lite Pro — Security Scan Report")
    y -= 0.8*cm

    c.setFont("Helvetica", 10)
    c.drawString(2*cm, y, f"Target: {target}")
    y -= 0.5*cm
    c.drawString(2*cm, y, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    y -= 1.0*cm

    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Executive Summary")
    y -= 0.6*cm

    c.setFont("Helvetica", 10)
    summary_line = " | ".join([f"{k}: {summary.get(k,0)}" for k in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]])
    c.drawString(2*cm, y, summary_line)
    y -= 1.0*cm

    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Findings")
    y -= 0.6*cm

    c.setFont("Helvetica", 9)
    for i, f in enumerate(findings, 1):
        block = [
            f"{i}. [{f.severity}] {f.title}",
            f"Rule: {f.rule_id} | Confidence: {f.confidence}",
            f"URL: {f.url or ''}",
            f"Description: {f.description}",
            f"Recommendation: {f.recommendation}",
        ]
        if f.evidence:
            ev = str(f.evidence)
            if len(ev) > 300:
                ev = ev[:300] + "..."
            block.append(f"Evidence: {ev}")

        for line in block:
            if y < 2.5*cm:
                c.showPage()
                y = h - 2*cm
                c.setFont("Helvetica", 9)
            c.drawString(2*cm, y, line)
            y -= 0.42*cm
        y -= 0.35*cm

    c.save()
