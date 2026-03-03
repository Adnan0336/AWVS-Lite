import os
from flask import Blueprint, render_template, request, redirect, url_for, send_file, flash
from app import db
from app.models import Scan as ScanModel, Finding as FindingModel
from scanner import Scanner
from core.severity import summarize
from reports.pdf_report import render_pdf

bp = Blueprint("scans", __name__)

@bp.route("/", methods=["GET"])
def dashboard():
    scans = ScanModel.query.order_by(ScanModel.created_at.desc()).limit(25).all()
    return render_template("dashboard.html", scans=scans)

@bp.route("/run", methods=["POST"])
def run_scan():
    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Please enter a target URL.", "error")
        return redirect(url_for("scans.dashboard"))

    scanner = Scanner(target)
    findings = scanner.run()
    summary = summarize(findings)

    scan_row = ScanModel(target=target)
    db.session.add(scan_row)
    db.session.flush()

    for f in findings:
        db.session.add(FindingModel(
            scan_id=scan_row.id,
            rule_id=f.rule_id,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            description=f.description,
            recommendation=f.recommendation,
            evidence=(str(f.evidence) if f.evidence else None),
            url=f.url,
        ))

    db.session.commit()
    return redirect(url_for("scans.detail", scan_id=scan_row.id))

@bp.route("/<int:scan_id>", methods=["GET"])
def detail(scan_id: int):
    scan = ScanModel.query.get_or_404(scan_id)
    # precompute summary
    sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in scan.findings:
        sev = (f.severity or "INFO").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
    # sort findings
    order = {"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1}
    findings = sorted(scan.findings, key=lambda x: order.get((x.severity or "INFO").upper(), 1), reverse=True)
    return render_template("scan_detail.html", scan=scan, findings=findings, sev_counts=sev_counts)

@bp.route("/<int:scan_id>/pdf", methods=["GET"])
def pdf(scan_id: int):
    scan = ScanModel.query.get_or_404(scan_id)
    # build dataclass-like objects for report
    class F:
        def __init__(self, row):
            self.rule_id=row.rule_id; self.title=row.title; self.severity=row.severity
            self.confidence=row.confidence; self.description=row.description
            self.recommendation=row.recommendation; self.evidence=row.evidence; self.url=row.url
    findings = [F(r) for r in scan.findings]
    summary = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in findings:
        s = (f.severity or "INFO").upper()
        if s in summary: summary[s]+=1

    out_path = os.path.join(os.getcwd(), f"scan_{scan.id}.pdf")
    render_pdf(out_path, scan.target, findings, summary)
    return send_file(out_path, as_attachment=True, download_name=f"AWVS-Lite-Pro_scan_{scan.id}.pdf")
