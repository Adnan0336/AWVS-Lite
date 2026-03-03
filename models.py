from datetime import datetime
from app import db

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(2048), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False, index=True)

    rule_id = db.Column(db.String(256), nullable=False)
    title = db.Column(db.String(512), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    confidence = db.Column(db.String(16), nullable=False)

    description = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text)
    url = db.Column(db.String(2048))

    scan = db.relationship("Scan", backref=db.backref("findings", lazy=True, cascade="all, delete-orphan"))
