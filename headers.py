from typing import List
import requests
from core.finding import Finding

SECURITY_HEADERS = {
    "Content-Security-Policy": ("MEDIUM", "Add a Content-Security-Policy to reduce XSS risk."),
    "X-Frame-Options": ("LOW", "Add X-Frame-Options (or frame-ancestors in CSP) to mitigate clickjacking."),
    "Strict-Transport-Security": ("MEDIUM", "Enable HSTS to enforce HTTPS (only if site supports HTTPS)."),
    "X-Content-Type-Options": ("LOW", "Set X-Content-Type-Options: nosniff."),
    "Referrer-Policy": ("LOW", "Set a Referrer-Policy to limit referrer leakage."),
    "Permissions-Policy": ("LOW", "Set a Permissions-Policy to restrict browser features."),
}

def scan(session: requests.Session, target: str, timeout: int = 8) -> List[Finding]:
    findings: List[Finding] = []
    r = session.get(target, timeout=timeout, allow_redirects=True)
    missing = []
    for h, (sev, rec) in SECURITY_HEADERS.items():
        if h not in r.headers:
            missing.append(h)
            findings.append(Finding(
                rule_id=f"headers.missing.{h.lower()}",
                title=f"Missing security header: {h}",
                severity=sev,
                confidence="HIGH",
                description=f"The response did not include the security header '{h}'.",
                recommendation=rec,
                evidence=f"Response headers: {dict(r.headers)}",
                url=r.url,
            ))
    if not missing:
        findings.append(Finding(
            rule_id="headers.ok",
            title="Security headers present (baseline)",
            severity="INFO",
            confidence="MEDIUM",
            description="No missing baseline security headers were detected for the landing page request.",
            recommendation="Continue to maintain secure header configuration across all responses.",
            evidence=f"Response headers: {dict(r.headers)}",
            url=r.url,
        ))
    return findings
