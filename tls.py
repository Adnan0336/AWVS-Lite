from typing import List
import requests
from urllib.parse import urlparse
from core.finding import Finding

def scan(session: requests.Session, target: str, timeout: int = 8) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(target)
    if parsed.scheme.lower() != "https":
        findings.append(Finding(
            rule_id="tls.not_https",
            title="Target is not HTTPS",
            severity="MEDIUM",
            confidence="HIGH",
            description="The target URL is not using HTTPS. Data may be transmitted without transport encryption.",
            recommendation="Enable HTTPS with a valid certificate and redirect HTTP to HTTPS.",
            evidence=target,
            url=target,
        ))
        return findings

    # Basic request verifies certificate by default
    try:
        r = session.get(target, timeout=timeout, allow_redirects=True)
        findings.append(Finding(
            rule_id="tls.https_ok",
            title="HTTPS reachable",
            severity="INFO",
            confidence="HIGH",
            description="The target is reachable over HTTPS with certificate verification enabled.",
            recommendation="Ensure modern TLS versions/ciphers and keep certificate renewals automated.",
            evidence=r.url,
            url=r.url,
        ))
    except requests.exceptions.SSLError as e:
        findings.append(Finding(
            rule_id="tls.ssl_error",
            title="TLS/SSL certificate verification error",
            severity="HIGH",
            confidence="HIGH",
            description="A TLS certificate verification error occurred when connecting.",
            recommendation="Fix certificate chain, hostname mismatch, or expiration issues.",
            evidence=str(e),
            url=target,
        ))
    return findings
