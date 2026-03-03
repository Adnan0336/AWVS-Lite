from typing import List
import requests
from core.finding import Finding

SERVER_LEAK_KEYS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

def scan(session: requests.Session, target: str, timeout: int = 8) -> List[Finding]:
    findings: List[Finding] = []
    r = session.get(target, timeout=timeout, allow_redirects=True)

    leaks = []
    for k, v in r.headers.items():
        if k.lower() in SERVER_LEAK_KEYS and v:
            leaks.append((k, v))

    if leaks:
        findings.append(Finding(
            rule_id="info_disclosure.headers",
            title="Potential information disclosure via response headers",
            severity="LOW",
            confidence="MEDIUM",
            description="The response includes technology-identifying headers that may aid attackers in fingerprinting.",
            recommendation="Consider minimizing or normalizing identifying headers (where feasible) and keep software patched.",
            evidence=str(leaks),
            url=r.url,
        ))
    else:
        findings.append(Finding(
            rule_id="info_disclosure.none",
            title="No obvious technology disclosure headers detected",
            severity="INFO",
            confidence="MEDIUM",
            description="No common technology-identifying headers were detected on the landing response.",
            recommendation="Continue to maintain patching and hardening practices.",
            evidence=f"Headers checked: {SERVER_LEAK_KEYS}",
            url=r.url,
        ))
    return findings
