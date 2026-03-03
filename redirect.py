from typing import List
import requests
from urllib.parse import urlparse
from core.finding import Finding

def scan(session: requests.Session, target: str, timeout: int = 8) -> List[Finding]:
    findings: List[Finding] = []
    r = session.get(target, timeout=timeout, allow_redirects=True)
    if r.history:
        # Identify cross-domain redirects
        start_host = urlparse(target).netloc
        end_host = urlparse(r.url).netloc
        if start_host and end_host and start_host.lower() != end_host.lower():
            findings.append(Finding(
                rule_id="redirect.cross_domain",
                title="Cross-domain redirect observed",
                severity="LOW",
                confidence="MEDIUM",
                description="The target redirected to a different hostname. This may be intended (CDN/www redirect) but should be reviewed.",
                recommendation="Confirm redirects are expected and that user-controlled parameters cannot influence redirect destinations.",
                evidence=" -> ".join([h.url for h in r.history] + [r.url]),
                url=r.url,
            ))
        else:
            findings.append(Finding(
                rule_id="redirect.present",
                title="Redirect chain observed",
                severity="INFO",
                confidence="HIGH",
                description="The target performs one or more redirects.",
                recommendation="Ensure redirects are expected and consistent.",
                evidence=" -> ".join([h.url for h in r.history] + [r.url]),
                url=r.url,
            ))
    else:
        findings.append(Finding(
            rule_id="redirect.none",
            title="No redirects observed",
            severity="INFO",
            confidence="HIGH",
            description="The target did not perform redirects for the landing request.",
            recommendation="No action required.",
            evidence=r.url,
            url=r.url,
        ))
    return findings
