import requests
from typing import List
from modules import headers, redirect, info_disclosure, tls
from core.finding import Finding

DEFAULT_TIMEOUT = 8

class Scanner:
    """
    Defensive security checks intended for scanning ONLY systems you own or have permission to test.
    This engine focuses on passive and configuration/security posture checks (headers, TLS, redirects,
    basic info disclosure signals). It does not include exploit payload injection.
    """
    def __init__(self, target: str, timeout: int = DEFAULT_TIMEOUT, user_agent: str = "AWVS-Lite-Pro/2.0"):
        self.target = target.strip()
        self.timeout = timeout
        self.user_agent = user_agent

    def _session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": self.user_agent})
        return s

    def run(self) -> List[Finding]:
        sess = self._session()
        findings: List[Finding] = []
        for rule in (headers, redirect, tls, info_disclosure):
            try:
                findings.extend(rule.scan(sess, self.target, timeout=self.timeout))
            except Exception as e:
                # Keep scanner resilient; record module failure as INFO.
                findings.append(Finding(
                    rule_id=f"{rule.__name__}.error",
                    title=f"{rule.__name__} module error",
                    severity="INFO",
                    confidence="LOW",
                    description="The module encountered an error during execution.",
                    recommendation="Review logs / network connectivity and retry.",
                    evidence=str(e),
                    url=self.target,
                ))
        # Sort: highest severity first
        findings.sort(key=lambda f: __import__("core.severity").severity.severity_rank(f.severity), reverse=True)
        return findings
