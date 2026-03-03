SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def normalize(sev: str) -> str:
    s = (sev or "").strip().upper()
    return s if s in SEVERITY_ORDER else "INFO"

def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(normalize(sev))

def summarize(findings):
    """Return counts by severity."""
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings or []:
        counts[normalize(getattr(f, "severity", "INFO"))] += 1
    return counts
