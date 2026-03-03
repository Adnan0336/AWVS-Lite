from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence: str  # LOW, MEDIUM, HIGH
    description: str
    recommendation: str
    evidence: Optional[str] = None
    url: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
