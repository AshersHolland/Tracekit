"""Structured findings that can be rendered into investigator-facing reports."""

from dataclasses import asdict, dataclass
import json
import os
from typing import Dict, Iterable, List, Optional


@dataclass
class Finding:
    claim: str
    category: str
    confidence: str = "unassigned"
    evidence: Optional[str] = None
    alternative: Optional[str] = None
    status: str = "lead"
    follow_up: Optional[str] = None


class FindingStore:
    def __init__(self, path: str):
        self.path = path
        self.items: List[Finding] = []

    def add(self, finding: Finding) -> Finding:
        self.items.append(finding)
        return finding

    def extend(self, findings: Iterable[Finding]) -> None:
        self.items.extend(findings)

    def save(self) -> None:
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump([asdict(item) for item in self.items], fh, indent=2)

    def load(self) -> List[Finding]:
        if not os.path.exists(self.path):
            return self.items
        with open(self.path, encoding="utf-8") as fh:
            self.items = [Finding(**item) for item in json.load(fh)]
        return self.items

    def as_dicts(self) -> List[Dict[str, Optional[str]]]:
        return [asdict(item) for item in self.items]
