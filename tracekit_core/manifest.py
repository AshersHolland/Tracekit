"""Machine-readable record of investigation inputs, commands, and outputs."""

from dataclasses import asdict, dataclass, field
import datetime as dt
import json
import os
from typing import Dict, List, Optional


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


@dataclass
class Manifest:
    case_id: str = "not provided"
    examiner: str = "not provided"
    created_at: str = field(default_factory=utc_now)
    commands: List[Dict[str, object]] = field(default_factory=list)
    artifacts: List[Dict[str, object]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def record_command(self, command: str, return_code: int, output: Optional[str] = None) -> None:
        row = {"time": utc_now(), "command": command, "return_code": return_code}
        if output:
            row["output"] = output
        self.commands.append(row)

    def record_artifact(self, path: str, sha256: str, kind: str = "output") -> None:
        self.artifacts.append({"path": path, "sha256": sha256, "kind": kind})

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def save(self, path: str) -> None:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "Manifest":
        with open(path, encoding="utf-8") as fh:
            return cls(**json.load(fh))
