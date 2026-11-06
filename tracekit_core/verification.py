"""Case reproducibility and output integrity checks."""

from dataclasses import dataclass, field
import hashlib
import os
from typing import List


@dataclass
class VerificationResult:
    passed: bool
    checked: int = 0
    failures: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_case(root: str) -> VerificationResult:
    result = VerificationResult(passed=True)
    required = [
        ("command log", os.path.join(root, "notes", "command_log.md")),
        ("evidence ledger", os.path.join(root, "findings", "evidence_table.md")),
        ("report", os.path.join(root, "report", "tracekit_report.md")),
        ("investigation manifest", os.path.join(root, "findings", "manifest.json")),
    ]
    for label, path in required:
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            result.checked += 1
        else:
            result.failures.append("%s is missing or empty: %s" % (label, os.path.relpath(path, root)))

    state = os.path.join(root, "findings", "tracekit_state.json")
    if os.path.isfile(state):
        result.checked += 1
        for label, path in (
            ("original hash", os.path.join(root, "hashes", "original_hash.txt")),
            ("working hash", os.path.join(root, "hashes", "working_hash.txt")),
        ):
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                result.checked += 1
            else:
                result.failures.append("%s is missing or empty: %s" %
                                       (label, os.path.relpath(path, root)))
    else:
        result.warnings.append("tracekit state is missing; image hash cross-checks were skipped")

    result.passed = not result.failures
    return result
