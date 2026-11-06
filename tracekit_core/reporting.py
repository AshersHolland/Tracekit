"""Report helpers shared by CLI commands and external integrations."""

import os
from typing import Iterable, Mapping, Optional


def render_findings(findings: Iterable[Mapping[str, object]]) -> str:
    rows = [
        "| Category | Claim | Confidence | Evidence | Status |",
        "|---|---|---|---|---|",
    ]
    for item in findings:
        values = [
            item.get("category", ""),
            item.get("claim", ""),
            item.get("confidence", ""),
            item.get("evidence", ""),
            item.get("status", ""),
        ]
        rows.append("| " + " | ".join(str(value or "").replace("|", "\\|") for value in values) + " |")
    return "\n".join(rows) + "\n"


def write_summary(path: str, title: str, findings: Iterable[Mapping[str, object]],
                  limitations: Optional[Iterable[str]] = None) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    limits = list(limitations or [])
    text = [
        "# %s\n" % title,
        "## Structured findings\n\n",
        render_findings(findings),
        "\n## Limitations\n\n",
    ]
    text.extend("- %s\n" % item for item in limits)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(text))
