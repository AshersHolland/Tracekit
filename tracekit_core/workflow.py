"""Small workflow primitives for repeatable Tracekit investigations."""

import hashlib
import os
import shutil
from typing import Dict

from .manifest import Manifest


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stage_fixture_case(root: str, fixture_root: str, log_fixture_root: str,
                       case_id: str = "DEMO-001") -> Manifest:
    """Stage synthetic CSV and log evidence for a deterministic demo run."""
    csv_dir = os.path.join(root, "findings", "csv")
    log_dir = os.path.join(root, "recovered", "allocated", "var", "log")
    os.makedirs(csv_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    copies = [
        (os.path.join(fixture_root, "exposure.csv"), os.path.join(csv_dir, "exposure.csv")),
        (os.path.join(log_fixture_root, "sample_auth.log"), os.path.join(log_dir, "auth.log")),
    ]
    manifest = Manifest(case_id=case_id, examiner="demo")
    for source, destination in copies:
        shutil.copyfile(source, destination)
        manifest.record_artifact(
            os.path.relpath(destination, root),
            sha256_file(destination),
            "synthetic fixture",
        )
    manifest.save(os.path.join(root, "findings", "manifest.json"))
    return manifest
