import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from argparse import Namespace
from unittest import mock

import tracekit
from tracekit_core.findings import Finding, FindingStore
from tracekit_core.manifest import Manifest
from tracekit_core.reporting import render_findings
from tracekit_core.verification import verify_case


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "mock_data")
LOG_FIXTURES = os.path.join(ROOT, "tests", "logs")


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


class TracekitTestCase(unittest.TestCase):
    def setUp(self):
        self.case_root = tempfile.mkdtemp(prefix="tracekit-test-")
        self.old_root = tracekit.ROOT
        self.old_state = tracekit.STATE
        tracekit.ROOT = self.case_root
        tracekit.STATE = os.path.join(self.case_root, "findings", "tracekit_state.json")

    def tearDown(self):
        tracekit.ROOT = self.old_root
        tracekit.STATE = self.old_state
        shutil.rmtree(self.case_root)

    def test_parse_log_reads_layout_users_status_and_bytes(self):
        path = os.path.join(LOG_FIXTURES, "sample_auth.log")
        headers, records, names = tracekit.parse_log(path)

        self.assertEqual(headers[0].startswith("# fields:"), True)
        self.assertEqual(names[:3], ["timestamp", "user", "source_ip"])
        self.assertEqual(records[1]["user"], "subject")
        self.assertEqual(records[1]["ip"], "10.20.30.40")
        self.assertEqual(records[2]["status"], "200")
        self.assertEqual(records[2]["bytes"], 2048)
        self.assertEqual(records[2]["ts"], "2026-04-15 09:06:00")

    def test_exposure_reports_totals_and_duplicate_rows(self):
        csv_dir = os.path.join(self.case_root, "findings", "csv")
        os.makedirs(csv_dir)
        shutil.copy(os.path.join(FIXTURES, "exposure.csv"), csv_dir)

        output = io.StringIO()
        args = Namespace(
            csv=None, list_columns=False, amount_col=None, account_col=None,
            include_allocated=False,
        )
        with contextlib.redirect_stdout(output):
            tracekit.cmd_exposure(args)

        finding = os.path.join(self.case_root, "findings", "exposure.md")
        with open(finding, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("$2,701.00", text)
        self.assertIn("$1,450.50", text)
        self.assertIn("Repeated rows inside file", text)
        self.assertIn("[step 4/4]", output.getvalue())

    def test_logs_creates_profile_from_fixture(self):
        destination = os.path.join(self.case_root, "recovered", "allocated", "var", "log")
        os.makedirs(destination)
        shutil.copy(
            os.path.join(LOG_FIXTURES, "sample_auth.log"),
            os.path.join(destination, "auth.log"),
        )

        output = io.StringIO()
        args = Namespace(baseline="analyst", subject="subject")
        with contextlib.redirect_stdout(output):
            tracekit.cmd_logs(args)

        with open(
            os.path.join(self.case_root, "findings", "log_profile.md"),
            encoding="utf-8",
        ) as fh:
            text = fh.read()
        self.assertIn("Baseline (analyst) vs subject (subject)", text)
        self.assertIn("subject", text)
        self.assertIn("2048", text)
        self.assertIn("[step 3/3]", output.getvalue())

    def test_report_embeds_findings_and_provenance(self):
        os.makedirs(os.path.join(self.case_root, "findings"))
        os.makedirs(os.path.join(self.case_root, "notes"))
        with open(
            os.path.join(self.case_root, "findings", "evidence_table.md"),
            "w",
            encoding="utf-8",
        ) as fh:
            fh.write("# Evidence table\n\n| ID | Path |\n|---|---|\n| E-001 | /mock.txt |\n")
        with open(
            os.path.join(self.case_root, "notes", "command_log.md"),
            "w",
            encoding="utf-8",
        ) as fh:
            fh.write("| Time (UTC) | rc | Command |\n|---|---|---|\n")
        with open(tracekit.STATE, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "ledger": [{"id": "E-001", "path": "/mock.txt", "size": 4}],
                    "evidence": "evidence/mock.dd",
                    "img": "working/working.dd",
                    "sha_original": "a" * 64,
                    "sha_working": "a" * 64,
                    "offset": 0,
                },
                fh,
            )

        output = io.StringIO()
        args = Namespace(
            title="Synthetic investigation",
            case_id="TEST-001",
            examiner="Test Examiner",
            incident="Fixture validation",
        )
        with contextlib.redirect_stdout(output):
            tracekit.cmd_report(args)

        with open(
            os.path.join(self.case_root, "report", "tracekit_report.md"),
            encoding="utf-8",
        ) as fh:
            report = fh.read()
        self.assertIn("# Synthetic investigation", report)
        self.assertIn("TEST-001", report)
        self.assertIn("Evidence table", report)
        self.assertIn("Open questions and limitations", report)
        self.assertIn("[step 4/4]", output.getvalue())

    def test_core_modules_persist_findings_and_manifest(self):
        findings_path = os.path.join(self.case_root, "findings", "structured_findings.json")
        store = FindingStore(findings_path)
        store.add(Finding(
            claim="Subject accessed the synthetic report",
            category="access",
            confidence="medium",
            evidence="tests/logs/sample_auth.log:4",
        ))
        store.save()
        loaded = FindingStore(findings_path)
        self.assertEqual(loaded.load()[0].category, "access")
        self.assertIn("Subject accessed", render_findings(loaded.as_dicts()))

        manifest_path = os.path.join(self.case_root, "findings", "manifest.json")
        manifest = Manifest(case_id="TEST-CORE", examiner="unit-test")
        manifest.record_command("tracekit.py demo", 0)
        manifest.save(manifest_path)
        restored = Manifest.load(manifest_path)
        self.assertEqual(restored.case_id, "TEST-CORE")
        self.assertEqual(restored.commands[0]["return_code"], 0)

    def test_verify_case_reports_missing_outputs(self):
        result = verify_case(self.case_root)
        self.assertFalse(result.passed)
        self.assertTrue(any("report" in failure for failure in result.failures))

    def test_demo_workflow_generates_report_and_passes_verification(self):
        output = io.StringIO()
        args = Namespace(case_id="DEMO-TEST", title="Demo test")
        with contextlib.redirect_stdout(output):
            tracekit.cmd_demo(args)

        report_path = os.path.join(self.case_root, "report", "tracekit_report.md")
        self.assertTrue(os.path.isfile(report_path))
        with open(report_path, encoding="utf-8") as fh:
            self.assertIn("Demo test", fh.read())
        self.assertIn("verification passed", output.getvalue())

    def test_unpack_fixture_extracts_archive_and_workbook(self):
        source = os.path.join(self.case_root, "recovered", "deleted")
        os.makedirs(source)
        os.makedirs(os.path.join(self.case_root, "findings"))
        shutil.copy(os.path.join(FIXTURES, "sample_archive.zip"), source)
        shutil.copy(os.path.join(FIXTURES, "sample_workbook.xlsx"), source)
        with open(tracekit.STATE, "w", encoding="utf-8") as fh:
            json.dump({"ledger": [], "img": "working/working.dd"}, fh)

        with contextlib.redirect_stdout(io.StringIO()):
            tracekit.cmd_unpack(Namespace(all=False))

        with open(
            os.path.join(self.case_root, "findings", "unpacked.md"),
            encoding="utf-8",
        ) as fh:
            text = fh.read()
        self.assertIn("xlsx sheet 'Transactions'", text)
        self.assertIn("zip", text)
        self.assertTrue(os.path.isfile(
            os.path.join(self.case_root, "findings", "csv", "sample_workbook__Transactions.csv")
        ))

    def test_pivot_fixture_finds_shared_mac_and_requested_ip(self):
        destination = os.path.join(self.case_root, "recovered", "allocated")
        os.makedirs(destination)
        for name in ("asset_inventory.txt", "pivot_network.log", "hosts", "known_hosts"):
            shutil.copy(os.path.join(FIXTURES, name), os.path.join(destination, name))

        with contextlib.redirect_stdout(io.StringIO()):
            tracekit.cmd_pivot(Namespace(ip=["10.20.30.41"]))

        with open(
            os.path.join(self.case_root, "findings", "pivot.md"),
            encoding="utf-8",
        ) as fh:
            text = fh.read()
        self.assertIn("10.20.30.41", text)
        self.assertIn("aa:bb:cc:dd:ee:ff", text)
        self.assertIn("Dossier for requested IPs", text)

    def test_volume_fixture_supports_ip_and_custom_field(self):
        log_path = os.path.join(FIXTURES, "volume_custom.log")
        with contextlib.redirect_stdout(io.StringIO()):
            tracekit.cmd_volume(Namespace(
                ip="10.20.30.40", match=None, date="2026-04-15",
                logs=[log_path], field=r"payload_bytes=(\d+)",
            ))

        with open(
            os.path.join(self.case_root, "findings", "volume_10_20_30_40.md"),
            encoding="utf-8",
        ) as fh:
            text = fh.read()
        self.assertIn("| 3072 |", text)
        self.assertIn("payload_bytes=3072", text)

    def test_fuse_fixture_creates_filtered_timeline(self):
        os.makedirs(os.path.join(self.case_root, "timeline"))
        shutil.copy(
            os.path.join(FIXTURES, "timeline_bodyfile.txt"),
            os.path.join(self.case_root, "timeline", "bodyfile.txt"),
        )
        log_dir = os.path.join(self.case_root, "recovered", "allocated", "var", "log")
        os.makedirs(log_dir)
        shutil.copy(
            os.path.join(LOG_FIXTURES, "sample_auth.log"),
            os.path.join(log_dir, "auth.log"),
        )

        with contextlib.redirect_stdout(io.StringIO()):
            tracekit.cmd_fuse(Namespace(frm="2026-04-15", to="2026-04-15", year=2026))

        with open(
            os.path.join(self.case_root, "timeline", "fused_timeline.csv"),
            encoding="utf-8",
        ) as fh:
            text = fh.read()
        self.assertIn("fs-mtime", text)
        self.assertIn("2026-04-15 09:06:00", text)
        self.assertTrue(os.path.isfile(
            os.path.join(self.case_root, "timeline", "incident_timeline_draft.md")
        ))

    def test_stomp_fixture_flags_script_chronology(self):
        os.makedirs(os.path.join(self.case_root, "timeline"))
        os.makedirs(os.path.join(self.case_root, "findings"))
        shutil.copy(
            os.path.join(FIXTURES, "bodyfile.txt"),
            os.path.join(self.case_root, "timeline", "bodyfile.txt"),
        )
        script = os.path.join(
            self.case_root, "recovered", "allocated", "home", "subject",
            "timestamp_script.sh",
        )
        os.makedirs(os.path.dirname(script))
        shutil.copy(os.path.join(FIXTURES, "timestamp_script.sh"), script)
        log_dir = os.path.join(self.case_root, "recovered", "allocated", "var", "log")
        os.makedirs(log_dir)
        shutil.copy(
            os.path.join(LOG_FIXTURES, "sample_auth.log"),
            os.path.join(log_dir, "auth.log"),
        )
        with open(tracekit.STATE, "w", encoding="utf-8") as fh:
            json.dump({"ledger": [], "img": "working/working.dd"}, fh)

        with contextlib.redirect_stdout(io.StringIO()):
            tracekit.cmd_stomp(Namespace(
                epoch="2026-04-16", year=2026, include_system=False,
            ))

        with open(
            os.path.join(self.case_root, "findings", "timestamp_flags.md"),
            encoding="utf-8",
        ) as fh:
            text = fh.read()
        self.assertIn("/home/subject/timestamp_script.sh", text)
        self.assertIn("predates the earliest log mtime", text)

    def test_cite_fixture_records_hash_in_ledger(self):
        os.makedirs(os.path.join(self.case_root, "findings"))
        with open(tracekit.STATE, "w", encoding="utf-8") as fh:
            json.dump({"ledger": [], "img": "working/working.dd", "offset": 0}, fh)

        class Result:
            def __init__(self, stdout):
                self.stdout = stdout

        def fake_sh(args, out=None):
            return Result(b"123\n" if args[0] == "ifind" else b"cited synthetic bytes")

        with mock.patch.object(tracekit, "sh", side_effect=fake_sh):
            with contextlib.redirect_stdout(io.StringIO()):
                tracekit.cmd_cite(Namespace(paths=["/etc/hosts"]))

        state = tracekit.load_state()
        self.assertEqual(state["ledger"][0]["path"], "/etc/hosts")
        self.assertEqual(state["ledger"][0]["inode"], 123)
        self.assertTrue(os.path.isfile(
            os.path.join(self.case_root, "hashes", "recovered_hashes.txt")
        ))

    def test_init_fixture_records_hashes_and_mocked_tsk_outputs(self):
        evidence = os.path.join(self.case_root, "synthetic.dd")
        with open(evidence, "wb") as fh:
            fh.write(b"synthetic disk image bytes")
        tsk_dir = os.path.join(FIXTURES, "tsk")

        class Result:
            def __init__(self, stdout=b"", returncode=0):
                self.stdout = stdout
                self.returncode = returncode
                self.stderr = b""

        def fake_sh(args, out=None):
            name = args[0]
            fixture = {
                "img_stat": "img_stat.txt",
                "mmls": "mmls.txt",
                "fsstat": "fsstat.txt",
            }.get(name)
            if name == "fls":
                content = read_bytes(os.path.join(tsk_dir, "file_listing.txt"))
            elif name == "mmls":
                content = read_bytes(os.path.join(tsk_dir, fixture))
            elif fixture:
                content = read_bytes(os.path.join(tsk_dir, fixture))
            elif name == "mactime":
                content = b"time,detail\n"
            else:
                content = b""
            result = Result(content)
            if out:
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "wb") as fh:
                    fh.write(content)
            return result

        with mock.patch.object(tracekit, "sh", side_effect=fake_sh):
            with contextlib.redirect_stdout(io.StringIO()):
                tracekit.cmd_init(Namespace(
                    evidence=evidence, published_hash=None, offset=None, day=None,
                ))

        state = tracekit.load_state()
        self.assertEqual(state["offset"], 0)
        self.assertEqual(state["sha_original"], state["sha_working"])
        self.assertTrue(os.path.isfile(
            os.path.join(self.case_root, "timeline", "bodyfile.txt")
        ))

    def test_deleted_fixture_recovers_file_with_mocked_tsk(self):
        os.makedirs(os.path.join(self.case_root, "findings"))
        with open(tracekit.STATE, "w", encoding="utf-8") as fh:
            json.dump({
                "ledger": [], "img": "working/working.dd", "offset": 0,
            }, fh)
        tsk_dir = os.path.join(FIXTURES, "tsk")

        class Result:
            def __init__(self, stdout=b""):
                self.stdout = stdout
                self.returncode = 0
                self.stderr = b""

        def fake_sh(args, out=None):
            if args[0] == "fls" and "-d" in args:
                data = read_bytes(os.path.join(tsk_dir, "file_listing.txt"))
            elif args[0] == "istat":
                data = read_bytes(os.path.join(tsk_dir, "istat_deleted.txt"))
            elif args[0] == "icat":
                data = b"deleted-file-data"
            elif args[0] == "file":
                data = b"text/plain\n"
            else:
                data = b""
            if out:
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "wb") as fh:
                    fh.write(data)
            return Result(data)

        with mock.patch.object(tracekit, "sh", side_effect=fake_sh):
            with contextlib.redirect_stdout(io.StringIO()):
                tracekit.cmd_deleted(Namespace(carve=False))

        inventory = os.path.join(self.case_root, "findings", "deleted_inventory.md")
        with open(inventory, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("/deleted.txt", text)
        self.assertTrue(os.path.isfile(
            os.path.join(self.case_root, "recovered", "deleted", "deleted.txt")
        ))


if __name__ == "__main__":
    unittest.main()
