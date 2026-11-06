# Tracekit

An evidence-driven helper for disk-image forensics, built as a thin automation layer over [The Sleuth Kit](https://www.sleuthkit.org/).

tracekit runs the same commands you would type by hand, **records every one** (UTC time, exit code) in `notes/command_log.md`, hashes everything it produces, and then does the tedious correlation work:

- inventorying and recovering deleted files (separating real files from directory-slack `^` entries)
- unpacking `.xlsx`, `.zip` and `.tar.gz` evidence into CSV
- totalling financial exposure with exact decimal arithmetic and double-count checks
- profiling log users and comparing a baseline account against a subject
- linking IPs, MACs, host names and SSH host keys across artifacts
- flagging timestamp inconsistencies (possible timestomping)
- fusing filesystem and log events into one timeline

**It contains no case answers.** Nothing is hard-coded to any host, file, user or address. It surfaces *leads* from your evidence; you decide what they mean, assign confidence, and name the weakest link.

## What Tracekit provides

Tracekit is designed to make an investigation **repeatable, explainable, and reportable**:

- **Evidence preservation:** hashes the original image, creates a working copy, records chain of custody, and logs commands with UTC timestamps and return codes.
- **Artifact analysis:** inventories files, recovers deleted content, unpacks supported archives and spreadsheets, profiles logs, correlates identifiers, checks timestamps, and fuses timelines.
- **Step-by-step transparency:** every command prints numbered progress messages so an end-user can see what is happening while the analysis runs.
- **Structured reporting:** produces Markdown findings, an evidence ledger, a machine-readable manifest, structured findings, and a final report scaffold.
- **Reproducibility checks:** `verify` checks that key investigation outputs and provenance records exist before the case is handed off.
- **Safe demonstration:** `demo` runs the workflow against synthetic fixtures without requiring a disk image or real evidence.

Tracekit supports examiner judgment; it does not automatically establish attribution, intent, causation, or final conclusions.

## Requirements

- Python 3.8+ (standard library only; no `pip install` needed)
- Linux with The Sleuth Kit and helpers:

```bash
sudo apt install sleuthkit foremost file unzip
```

## Quick start: real evidence

```bash
git clone https://github.com/<your-username>/tracekit.git
mkdir ~/case1 && cd ~/case1
python3 ~/tracekit/tracekit.py init --evidence /path/to/image.dd --published-hash <sha256>
python3 ~/tracekit/tracekit.py deleted
python3 ~/tracekit/tracekit.py unpack
python3 ~/tracekit/tracekit.py exposure --list-columns
python3 ~/tracekit/tracekit.py logs --baseline analyst --subject subject
python3 ~/tracekit/tracekit.py pivot --ip 10.10.20.5
python3 ~/tracekit/tracekit.py fuse --from 2026-04-15 --to 2026-04-16 --year 2026
python3 ~/tracekit/tracekit.py report --case-id CASE-001 --examiner "A. Examiner" \
  --incident "Unauthorized report access"
python3 ~/tracekit/tracekit.py verify
```

`init` copies the image into `evidence/` (made read-only), verifies it against the published hash **before** creating a working copy, verifies the working copy, finds the partition offset from `mmls`, and builds file listings and a `mactime` timeline. All later commands work on `working/working.dd`.

The commands print progress similar to:

```text
TRACEKIT: starting 'deleted' in /cases/case1
[step 1/5] Enumerating deleted directory entries
[step 2/5] Inspecting inode metadata and classifying entries
[step 3/5] Recovering deleted file contents and hashing recovered artifacts
...
[step 5/5] Deleted-file analysis complete
```

The generated command history is stored in `notes/command_log.md`, while raw tool output remains under `output/`.

## Quick start: synthetic demonstration

Use the demo before processing real evidence. It copies the repository's synthetic CSV and log fixtures into an isolated case directory, runs exposure and log analysis, writes a report, and verifies the generated outputs:

```bash
rm -rf /tmp/tracekit-demo
TRACEKIT_ROOT=/tmp/tracekit-demo python3 tracekit.py demo \
  --case-id DEMO-001 \
  --title "Synthetic investigation demonstration"
```

Expected outputs include:

```text
/tmp/tracekit-demo/
├── findings/
│   ├── evidence_table.md
│   ├── exposure.md
│   ├── log_profile.md
│   ├── manifest.json
│   └── tracekit_state.json
├── hashes/
│   └── recovered_hashes.txt
├── notes/
│   └── command_log.md
└── report/
    └── tracekit_report.md
```

Run verification again at any time:

```bash
TRACEKIT_ROOT=/tmp/tracekit-demo python3 tracekit.py verify
```

The demo data is synthetic and must never be treated as case evidence.

## Commands

| Command | What it does |
|---|---|
| `init --evidence IMG [--published-hash HEX] [--offset N] [--day YYYY-MM-DD]` | Hash, verify, copy, list, timeline, extract allocated files |
| `deleted [--carve]` | Recover deleted files by inode; optional `foremost` carving of unallocated space |
| `unpack [--all]` | Convert spreadsheets/archives to CSV (`--all` includes allocated files, kept separate) |
| `exposure [--csv F ...] [--amount-col C] [--account-col C] [--list-columns] [--include-allocated]` | Rows, dollar totals, distinct accounts, overlap and sensitive-field categories |
| `logs [--baseline USER --subject USER]` | Per-user and per-IP log profiles |
| `pivot [--ip IP ...]` | IP/MAC/host-key/hostname correlation and asset-inventory gaps |
| `volume (--ip IP \| --match REGEX) [--date D] [--logs F ...] [--field REGEX]` | Sum transferred bytes per log source for corroboration |
| `stomp [--epoch D] [--year YYYY] [--include-system]` | Timestamp consistency flags |
| `fuse [--from D --to D] [--year YYYY]` | Fused filesystem + log timeline and a draft scaffold |
| `cite PATH ...` | Add allocated files to the evidence ledger with inode and SHA-256 |
| `ledger` | Write the evidence table (`findings/evidence_table.md`) |
| `versions` | Record versions and paths of every tool used |
| `report [--title TEXT] [--case-id ID] [--examiner NAME] [--incident TEXT]` | Assemble provenance, coverage, findings, limitations, and review prompts into `report/tracekit_report.md` |
| `demo [--case-id ID] [--title TEXT]` | Run a complete synthetic investigation using the repository fixtures |
| `verify` | Check required provenance, ledger, manifest, and report outputs |

Every command prints numbered progress steps describing what it is doing and the evidence it is producing. This is
intentional: the terminal output is part of the examiner's operational record and makes long-running analysis
understandable to the end-user. Run `tracekit.py report` after the analyses you need; complete its executive summary,
conclusions, confidence, alternative explanations, and open questions rather than treating generated leads as answers.

Run `tracekit.py <command> -h` for details.

## Recommended investigation workflow

### 1. Establish provenance

```bash
python3 tracekit.py init \
  --evidence /evidence/host-01.dd \
  --published-hash 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --day 2026-04-15
python3 tracekit.py versions
```

If the published hash does not match, Tracekit stops before creating a working copy. Do not continue until the evidence custodian resolves the mismatch.

### 2. Recover and classify artifacts

```bash
python3 tracekit.py deleted
python3 tracekit.py unpack
python3 tracekit.py cite /etc/hosts /var/log/auth.log
python3 tracekit.py ledger
```

Use `deleted --carve` only when inode recovery is insufficient. Carved files have contents but normally do not retain their original path, filename, or timestamps.

### 3. Analyze impact and activity

```bash
python3 tracekit.py exposure --list-columns
python3 tracekit.py exposure \
  --csv findings/csv/recovered_report.csv \
  --amount-col amount \
  --account-col account_number

python3 tracekit.py logs --baseline analyst --subject subject
python3 tracekit.py volume --ip 10.20.30.40 --date 2026-04-15
python3 tracekit.py pivot --ip 10.20.30.40
```

Review heuristic selections. Confirm CSV columns, byte direction, log layouts, and identifier mappings against the raw artifacts.

### 4. Build and review the timeline

```bash
python3 tracekit.py stomp --epoch 2026-04-15 --year 2026
python3 tracekit.py fuse --from 2026-04-15 --to 2026-04-16 --year 2026
```

The fused timeline is a starting point. Add event significance, incident phase, evidence IDs, and confidence in `timeline/incident_timeline_draft.md`.

### 5. Generate and verify the report

```bash
python3 tracekit.py report \
  --title "Host 01 investigation report" \
  --case-id CASE-001 \
  --examiner "A. Examiner" \
  --incident "Suspected unauthorized data access"
python3 tracekit.py verify
```

Complete the report's executive summary and conclusions manually. For each conclusion record the claim, supporting evidence IDs, timeline bounds, confidence, alternative explanation, limitations, and follow-up action.

## Modular interfaces

The original `tracekit.py` file remains the compatibility CLI. Reusable functionality is available in the `tracekit_core/` package:

| Module | Purpose |
|---|---|
| `tracekit_core/findings.py` | `Finding` records and `FindingStore` JSON persistence |
| `tracekit_core/manifest.py` | Case metadata, command records, artifact hashes, and warnings |
| `tracekit_core/reporting.py` | Rendering structured findings and summary reports |
| `tracekit_core/verification.py` | Required-output and provenance checks |
| `tracekit_core/workflow.py` | Synthetic fixture staging and repeatable workflow helpers |

Example of creating a structured finding from another Python integration:

```python
from tracekit_core.findings import Finding, FindingStore

store = FindingStore("findings/structured_findings.json")
store.add(Finding(
    claim="The subject account accessed the report endpoint",
    category="access",
    confidence="medium",
    evidence="E-014; /var/log/auth.log lines 42-45",
    alternative="A shared service account or proxy may have made the request",
    follow_up="Correlate with endpoint and network records",
))
store.save()
```

When `findings/structured_findings.json` exists, `report` includes a structured findings table in the generated report.

## Tests

The repository includes synthetic fixtures under `tests/mock_data/` and
`tests/logs/`, plus a standard-library test suite covering log parsing,
exposure analysis, report generation, and step-by-step progress output:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover log parsing, exposure totals and duplicate detection, report generation, progress output, structured findings, manifests, verification failures, and the complete synthetic workflow. To run one test:

```bash
python3 -m unittest tests.test_tracekit.TracekitTestCase.test_demo_workflow_generates_report_and_passes_verification -v
```

Test fixtures are located at:

```text
tests/mock_data/exposure.csv
tests/mock_data/asset_inventory.txt
tests/logs/sample_auth.log
```

Additional fixtures cover pivot identifiers, custom byte fields, ZIP/XLSX
unpacking, bodyfile timelines, timestamp contradictions, and mocked Sleuth Kit
responses for `init` and deleted-file recovery. See `tests/README.md` for the
coverage summary.

## Case directory layout

```
evidence/    original image (read-only)     findings/   generated reports + state
working/     working copy, scratch          hashes/     original, working, recovered hashes
output/      raw TSK output                 notes/      command log, chain of custody
timeline/    bodyfile, mactime, fused       recovered/  allocated, deleted, carved files
```

Additional generated records include:

```text
findings/manifest.json              machine-readable case manifest
findings/structured_findings.json   examiner findings and confidence records
report/tracekit_report.md           assembled report draft
notes/command_log.md                commands, timestamps, and return codes
notes/chain_of_custody.md           image handling record
hashes/                             original, working, and recovered hashes
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `TRACEKIT_ROOT` | current directory | Case directory (`CYBR_ROOT` also accepted) |
| `TRACEKIT_YEAR` | current year | Year assumed for syslog-style timestamps with no year |

## Caveats

- Column, byte-field and log-layout detection is heuristic. Always confirm with `--list-columns`, `--field`, and the sample lines in each report, and cross-check one total by hand.
- Carved files have contents only: no path, name or timestamps.
- On ext2 there is no creation time, and on lab-built images ctime/dtime usually reflect image construction rather than events.
- `verify` confirms required records and outputs exist; it does not independently prove that an examiner's interpretation is correct.
- The generated report is a structured draft. It intentionally leaves conclusions, confidence, alternative explanations, and open questions for examiner review.
- Output is intended to support, not replace, examiner judgment.

## Use only on evidence you are authorized to examine.

## License

MIT. See [LICENSE](LICENSE).
