# tracekit

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

## Requirements

- Python 3.8+ (standard library only; no `pip install` needed)
- Linux with The Sleuth Kit and helpers:

```bash
sudo apt install sleuthkit foremost file unzip
```

## Quick start

```bash
git clone https://github.com/<your-username>/tracekit.git
mkdir ~/case1 && cd ~/case1
python3 ~/tracekit/tracekit.py init --evidence /path/to/image.dd --published-hash <sha256>
python3 ~/tracekit/tracekit.py deleted
python3 ~/tracekit/tracekit.py unpack
python3 ~/tracekit/tracekit.py exposure --list-columns
```

`init` copies the image into `evidence/` (made read-only), verifies it against the published hash **before** creating a working copy, verifies the working copy, finds the partition offset from `mmls`, and builds file listings and a `mactime` timeline. All later commands work on `working/working.dd`.

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

Run `tracekit.py <command> -h` for details.

## Case directory layout

```
evidence/    original image (read-only)     findings/   generated reports + state
working/     working copy, scratch          hashes/     original, working, recovered hashes
output/      raw TSK output                 notes/      command log, chain of custody
timeline/    bodyfile, mactime, fused       recovered/  allocated, deleted, carved files
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
- Output is intended to support, not replace, examiner judgment.

## Use only on evidence you are authorized to examine.

## License

MIT. See [LICENSE](LICENSE).
