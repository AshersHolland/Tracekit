#!/usr/bin/env python3
"""
TRACEKIT - an evidence-driven helper for forensic procedures.

WHAT IT IS
  A thin automation layer over The Sleuth Kit. It runs the same commands you
  would type by hand, records every one of them (with UTC time and exit code)
  in notes/command_log.md, hashes everything it produces, and then does the
  tedious correlation work: finding what was deleted, opening compressed
  files, totalling exposure, profiling log users, and linking IP addresses,
  MAC addresses, host names and SSH host keys across artifacts.

WHAT IT IS NOT
  It contains no case answers. Nothing in it is hard-coded to any host, file,
  user, address or number. It surfaces leads from YOUR evidence; you decide
  what they mean, assign confidence, and name the weakest link.

USAGE (run from your case directory, or set TRACEKIT_ROOT)
  tracekit.py init     --evidence /path/to/evidence.dd [--published-hash HEX] [--offset N] [--day YYYY-MM-DD]
  tracekit.py deleted  [--carve]
  tracekit.py unpack   [--all]
  tracekit.py exposure [--csv FILE ...] [--include-allocated] [--list-columns] [--amount-col NAME] [--account-col NAME]
  tracekit.py logs     [--baseline USER --subject USER]
  tracekit.py pivot    [--ip IP [IP ...]]
  tracekit.py volume   (--ip IP | --match REGEX) [--date YYYY-MM-DD] [--logs FILE FILE] [--field REGEX]
  tracekit.py stomp    [--epoch YYYY-MM-DD] [--year YYYY] [--include-system]
  tracekit.py fuse     [--from YYYY-MM-DD --to YYYY-MM-DD] [--year YYYY]
  tracekit.py cite     PATH [PATH ...]
  tracekit.py ledger
  tracekit.py versions

ENVIRONMENT
  TRACEKIT_ROOT  case directory (default: current directory; CYBR_ROOT is also honoured)
  TRACEKIT_YEAR  year assumed for syslog-style timestamps that carry no year (default: current year)
"""
import argparse, base64, collections, csv, datetime as dt, hashlib, json, os, re
import platform, shlex, shutil, subprocess, sys, tarfile, zipfile
import xml.etree.ElementTree as ET
from decimal import Decimal, InvalidOperation

__version__ = "1.0.0"

ROOT = os.path.abspath(os.environ.get("TRACEKIT_ROOT") or os.environ.get("CYBR_ROOT") or os.getcwd())
YEAR = int(os.environ.get("TRACEKIT_YEAR") or dt.date.today().year)
DIRS = ["evidence", "working", "timeline", "output", "recovered", "findings",
        "notes", "report", "hashes", "screenshots"]
P = lambda *a: os.path.join(ROOT, *a)
STATE = P("findings", "tracekit_state.json")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
FP_RE = re.compile(r"SHA256:[A-Za-z0-9+/=]{20,}")
ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")
SYS_RE = re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b")
MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


# ----------------------------------------------------------------- plumbing
def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def ensure(*d):
    for x in d:
        os.makedirs(P(x) if not os.path.isabs(x) else x, exist_ok=True)


def log_row(rc, text):
    """Append one row to notes/command_log.md (creates the table header on first use)."""
    ensure("notes")
    path = P("notes", "command_log.md")
    new = not os.path.exists(path)
    with open(path, "a") as f:
        if new:
            f.write("| Time (UTC) | rc | Command |\n|---|---|---|\n")
        f.write("| %s | %s | `%s` |\n" % (now(), rc, text))

def sh(args, out=None):
    """Run a command, log it, optionally save stdout to a file."""
    try:
        r = subprocess.run(args, capture_output=True)
    except FileNotFoundError:
        sys.exit("Required tool not found: %s (try: sudo apt install sleuthkit foremost unzip file)" % args[0])
    log_row("rc=%d" % r.returncode,
            " ".join(shlex.quote(str(x)) for x in args) + ((" > " + os.path.relpath(out, ROOT)) if out else ""))
    if out:
        ensure(os.path.dirname(out))
        with open(out, "wb") as f:
            f.write(r.stdout)
    return r


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def load_state():
    if os.path.exists(STATE):
        return json.load(open(STATE))
    return {"ledger": []}

def save_state(s):
    ensure("findings")
    json.dump(s, open(STATE, "w"), indent=2)

def need(s, *keys):
    for k in keys:
        if k not in s:
            sys.exit("Run `tracekit.py init` first (missing %s)." % k)

def ledger_add(s, **kw):
    for e in s["ledger"]:
        if e["path"] == kw["path"] and e["sha256"] == kw["sha256"]:
            return e
    kw["id"] = "E-%03d" % (len(s["ledger"]) + 1)
    s["ledger"].append(kw)
    return kw

def tsk(s, tool, *rest):
    return [tool, "-o", str(s["offset"])] + list(rest) + [s["img"]]

def write(path, text):
    ensure(os.path.dirname(path))
    with open(path, "w") as f:
        f.write(text)
    print("  wrote", os.path.relpath(path, ROOT))

def md_table(heads, rows):
    out = ["| " + " | ".join(heads) + " |", "|" + "---|" * len(heads)]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in r) + " |")
    return "\n".join(out) + "\n"

def is_text(path, n=4096):
    try:
        with open(path, "rb") as f:
            b = f.read(n)
        return b"\0" not in b
    except OSError:
        return False

def text_files(*bases, maxsize=8 << 20):
    for base in bases:
        for dp, _, fns in os.walk(base):
            for fn in fns:
                p = os.path.join(dp, fn)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                if os.path.getsize(p) <= maxsize and is_text(p):
                    yield p

def parse_ts(line, year=None):
    """Return a sortable ISO string for the first timestamp found, else None."""
    m = ISO_RE.search(line)
    if m:
        return m.group(0).replace("T", " ")
    m = SYS_RE.search(line)
    if m and year and m.group(1) in MONTHS:
        return "%04d-%02d-%02d %s" % (year, MONTHS[m.group(1)], int(m.group(2)), m.group(3))
    return None

def bodyfile():
    b = P("timeline", "bodyfile.txt")
    if not os.path.exists(b):
        sys.exit("timeline/bodyfile.txt not found. Run `tracekit.py init` first.")
    return b

def rel(p):
    return os.path.relpath(p, ROOT)

def evpath(p, base):
    """Path of an extracted file as it appears inside the image."""
    return "/" + os.path.relpath(p, base)


# --------------------------------------------------------------------- init
def cmd_init(a):
    ensure(*DIRS)
    s = load_state()
    src = os.path.abspath(a.evidence)
    ev = P("evidence", os.path.basename(src))
    if src != ev and not os.path.exists(ev):
        shutil.copyfile(src, ev)
    h1 = sha256_file(ev)
    write(P("hashes", "original_hash.txt"), "%s  %s\n" % (h1, rel(ev)))
    print("original SHA-256:", h1)
    if a.published_hash:
        ok = h1.lower() == a.published_hash.strip().lower().split()[0]
        print("original == published hash:", "MATCH" if ok else "MISMATCH - STOP, notify the evidence custodian")
        if not ok:
            sys.exit(2)          # checked BEFORE any working copy is made
    wk = P("working", "working.dd")
    if not os.path.exists(wk):
        shutil.copyfile(ev, wk)
    h2 = sha256_file(wk)
    write(P("hashes", "working_hash.txt"), "%s  %s\n" % (h2, rel(wk)))
    os.chmod(ev, 0o444)
    print("working  SHA-256:", h2)
    print("original == working:", "MATCH" if h1 == h2 else "MISMATCH - STOP")
    if h1 != h2:
        sys.exit(2)
    with open(P("notes", "chain_of_custody.md"), "a") as f:
        f.write("| %s | examiner | hashed original; created working copy | %s... |\n" % (now(), h1[:12]))
    ai = P("notes", "ai_prompts.md")
    if not os.path.exists(ai):
        write(ai, "# AI prompts used\n\nPaste every prompt you gave an AI assistant here, plus a note that "
                  "findings/tracekit.py was AI-assisted.\n")
    s.update(img=wk, evidence=ev, sha_original=h1, sha_working=h2)

    r = sh(["img_stat", wk], P("output", "img_stat.txt"))
    r = sh(["mmls", wk], P("output", "mmls.txt"))
    parts = []
    for l in r.stdout.decode("utf8", "replace").splitlines():
        m = re.match(r"^\d+:\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$", l)
        if m and not re.search(r"Unallocated|Meta|Table", m.group(5), re.I):
            parts.append((int(m.group(2)), int(m.group(4)), m.group(5).strip()))
    if a.offset is not None:
        off = a.offset
    elif parts:
        parts.sort(key=lambda x: -x[1])
        off = parts[0][0]
        if len(parts) > 1:
            print("WARNING: several partitions; using the largest. Check output/mmls.txt:", parts)
    else:
        off = 0
        print("mmls found no partition table; assuming the filesystem starts at sector 0.")
    s["offset"] = off
    print("partition offset (sectors):", off, "(derived from your own mmls output)")
    save_state(s)

    sh(tsk(s, "fsstat"), P("output", "fsstat.txt"))
    sh(tsk(s, "fls", "-r"), P("output", "file_listing.txt"))
    sh(tsk(s, "fls", "-r", "-p"), P("output", "file_listing_paths.txt"))
    sh(tsk(s, "fls", "-r", "-m", "/"), P("timeline", "bodyfile.txt"))
    sh(["mactime", "-b", P("timeline", "bodyfile.txt"), "-d", "-z", "UTC"], P("timeline", "full_timeline.csv"))
    if a.day:
        d0 = dt.date.fromisoformat(a.day)
        rng = "%s..%s" % (d0, d0 + dt.timedelta(days=1))
        sh(["mactime", "-b", P("timeline", "bodyfile.txt"), "-d", "-z", "UTC", rng], P("timeline", "incident_day.csv"))
    os.makedirs(P("recovered", "allocated"), exist_ok=True)
    sh(tsk(s, "tsk_recover", "-a") [:-1] + [s["img"], P("recovered", "allocated")])
    n = sum(len(f) for _, _, f in os.walk(P("recovered", "allocated")))
    print("allocated files extracted for analysis:", n)
    print("listing lines:", sum(1 for _ in open(P("output", "file_listing.txt"), errors="ignore")))
    save_state(s)
    print("\nNext: tracekit.py deleted")


# ------------------------------------------------------------------ deleted
FLS_RE = re.compile(r"^(?P<t>\S+)\s+(?:\*\s+)?(?P<inode>\d+)(?:\([^)]*\))?(?:-\d+-\d+)?:\s+(?P<path>.*)$")

def istat_info(s, inode):
    t = sh(tsk(s, "istat", "-z", "UTC") [:-1] + [s["img"], str(inode)]).stdout.decode("utf8", "replace")
    g = lambda pat: (re.search(pat, t) or [None, ""])[1].strip() if re.search(pat, t) else ""
    return {"raw": t, "allocated": "Not Allocated" not in t,
            "size": int(g(r"size:\s*(\d+)") or 0), "links": g(r"num of links:\s*(\d+)"),
            "atime": g(r"Accessed:\s*(.*)"), "mtime": g(r"File Modified:\s*(.*)"),
            "ctime": g(r"Inode Modified:\s*(.*)"), "dtime": g(r"Deleted:\s*(.*)"),
            "blocks": bool(re.search(r"(Direct Blocks|Extents?):?\s*\n\s*\d", t))}

def cmd_deleted(a):
    s = load_state(); need(s, "img", "offset")
    r = sh(tsk(s, "fls", "-r", "-d", "-p"), P("output", "deleted_files.txt"))
    entries = []
    for l in r.stdout.decode("utf8", "replace").splitlines():
        m = FLS_RE.match(l.strip())
        if m:
            entries.append((m["t"], int(m["inode"]), m["path"]))
    cache, real, slack, dirs, review = {}, [], [], [], []
    for t, ino, path in entries:
        base = path.rstrip("/").split("/")[-1]
        if ino not in cache:                      # istat once per inode (was re-run on every entry)
            cache[ino] = istat_info(s, ino)
        info = cache[ino]
        if base == "^":
            (slack if info["size"] == 0 else review).append((t, ino, path, info))
        elif "d" in (t.split("/")[0], t.split("/")[-1]):
            dirs.append((t, ino, path, info))
        else:
            real.append((t, ino, path, info))
    rec_rows = []
    for t, ino, path, info in real:
        dest = P("recovered", "deleted", *[p for p in path.split("/") if p not in ("", ".", "..")])
        ensure(os.path.dirname(dest))
        data = sh(tsk(s, "icat") [:-1] + [s["img"], str(ino)]).stdout
        with open(dest, "wb") as f:
            f.write(data)
        digest = sha256_file(dest)
        ftype = sh(["file", "-b", dest]).stdout.decode().strip()
        method = "icat (by inode)"
        status = "content recovered" if len(data) else ("EMPTY - istat size %d; try --carve" % info["size"] if info["size"] else "empty (size 0)")
        if len(data) and info["size"] and len(data) != info["size"]:
            status = "SIZE MISMATCH (icat %d B vs istat %d B) - verify by hand" % (len(data), info["size"])
        e = ledger_add(s, path="/" + path, inode=ino, size=len(data), sha256=digest, state="deleted",
                       method=method, filetype=ftype)
        rec_rows.append([e["id"], "/" + path, ino, len(data), info["mtime"], info["atime"], status, digest, ftype])
    dir_rows = []
    for t, ino, path, info in dirs:
        lst = sh(tsk(s, "fls") [:-1] + [s["img"], str(ino)], P("output", "deleted_dir_%d.txt" % ino))
        dir_rows.append(["/" + path, ino, info["mtime"], info["dtime"], len(lst.stdout.decode(errors="ignore").splitlines())])
    slack_rows = [["/" + p, i, inf["size"], inf["links"], "yes" if inf["allocated"] else "no",
                   "directory-block slack: name '^', size 0, no data blocks"] for _, i, p, inf in slack]
    for ino in sorted({i for _, i, _, _ in slack}):
        write(P("output", "istat_%d.txt" % ino), cache[ino]["raw"])
    save_state(s)

    parents = {os.path.dirname(r[1]) for r in rec_rows}
    out = ["# Deleted-file inventory (generated by tracekit)\n",
           "Raw `fls -r -d` entries: %d | real deleted files: %d | deleted directories: %d | slack-space entries excluded: %d | needs manual review: %d | distinct parent directories of real files: %d\n"
           % (len(entries), len(real), len(dirs), len(slack), len(review), len(parents)),
           "## Real deleted files\n",
           md_table(["ID", "Original path", "Inode", "Recovered bytes", "mtime (UTC)", "atime (UTC)", "Status", "SHA-256", "Type"], rec_rows),
           "## Deleted directories\n",
           md_table(["Path", "Inode", "mtime", "dtime (image-build time; unreliable)", "Entries listed"], dir_rows),
           "## Slack-space entries excluded (verify with istat output files)\n",
           md_table(["Listed path", "Inode", "istat size", "Links", "Allocated?", "Reason excluded"], slack_rows)]
    if review:
        out += ["## Entries named '^' with non-zero size - REVIEW MANUALLY\n",
                md_table(["Path", "Inode", "Size"], [["/" + p, i, inf["size"]] for _, i, p, inf in review])]
    write(P("findings", "deleted_inventory.md"), "\n".join(out))
    empties = [r for r in rec_rows if str(r[6]).startswith("EMPTY")]
    print("\nreal files %d | dirs %d | slack excluded %d | empty recoveries %d" % (len(real), len(dirs), len(slack), len(empties)))
    if a.carve or empties:
        if a.carve:
            sh(tsk(s, "blkls") , P("working", "unalloc.blkls"))
            sh(["foremost", "-i", P("working", "unalloc.blkls"), "-o", P("recovered", "carved"), "-T"])
            print("carved into recovered/carved/ - disclose in the report that carved files have contents only,"
                  " no path, name or timestamps.")
        else:
            print("Some inode recoveries were empty. Re-run with --carve and say so in the report.")
    _write_hashes(s)


def _write_hashes(s):
    lines = ["%s  %s  (inode %s, %s, %s)" % (e["sha256"], e["path"], e.get("inode", "-"), e["state"], e["method"])
             for e in s["ledger"]]
    write(P("hashes", "recovered_hashes.txt"), "\n".join(lines) + "\n")


# ------------------------------------------------------------------- unpack
NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"

def col_idx(ref):
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group(0):
        n = n * 26 + ord(ch) - 64
    return n - 1

def read_xlsx(path):
    z = zipfile.ZipFile(path)
    names = z.namelist()
    ss = []
    if "xl/sharedStrings.xml" in names:
        for si in ET.fromstring(z.read("xl/sharedStrings.xml")).iter(NS + "si"):
            ss.append("".join(t.text or "" for t in si.iter(NS + "t")))
    sheets = sorted((n for n in names if re.match(r"xl/worksheets/sheet\d+\.xml$", n)),
                    key=lambda n: int(re.search(r"(\d+)", n.split("/")[-1]).group(1)))
    snames = []
    if "xl/workbook.xml" in names:
        snames = [x.get("name") for x in ET.fromstring(z.read("xl/workbook.xml")).iter(NS + "sheet")]
    for i, sn in enumerate(sheets):
        rows = []
        for row in ET.fromstring(z.read(sn)).iter(NS + "row"):
            vals = {}
            for c in row.iter(NS + "c"):
                ref, t, v = c.get("r"), c.get("t"), c.find(NS + "v")
                idx = col_idx(ref) if ref else len(vals)
                if t == "inlineStr":
                    val = "".join(x.text or "" for x in c.iter(NS + "t"))
                elif v is None:
                    val = ""
                elif t == "s":
                    val = ss[int(v.text)]
                else:
                    val = v.text or ""
                vals[idx] = val
            if vals:
                rows.append([vals.get(k, "") for k in range(max(vals) + 1)])
        yield (snames[i] if i < len(snames) else "sheet%d" % (i + 1)), rows


def slug(x):
    return re.sub(r"[^\w.\-]+", "_", x)

def safe_extract(tf, m, dest):
    try:
        tf.extract(m, dest, filter="data")
    except TypeError:                              # Python without extraction filters
        tf.extract(m, dest)

def cmd_unpack(a):
    """Output names are derived from the source path, so re-running overwrites instead of duplicating.
    Recovered/deleted material goes to findings/csv/; allocated material (--all) goes to findings/csv_allocated/
    so `exposure` does not silently mix the two."""
    s = load_state(); need(s, "img")
    bases = [(P("recovered", "deleted"), P("findings", "csv"))]
    if a.all:
        bases.append((P("recovered", "allocated"), P("findings", "csv_allocated")))
    rows = []
    for base, csvdir in bases:
        for dp, _, fns in os.walk(base):
            for fn in sorted(fns):
                p = os.path.join(dp, fn)
                tag = slug(os.path.relpath(p, base))
                with open(p, "rb") as f:
                    magic = f.read(4)
                if magic[:2] == b"PK":
                    try:
                        z = zipfile.ZipFile(p)
                    except zipfile.BadZipFile:
                        continue
                    if "xl/workbook.xml" in z.namelist():
                        try:
                            sheets = list(read_xlsx(p))
                        except (KeyError, ET.ParseError, ValueError, IndexError) as e:
                            rows.append([rel(p), "xlsx (UNREADABLE - inspect by hand)", str(e), "", ""])
                            continue
                        for sheet, data in sheets:
                            out = os.path.join(csvdir, "%s__%s.csv" % (os.path.splitext(tag)[0], slug(sheet)))
                            ensure(os.path.dirname(out))
                            with open(out, "w", newline="") as f:
                                csv.writer(f).writerows(data)
                            rows.append([rel(p), "xlsx sheet '%s'" % sheet, "%d data rows" % max(len(data) - 1, 0), rel(out), sha256_file(out)])
                    else:
                        dest = P("working", "unpacked", tag + "_zip")
                        z.extractall(dest)
                        rows.append([rel(p), "zip", "%d members" % len(z.namelist()), rel(dest), ""])
                elif magic[:2] == b"\x1f\x8b":
                    dest = P("working", "unpacked", tag + "_tar")
                    ensure(dest)
                    try:
                        with tarfile.open(p) as tf:
                            safe = [m for m in tf.getmembers()
                                    if m.isfile() and not os.path.isabs(m.name) and ".." not in m.name.split("/")]
                            for m in safe:
                                safe_extract(tf, m, dest)
                    except tarfile.TarError as e:
                        rows.append([rel(p), "gzip (not tar?)", str(e), "", ""])
                        continue
                    for m in safe:
                        fp = os.path.join(dest, m.name)
                        d = sha256_file(fp)
                        rows.append([rel(p), "tar.gz member", "%d bytes" % m.size, m.name, d])
                        # path is relative to the directory it came from, never a host path
                        ledger_add(s, path="%s!%s" % (evpath(p, base), m.name), inode="-", size=m.size,
                                   sha256=d, state="inside archive", method="tar -xzf", filetype="")
                    for m in safe:
                        if m.name.lower().endswith(".csv"):
                            out = os.path.join(csvdir, "archive__%s__%s" % (os.path.splitext(tag)[0], slug(m.name)))
                            ensure(csvdir)
                            shutil.copy(os.path.join(dest, m.name), out)
                elif fn.lower().endswith(".csv"):
                    ensure(csvdir)
                    out = os.path.join(csvdir, tag)
                    shutil.copy(p, out)
                    with open(out, newline="", errors="ignore") as fh:
                        n = sum(1 for r in csv.reader(fh) if any(c.strip() for c in r)) - 1
                    rows.append([rel(p), "csv", "%d data rows" % max(n, 0), rel(out), sha256_file(out)])
    save_state(s); _write_hashes(s)
    write(P("findings", "unpacked.md"), "# Unpacked evidence\n\n" + md_table(["Source", "Kind", "Size/rows", "Output", "SHA-256"], rows))
    print("unpacked items:", len(rows), "- CSVs are in findings/csv/" + (" and findings/csv_allocated/" if a.all else ""))


# ----------------------------------------------------------------- exposure
AMT_PRI = [r"^amount", r"amt", r"^value", r"balance", r"^total", r"usd|dollar"]
ACC_PRI = [r"^(client[_ ]?)?acc(ou)?nt[_ ]?(no|num|number|id)$", r"iban", r"^acct", r"account"]
ACC_BAD = re.compile(r"name|type|status|manager|owner|bank|branch|category", re.I)
SENSITIVE = [("account number", r"acc(ou)?nt|iban|acct"), ("routing / bank code", r"routing|aba|swift|sort"),
             ("person / client name", r"(client|customer|employee|payee|beneficiary|holder)?[_ ]?name"),
             ("tax / national ID", r"ssn|tax|tin\b|national"), ("balance / amount", r"amount|balance|value|salary|pay|total"),
             ("contact details", r"email|phone|address"), ("date of birth", r"dob|birth"),
             ("wire / counterparty", r"wire|counterpart|beneficiary|reference|memo")]

def to_dec(x):
    x = (x or "").strip()
    if not x:
        return None
    neg = x.startswith("(") and x.endswith(")")
    x = re.sub(r"[^\d.\-]", "", x)
    try:
        v = Decimal(x)
    except InvalidOperation:
        return None
    return -v if neg else v

def pick(headers, pats, bad=None, forced=None):
    low = [h.strip().lower() for h in headers]
    if forced and forced.lower() in low:
        return low.index(forced.lower())
    for pat in pats:
        for i, h in enumerate(low):
            if re.search(pat, h) and not (bad and bad.search(h)):
                return i
    return None


def read_csv_rows(f):
    with open(f, newline="", errors="ignore") as fh:
        return list(csv.reader(fh))

def row_key(r):
    return hashlib.sha1("\x1f".join(c.strip().lower() for c in r).encode("utf8", "replace")).hexdigest()

def cmd_exposure(a):
    ensure("findings")
    dirs = [P("findings", "csv")] + ([P("findings", "csv_allocated")] if a.include_allocated else [])
    files = a.csv or sorted(os.path.join(dp, f) for d in dirs for dp, _, fs in os.walk(d) for f in fs if f.endswith(".csv"))
    if not files:
        sys.exit("No CSVs found. Run `deleted` then `unpack` first, or pass --csv.")
    if a.list_columns:
        for f in files:
            rws = read_csv_rows(f)
            print(rel(f), "->", rws[0] if rws else [])
        return
    per, accounts, seen = [], set(), set()
    total_rows = 0
    grand = dedup_grand = Decimal(0); cats = {}
    keysets, accsets = {}, {}
    for f in files:
        rows = read_csv_rows(f)
        if not rows:
            continue
        head, data = rows[0], [r for r in rows[1:] if any(c.strip() for c in r)]
        ai, ci = pick(head, AMT_PRI, forced=a.amount_col), pick(head, ACC_PRI, ACC_BAD, forced=a.account_col)
        tot, bad, accs, within, fkeys = Decimal(0), 0, set(), 0, set()
        for r in data:
            key = row_key(r)
            if key in fkeys:
                within += 1
            fkeys.add(key)
            v = None
            if ai is not None and ai < len(r):
                v = to_dec(r[ai])
                if v is None:
                    bad += 1
                else:
                    tot += v
            if key not in seen:
                seen.add(key)
                if v is not None:
                    dedup_grand += v
            if ci is not None and ci < len(r) and r[ci].strip():
                accs.add(r[ci].strip())
        keysets[f], accsets[f] = fkeys, accs
        accounts |= accs; grand += tot; total_rows += len(data)
        for cat, pat in SENSITIVE:
            hits = [h for h in head if re.search(pat, h, re.I)]
            if hits:
                cats.setdefault(cat, set()).update("%s: %s" % (os.path.basename(f), h) for h in hits)
        per.append([os.path.basename(f), len(data), head[ai] if ai is not None else "NOT FOUND",
                    "{:,.2f}".format(tot), head[ci] if ci is not None else "NOT FOUND", len(accs), bad, within])
    fl = list(keysets)
    ov = []
    for i in range(len(fl)):
        for j in range(i + 1, len(fl)):
            rr, aa = len(keysets[fl[i]] & keysets[fl[j]]), len(accsets[fl[i]] & accsets[fl[j]])
            if rr or aa:
                ov.append([os.path.basename(fl[i]), os.path.basename(fl[j]), rr, aa])
    ov.sort(key=lambda x: (-x[2], -x[3]))
    out = ["# Quantified exposure (generated by tracekit)\n",
           md_table(["File", "Rows", "Amount column used", "Sum", "Account column used", "Distinct accounts", "Unparsable amounts", "Repeated rows inside file"], per),
           "**Totals across the %d files listed:** %d rows, $%s, %d distinct accounts (union across files).\n"
           % (len(per), total_rows, "{:,.2f}".format(grand), len(accounts)),
           "**After removing exact-duplicate rows (case/space-insensitive, kept first copy):** %d unique rows, $%s. "
           "A repeated row can be a legitimate repeat transaction, so inspect before subtracting.\n"
           % (len(seen), "{:,.2f}".format(dedup_grand)),
           "## Overlap between files (double-count check)\n",
           (md_table(["File A", "File B", "Identical rows shared", "Accounts shared"], ov[:30]) +
            ("(%d overlapping pairs; first 30 shown)\n" % len(ov) if len(ov) > 30 else "")) if ov else "No identical rows or accounts are shared between files.\n",
           "Overlap by accounts is expected when statements describe the same clients as a spreadsheet; overlap by identical rows means the "
           "totals above double-count. Say which applies in your report.\n",
           "## Sensitive field categories (from column headers)\n",
           md_table(["Category", "Columns"], [[c, "; ".join(sorted(v))] for c, v in sorted(cats.items())]),
           "## Method (edit and paste into the report)\n",
           "Compressed spreadsheets were unzipped and their XML worksheets converted to CSV (shared strings resolved, cell references "
           "preserved). Rows are non-blank data rows beneath the header. Dollar totals sum the amount column named above using exact "
           "decimal arithmetic. Distinct accounts are unique non-empty values of the account column, unioned across files. "
           "YOU must confirm the amount/account columns are the right ones (use --list-columns / --amount-col / --account-col), pass "
           "--csv for exactly the files that were exfiltrated (default = recovered/deleted material only), and cross-check one total "
           "independently with awk or bc.\n"]
    write(P("findings", "exposure.md"), "\n".join(out))
    print("files %d | rows %d | $%s | accounts %d | unique rows %d ($%s after exact-duplicate removal) | overlapping file pairs %d"
          % (len(per), total_rows, "{:,.2f}".format(grand), len(accounts), len(seen), "{:,.2f}".format(dedup_grand), len(ov)))
    if any(o[2] for o in ov):
        print("  WARNING: some files share identical rows - the plain totals double-count. See findings/exposure.md.")
    for r in per:
        if r[2] == "NOT FOUND" or r[4] == "NOT FOUND":
            print("  check columns for", r[0], "-> use --list-columns")


# --------------------------------------------------------------------- logs
COLS = {"time": r"time|date|^ts$", "user": r"user|account|uid|principal|who", "ip": r"src|source|client|remote|^ip|addr",
        "status": r"status|code|result", "bytes": r"bytes|size|length|sent|^out", "path": r"path|url|endpoint|request|file|uri|report"}
FAIL_RE = re.compile(r"fail|denied|invalid|refused|\b40[13]\b|error", re.I)
USER_RES = [re.compile(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_.-]*)\s*:\s*TTY="),     # sudo log: "<user> : TTY=... ; USER=root ; COMMAND=..."
            re.compile(r"\buser[=:\s]+\"?([A-Za-z0-9_.@-]+)"), re.compile(r"for (?:invalid user )?([A-Za-z0-9_.-]+) from"),
            re.compile(r"\bby ([A-Za-z0-9_.-]+)\b"), re.compile(r"^\S+\s+\S+\s+([a-z_][a-z0-9_-]*)\s")]
BYTES_RES = [re.compile(r"(?<![A-Za-z0-9])(?:bytes_out|bytes_sent|sent_bytes|out_bytes|tx_bytes|resp_bytes|sent|tx)[=:\s]+(\d{2,})", re.I),   # outbound first
             re.compile(r"(?:bytes|size|length|resp_size)[=:\s]+(\d{2,})", re.I),
             re.compile(r"\b(\d{3,})\s+bytes\b", re.I)]


def layout(lines):
    """Pick the layout comment. A line that says fields/format/columns/header/layout wins; otherwise the first
    comment with 3+ words is used (check it by eye: `head -n 5 <log>`)."""
    cand = []
    for l in lines:
        if l.startswith("#"):
            toks = [t for t in re.split(r"[\s,|;\t]+", re.sub(r"^#\s*(fields?|format|columns?|header|layout)?:?", "", l, flags=re.I).strip()) if t]
            if len(toks) >= 3:
                explicit = bool(re.match(r"^#\s*(fields?|format|columns?|header|layout)\b", l, re.I))
                cand.append((explicit, [t.lower() for t in toks]))
    for explicit, toks in cand:
        if explicit:
            return toks
    return cand[0][1] if cand else None


def map_cols(names):
    m = {}
    for k, pat in COLS.items():
        for i, n in enumerate(names):
            if re.search(pat, n):
                m.setdefault(k, i)
    return m

def parse_log(path):
    lines = open(path, errors="ignore").read().splitlines()
    hdr = [l for l in lines if l.startswith("#")]
    body = [l for l in lines if l.strip() and not l.startswith("#")]
    names = layout(hdr); cm = map_cols(names) if names else {}
    recs = []
    for l in body:
        rec = {"line": l, "user": None, "ip": None, "status": None, "bytes": 0, "path": None, "ts": parse_ts(l, YEAR)}
        if cm:
            for d in (",", "\t", "|", None):
                toks = [t.strip() for t in (l.split(d) if d else l.split())]
                if d is None and len(toks) > 1 and re.match(r"\d{4}-\d{2}-\d{2}$", toks[0]) and re.match(r"\d{2}:\d{2}:\d{2}", toks[1]):
                    toks[0:2] = [toks[0] + " " + toks[1]]   # date and time share one layout field
                if len(toks) >= len(names) - 1 and len(toks) <= len(names) + 1:
                    for k, i in cm.items():
                        if i < len(toks):
                            rec[k if k != "bytes" else "bytes_raw"] = toks[i]
                    break
            if rec.get("bytes_raw", "").isdigit():
                rec["bytes"] = int(rec["bytes_raw"])
        if rec["user"] is None:
            for rx in USER_RES:
                m = rx.search(l)
                if m:
                    rec["user"] = m.group(1); break
        if rec["ip"] is None:
            m = IP_RE.search(l); rec["ip"] = m.group(0) if m else None
        if rec["status"] is None:
            m = re.search(r"\s([2-5]\d\d)\s", l); rec["status"] = m.group(1) if m else None
        if not rec["bytes"]:
            for rx in BYTES_RES:
                m = rx.search(l)
                if m:
                    rec["bytes"] = int(m.group(1)); break
        recs.append(rec)
    return hdr, recs, names

def log_files():
    base = P("recovered", "allocated")
    for p in text_files(base, P("recovered", "deleted")):
        if re.search(r"\.log(\.\d+)?$", p) or "/var/log/" in p:
            yield p

def cmd_logs(a):
    out = ["# Log profile (generated by tracekit)\n", "Comment lines beginning with # are read as layout and excluded from every count.\n"]
    profiles = {}
    for p in sorted(log_files()):
        hdr, recs, names = parse_log(p)
        if not recs:
            continue
        users = collections.defaultdict(lambda: {"n": 0, "fail": 0, "bytes": 0, "hours": collections.Counter(), "status": collections.Counter(), "ips": set(), "paths": set(), "first": None, "last": None})
        ips = collections.defaultdict(lambda: {"n": 0, "fail": 0, "ok": 0})
        for r in recs:
            u = users[r["user"] or "(unparsed)"]
            u["n"] += 1; u["bytes"] += r["bytes"]
            if FAIL_RE.search(r["line"]): u["fail"] += 1
            h = re.search(r"\b(\d{2}):\d{2}:\d{2}\b", r["line"])
            if h: u["hours"][h.group(1)] += 1
            if r["status"]: u["status"][r["status"]] += 1
            if r["ip"]: u["ips"].add(r["ip"])
            if r.get("path"): u["paths"].add(r["path"])
            if r["ts"]:
                u["first"] = min(u["first"] or r["ts"], r["ts"]); u["last"] = max(u["last"] or r["ts"], r["ts"])
            if r["ip"]:
                i = ips[r["ip"]]; i["n"] += 1
                if FAIL_RE.search(r["line"]): i["fail"] += 1
                if re.search(r"accepted|success|\b200\b", r["line"], re.I): i["ok"] += 1
        profiles[p] = users
        out.append("## %s\n" % rel(p))
        out.append("Layout used: `%s` | data lines: %d\n" % (("fields: " + " ".join(names)) if names else "none found - columns guessed from line text", len(recs)))
        out.append(md_table(["User", "Lines", "Fail-like", "Bytes", "First", "Last", "Distinct IPs", "Status mix", "Busiest hours"],
            [[k, v["n"], v["fail"], v["bytes"], v["first"] or "", v["last"] or "", len(v["ips"]),
              ", ".join("%s:%d" % x for x in v["status"].most_common(4)), ", ".join("%sh x%d" % x for x in v["hours"].most_common(3))]
             for k, v in sorted(users.items(), key=lambda kv: -kv[1]["n"])[:12]]))
        out.append(md_table(["Source IP", "Lines", "Fail-like", "Success-like"],
            [[k, v["n"], v["fail"], v["ok"]] for k, v in sorted(ips.items(), key=lambda kv: -kv[1]["fail"])[:10]]))
    if a.baseline and a.subject:
        out.append("# Baseline (%s) vs subject (%s)\n" % (a.baseline, a.subject))
        rows = []
        for p, users in profiles.items():
            b, sj = users.get(a.baseline), users.get(a.subject)
            if b or sj:
                f = lambda u: ("%d lines / %d B / %d fail-like / hrs %s / status %s" % (u["n"], u["bytes"], u["fail"], ",".join(h for h, _ in u["hours"].most_common(3)), dict(u["status"]))) if u else "-"
                rows.append([rel(p), f(b), f(sj)])
        out.append(md_table(["Log", a.baseline, a.subject], rows))
        out.append("Interpretation is yours: compare hours, volume, request mix and status progression "
                   "(for example denied-then-allowed) between the account whose job is this work and the subject.\n")
    write(P("findings", "log_profile.md"), "\n".join(out))
    print("profiled %d logs -> findings/log_profile.md" % len(profiles))


# -------------------------------------------------------------------- pivot
def fingerprint(blob):
    try:
        return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(blob + "=" * (-len(blob) % 4))).digest()).decode().rstrip("=")
    except Exception:
        return "RAW:" + blob[:28]

def cmd_pivot(a):
    base = P("recovered", "allocated")
    files = list(text_files(base, P("recovered", "deleted"), P("working", "unpacked")))
    ids = collections.defaultdict(lambda: collections.Counter())
    edges = collections.defaultdict(list)
    hostkeys = collections.defaultdict(set)
    names = collections.defaultdict(set)
    inventory = set()
    dossier = collections.defaultdict(list)
    for p in files:
        isinv = "asset" in os.path.basename(p).lower() or "inventory" in os.path.basename(p).lower()
        low = os.path.basename(p).lower()
        for n, l in enumerate(open(p, errors="ignore").read().splitlines(), 1):
            ips, macs, fps = IP_RE.findall(l), [m.lower().replace("-", ":") for m in MAC_RE.findall(l)], FP_RE.findall(l)
            if isinv:
                inventory.update(ips); inventory.update(macs)
                inventory.update(t.lower() for t in re.split(r"[\s,;|\"']+", l) if t and not t.startswith("#"))
                continue
            for x in ips + macs + fps:
                ids[x][rel(p)] += 1
            for ip in ips:
                if a.ip and ip in a.ip and len(dossier[ip]) < 40:
                    dossier[ip].append((rel(p), n, l.strip()[:220]))
            for ip in ips:
                for m in macs:
                    edges[(ip, m)].append((parse_ts(l, YEAR) or "", rel(p), n, l.strip()[:200]))
                for f in fps:
                    hostkeys[f].add(ip)
            if low == "hosts" or "/etc/hosts" in p:
                m = re.match(r"^\s*([0-9a-fA-F:.]+)\s+(.+?)\s*(#.*)?$", l)
                if m and not l.strip().startswith("#"):
                    names[m.group(1)].update(m.group(2).split())
            if low.startswith("known_hosts"):
                parts = l.split()
                if len(parts) >= 3 and not l.startswith("#"):
                    key = fingerprint(parts[2])
                    for h in parts[0].split(","):
                        h = re.sub(r"^\[|\](:\d+)?$", "", h)
                        hostkeys[key].add(h if not h.startswith("|1|") else "(hashed entry)")
    out = ["# Identifier pivot (generated by tracekit)\n",
           "Leads for attribution, not conclusions. For each lead you still need independent artifacts, an alternative-explanation test, "
           "and a named weakest link.\n"]
    ipmap = collections.defaultdict(set)
    for (ip, m) in edges:
        ipmap[m].add(ip)
    out.append("## MAC addresses bound to more than one IP address\n")
    rows = []
    for m, ips in sorted(ipmap.items()):
        if len(ips) > 1:
            for ip in sorted(ips):
                ev = sorted(edges[(ip, m)])
                rows.append([m, ip, len({e[1] for e in ev}), ev[0][0] or "(no year)", ev[-1][0] or "", ev[0][1] + ":" + str(ev[0][2])])
    out.append(md_table(["MAC", "IP", "Artifacts", "First seen", "Last seen", "Example evidence"], rows) if rows else "None found.\n")
    out.append("## IPs bound to more than one MAC\n")
    macmap = collections.defaultdict(set)
    for (ip, m) in edges:
        macmap[ip].add(m)
    rows = [[ip, ", ".join(sorted(ms))] for ip, ms in sorted(macmap.items()) if len(ms) > 1]
    out.append(md_table(["IP", "MACs"], rows) if rows else "None found.\n")
    out.append("## Host keys / fingerprints seen at more than one address or name\n")
    rows = [[k, ", ".join(sorted(v))] for k, v in hostkeys.items() if len(v) > 1]
    out.append(md_table(["Key", "Addresses / names"], rows) if rows else "None found.\n")
    out.append("## Name mappings in hosts files\n")
    out.append(md_table(["IP", "Names"], [[k, " ".join(sorted(v))] for k, v in sorted(names.items())]) if names else "None found.\n")
    out.append("## Identifiers seen in logs/files but absent from any asset-inventory file\n")
    if inventory:
        miss = [[x, sum(c.values()), ", ".join(sorted(c)[:4])] for x, c in sorted(ids.items()) if x.lower() not in inventory and not x.startswith("SHA256")]
        out.append(md_table(["Identifier", "Mentions", "Artifacts (first 4)"], miss) if miss else "None.\n")
    else:
        out.append("No file with 'asset' or 'inventory' in its name was found; locate and add it, then re-run.\n")
    out.append("## Every IP and the artifacts that mention it\n")
    out.append(md_table(["IP", "Artifacts", "Mentions", "Files"], [[x, len(c), sum(c.values()), ", ".join(sorted(c)[:3])]
               for x, c in sorted(ids.items()) if IP_RE.fullmatch(x)]))
    if dossier:
        out.append("## Dossier for requested IPs\n")
        for ip, hits in dossier.items():
            out.append("### %s\n" % ip)
            out.append(md_table(["Artifact", "Line", "Text"], hits))
    write(P("findings", "pivot.md"), "\n".join(out))
    n_share = len([r for r in ipmap.values() if len(r) > 1])
    print("MACs with >1 IP: %d | shared host keys: %d" % (n_share, len([1 for v in hostkeys.values() if len(v) > 1])))


# ------------------------------------------------------------------- volume

def cmd_volume(a):
    if not (a.ip or a.match):
        sys.exit("volume needs --ip IP and/or --match REGEX (both given = both must be on the line)")
    needles = []
    if a.ip:
        # exact-address match: 10.10.20.5 must NOT match 10.10.20.55
        needles.append(re.compile(r"(?<![\d.])%s(?!\d|\.\d)" % re.escape(a.ip)))
    if a.match:
        needles.append(re.compile(a.match))
    srcs = [os.path.abspath(x) for x in a.logs] if a.logs else [p for p in log_files()]
    rx = [re.compile(a.field, re.I)] if a.field else BYTES_RES
    rows, totals, samples = [], {}, []
    for p in srcs:
        tot, n, nobytes, sample = 0, 0, 0, []
        for l in open(p, errors="ignore"):
            if l.startswith("#") or not all(r.search(l) for r in needles):
                continue
            if a.date and a.date not in l and not (parse_ts(l, int(a.date[:4])) or "").startswith(a.date):
                continue
            for r in rx:
                m = r.search(l)
                if m:
                    tot += int(m.group(1)); n += 1
                    if len(sample) < 3:
                        sample.append(l.strip()[:200])
                    break
            else:
                nobytes += 1
        if n or nobytes:
            totals[p] = tot
            rows.append([rel(p), n, nobytes, tot, "{:,.1f}".format(tot / 1e6)])
            samples.append((rel(p), sample))
    what = a.ip or ("lines matching /%s/" % a.match)
    out = ["# Volume for %s on %s (generated by tracekit)\n" % (what, a.date or "all dates"),
           md_table(["Source log", "Lines with a byte count", "Matched lines with NO byte field", "Total bytes", "MB (10^6 B)"], rows),
           "Byte fields are matched by pattern (outbound-labelled fields first, then generic bytes/size/length). Open each log and "
           "confirm the pattern picked the right field and direction (use --field with one capture group to override).\n",
           "## Sample matched lines (check the byte field by eye)\n"]
    for src_, smp in samples:
        out.append("**%s**\n" % src_)
        out.extend("- `%s`" % x for x in smp)
        out.append("")
    vals = sorted(totals.values())
    if len(vals) >= 2:
        lo, hi = vals[0], vals[-1]
        out.append("Spread between smallest and largest source: %.2f%%. For corroboration the sources must be written by DIFFERENT "
                   "subsystems (for example the network log vs. the transfer tool's own log); two lines of one log do not count. "
                   "State the subsystem for each in the report.\n" % (100.0 * (hi - lo) / hi if hi else 0))
    write(P("findings", "volume_%s.md" % re.sub(r"\W+", "_", a.ip or a.match)), "\n".join(out))
    for r in rows:
        print(r[0], r[3], "bytes", "(%d lines, %d matched without a byte field)" % (r[1], r[2]))
    if not rows:
        print("no matching lines - for a log that does not contain the IP, use --match (user name, endpoint, ...) or sum by hand")


# -------------------------------------------------------------------- stomp
def cmd_stomp(a):
    s = load_state(); need(s, "img")
    body = [l.rstrip("\n").split("|") for l in open(bodyfile(), errors="ignore") if l.count("|") >= 10]
    rec = []
    for f in body:
        try:
            rec.append(dict(name=f[1], inode=f[2], mode=f[3], size=f[6], a=int(f[7]), m=int(f[8]), c=int(f[9])))
        except ValueError:
            pass
    ts = lambda x: dt.datetime.fromtimestamp(x, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    build = max((r["c"] for r in rec), default=0)
    logs = [r["m"] for r in rec if r["name"].startswith("/var/log/") and not r["name"].endswith("(deleted)") and r["m"] > 0]
    epoch = int(dt.datetime.fromisoformat(a.epoch).replace(tzinfo=dt.timezone.utc).timestamp()) if a.epoch else (min(logs) if logs else 0)
    first_seen = {}
    for p in text_files(P("recovered", "allocated")):
        if "/var/log/" in p:
            for l in open(p, errors="ignore"):
                t = parse_ts(l, a.year)           # year needed for syslog-style lines such as auth.log
                if t and ISO_RE.match(t):
                    for ip in IP_RE.findall(l):
                        first_seen[ip] = min(first_seen.get(ip, t), t)
    flags = []
    for r in rec:
        if r["m"] <= 0 or (r["name"].endswith("(deleted)") and r["size"] == "0"):
            continue
        why = []
        if r["a"] and r["a"] < r["m"]: why.append("atime earlier than mtime")
        if r["m"] > r["c"] > 0: why.append("mtime later than ctime (ctime cannot precede mtime on a live system)")
        execbit = "x" in r["mode"][-9:] if len(r["mode"]) >= 9 else False
        p = P("recovered", "allocated") + r["name"]
        scriptish = execbit or re.search(r"\.(sh|py|pl|rb)$|/bin/", r["name"])
        sysdir = re.match(r"^/(usr|bin|sbin|lib|lib32|lib64|opt|boot|proc|sys|dev)/", r["name"])
        if scriptish and epoch and r["m"] < epoch and (a.include_system or not sysdir):
            why.append("script/executable mtime (%s) predates the earliest log mtime (%s)" % (ts(r["m"]), ts(epoch)))
        if os.path.isfile(p) and is_text(p) and os.path.getsize(p) < 2 << 20:
            for ip in set(IP_RE.findall(open(p, errors="ignore").read())):
                fs_ = first_seen.get(ip)
                if fs_ and fs_ > ts(r["m"]):
                    why.append("references %s, which first appears in logs at %s, AFTER this file's mtime" % (ip, fs_))
        if why:
            flags.append([r["name"], r["inode"], ts(r["a"]) if r["a"] else "", ts(r["m"]), ts(r["c"]), "; ".join(why)])
    out = ["# Timestamp consistency check (generated by tracekit)\n",
           "Image-build time estimated from the latest ctime: **%s UTC**. On this image ctime and dtime reflect image construction, "
           "not the scenario, so they cannot date events; the useful test is whether atime/mtime contradict the file's role or content. "
           "ext2 stores no creation time.\n" % ts(build),
           md_table(["Path", "Inode", "atime", "mtime", "ctime", "Why flagged"], flags),
           "Flags are leads. For each one you keep, run `istat`, state which timestamp exposes the problem, and explain why the others "
           "cannot be trusted.\n"]
    write(P("findings", "timestamp_flags.md"), "\n".join(out))
    print("flagged %d entries -> findings/timestamp_flags.md" % len(flags))


# --------------------------------------------------------------------- fuse
def cmd_fuse(a):
    ev = []
    for l in open(bodyfile(), errors="ignore"):
        f = l.rstrip("\n").split("|")
        if len(f) < 11: continue
        try:
            for lab, i in (("fs-mtime", 8), ("fs-atime", 7)):
                if int(f[i]) > 0:
                    t = dt.datetime.fromtimestamp(int(f[i]), dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                    ev.append((t, lab, f[1], "inode " + f[2], f[2]))
        except ValueError:
            pass
    for p in log_files():
        for n, l in enumerate(open(p, errors="ignore"), 1):
            if l.startswith("#"): continue
            t = parse_ts(l, a.year)
            if t:
                ev.append((t, "log", rel(p), l.strip()[:200], ""))
    if a.frm: ev = [e for e in ev if e[0] >= a.frm]
    if a.to: ev = [e for e in ev if e[0] <= a.to + " 23:59:59"]
    ev.sort()
    ensure("timeline")
    with open(P("timeline", "fused_timeline.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["time_utc", "source", "artifact", "detail", "inode"]); w.writerows(ev)
    buckets = collections.Counter((e[0][:15] + "0") for e in ev if e[1] == "log")
    top = buckets.most_common(15)
    rows = [[b + " (10-min bucket)", n, "", "", "", ""] for b, n in sorted(top)]
    write(P("timeline", "incident_timeline_draft.md"),
          "# Draft timeline scaffold (generated by tracekit)\n\nBusiest 10-minute log windows. Open fused_timeline.csv at each time, choose the "
          "significant events yourself, and fill in the artifact, inode, phase and confidence.\n\n"
          + md_table(["Window", "Log lines", "Event you identify", "Artifact / inode", "Phase", "Confidence"], rows))
    print("fused %d events -> timeline/fused_timeline.csv; scaffold in timeline/incident_timeline_draft.md" % len(ev))


# --------------------------------------------------------------- cite/ledger
def cmd_cite(a):
    s = load_state(); need(s, "img", "offset")
    rows = []
    for path in a.paths:
        p = path if path.startswith("/") else "/" + path
        r = sh(tsk(s, "ifind", "-n", p.lstrip("/")))
        inode = r.stdout.decode().strip().split()[0] if r.stdout.strip() else ""
        if not inode.isdigit():
            rows.append([p, "NOT FOUND", "", "", ""]); continue
        data = sh(tsk(s, "icat") [:-1] + [s["img"], inode]).stdout
        d = hashlib.sha256(data).hexdigest()
        e = ledger_add(s, path=p, inode=int(inode), size=len(data), sha256=d, state="allocated", method="icat", filetype="")
        rows.append([e["id"], p, inode, len(data), d])
    save_state(s); _write_hashes(s)
    print(md_table(["ID", "Path", "Inode", "Bytes", "SHA-256"], rows))

def cmd_ledger(a):
    s = load_state()
    rows = [[e["id"], e["path"], e.get("inode", ""), e["size"], e["state"], e["sha256"], e.get("method", "")] for e in s["ledger"]]
    t = md_table(["ID", "Path", "Inode", "Size (B)", "State", "SHA-256", "Method"], rows)
    write(P("findings", "evidence_table.md"), "# Evidence table (paste into your report)\n\n" + t)
    _write_hashes(s); print(t)


# ----------------------------------------------------------------- versions
def cmd_versions(a):
    """Record the version and path of every tool the kit (and the template) relies on (for the report's tool table)."""
    tools = [("sha256sum", ["--version"]), ("mmls", ["-V"]), ("img_stat", ["-V"]), ("fsstat", ["-V"]), ("fls", ["-V"]),
             ("istat", ["-V"]), ("icat", ["-V"]), ("ifind", ["-V"]), ("tsk_recover", ["-V"]), ("mactime", ["-V"]),
             ("blkls", ["-V"]), ("foremost", ["-V"]), ("file", ["--version"]), ("unzip", ["-v"]), ("tar", ["--version"]),
             ("python3", ["--version"])]
    rows = []
    for t, flag in tools:
        path = shutil.which(t)
        if not path:
            rows.append([t, "NOT INSTALLED", "-"])
            continue
        r = sh([t] + flag)
        txt = (r.stdout + r.stderr).decode("utf8", "replace").strip().splitlines()
        rows.append([t, txt[0].strip() if txt else "(no output)", path])
    u = platform.uname()
    write(P("findings", "tool_versions.md"),
          "# Tool versions (generated by tracekit)\n\nRecorded %s on %s %s (%s)\n\n%s" % (now(), u.system, u.release, u.machine,
                                                                                 md_table(["Tool", "Version line", "Path"], rows)))
    miss = [r[0] for r in rows if r[1] == "NOT INSTALLED"]
    if miss:
        print("NOT INSTALLED:", ", ".join(miss))


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="tracekit " + __version__)
    sp = ap.add_subparsers(dest="cmd", required=True)
    x = sp.add_parser("init"); x.add_argument("--evidence", required=True); x.add_argument("--published-hash")
    x.add_argument("--offset", type=int); x.add_argument("--day"); x.set_defaults(f=cmd_init)
    x = sp.add_parser("deleted"); x.add_argument("--carve", action="store_true"); x.set_defaults(f=cmd_deleted)
    x = sp.add_parser("unpack"); x.add_argument("--all", action="store_true"); x.set_defaults(f=cmd_unpack)
    x = sp.add_parser("exposure"); x.add_argument("--csv", nargs="*"); x.add_argument("--list-columns", action="store_true")
    x.add_argument("--amount-col"); x.add_argument("--account-col")
    x.add_argument("--include-allocated", action="store_true", help="also read findings/csv_allocated/ (from `unpack --all`)")
    x.set_defaults(f=cmd_exposure)
    x = sp.add_parser("logs"); x.add_argument("--baseline"); x.add_argument("--subject"); x.set_defaults(f=cmd_logs)
    x = sp.add_parser("pivot"); x.add_argument("--ip", nargs="*"); x.set_defaults(f=cmd_pivot)
    x = sp.add_parser("volume"); x.add_argument("--ip"); x.add_argument("--match", help="regex that must appear on the line (user, endpoint, ...)")
    x.add_argument("--date"); x.add_argument("--logs", nargs="*")
    x.add_argument("--field"); x.set_defaults(f=cmd_volume)
    x = sp.add_parser("stomp"); x.add_argument("--epoch"); x.add_argument("--year", type=int, default=YEAR)
    x.add_argument("--include-system", action="store_true", help="also apply the script-predates-logs rule to /bin, /usr, /lib ...")
    x.set_defaults(f=cmd_stomp)
    x = sp.add_parser("fuse"); x.add_argument("--from", dest="frm"); x.add_argument("--to"); x.add_argument("--year", type=int, default=YEAR)
    x.set_defaults(f=cmd_fuse)
    x = sp.add_parser("cite"); x.add_argument("paths", nargs="+"); x.set_defaults(f=cmd_cite)
    x = sp.add_parser("ledger"); x.set_defaults(f=cmd_ledger)
    x = sp.add_parser("versions"); x.set_defaults(f=cmd_versions)
    a = ap.parse_args()
    log_row("py", "tracekit.py " + " ".join(shlex.quote(x) for x in sys.argv[1:]))   # every invocation is on record
    a.f(a)

if __name__ == "__main__":
    main()
