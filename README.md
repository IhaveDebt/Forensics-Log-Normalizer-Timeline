
---

# 3 — Forensics Log Normalizer & Timeline (log_timeline.py)

**File:** `src/log_timeline.py`
```python
#!/usr/bin/env python3
"""
Forensics Log Normalizer & Timeline - log_timeline.py

- Ingest logs (syslog-like), normalize into structured records
- Build a timeline and simple pivot queries
- Export CSV for sharing in investigations (anonymized)
"""

import re
import csv
from datetime import datetime
from collections import defaultdict
import sys

SYSLOG_RE = re.compile(r'^(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+) (?P<host>\S+) (?P<proc>\S+): (?P<msg>.*)$')

def parse_syslog_line(line):
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(m.group("ts"), "%b %d %H:%M:%S").replace(year=datetime.now().year)
    return {
        "timestamp": ts.isoformat(),
        "host": m.group("host"),
        "proc": m.group("proc"),
        "message": m.group("msg")
    }

def load_logfile(path):
    recs = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            r = parse_syslog_line(line)
            if r:
                recs.append(r)
    return recs

def build_timeline(records):
    return sorted(records, key=lambda r: r["timestamp"])

def anonymize(records):
    # simple: remove IP-looking tokens
    ip_re = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
    out = []
    for r in records:
        r2 = r.copy()
        r2["message"] = ip_re.sub("[IP]", r2["message"])
        out.append(r2)
    return out

def export_csv(records, outpath):
    keys = ["timestamp", "host", "proc", "message"]
    with open(outpath, "w", newline='', encoding='utf8') as f:
        w = csv.DictWriter(f, keys)
        w.writeheader()
        for r in records:
            w.writerow({k: r.get(k, "") for k in keys})

def main():
    if len(sys.argv) < 2:
        print("Usage: python src/log_timeline.py <logfile>")
        sys.exit(1)
    records = load_logfile(sys.argv[1])
    timeline = build_timeline(records)
    anon = anonymize(timeline)
    export_csv(anon, "timeline_export.csv")
    print(f"Processed {len(anon)} records -> timeline_export.csv")

if __name__ == "__main__":
    main()
