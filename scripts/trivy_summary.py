"""Turn Trivy JSON reports into a before/after table (Markdown). Usage: trivy_summary.py report1.json ..."""
import json
import sys
from pathlib import Path

rows = ["| Image | CRITICAL | HIGH | MEDIUM | LOW | fixable (HIGH+CRIT) |", "|---|---|---|---|---|---|"]
for f in sys.argv[1:]:
    data = json.loads(Path(f).read_text())
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    fixable = 0
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "UNKNOWN")
            if sev in counts:
                counts[sev] += 1
            if sev in ("HIGH", "CRITICAL") and v.get("FixedVersion"):
                fixable += 1
    name = Path(f).stem
    rows.append(f"| `{name}` | {counts['CRITICAL']} | {counts['HIGH']} | {counts['MEDIUM']} | {counts['LOW']} | {fixable} |")
print("\n".join(rows))
