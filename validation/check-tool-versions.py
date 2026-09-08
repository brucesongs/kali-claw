#!/usr/bin/env python3
"""check-tool-versions.py — automated baseline drift checks.

Reads the latest KALI_TOOLS_BASELINE file, extracts tracked tools and their
recorded versions, then verifies each against the running environment.

Two channels:
  - online (default when possible): probe via `apt-cache policy <pkg>` and
    `<tool> --version` / `-v` on the Kali host
  - offline (--offline or no tool found): emit a reconciliation checklist
    (recorded version vs "needs manual verification") for review

Usage:
  python3 validation/check-tool-versions.py                     # online probe
  python3 validation/check-tool-versions.py --offline           # checklist only
  python3 validation/check-tool-versions.py --json              # machine-readable
  python3 validation/check-tool-versions.py --baseline KALI_TOOLS_BASELINE_2026_09.md
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_BASELINE = None  # resolved in main(): newest KALI_TOOLS_BASELINE_*.md

VERSION_PROBE_FLAGS = ["--version", "-version", "-v", "-V", "version"]
ROLLING_MARKERS = ("rolling", "= 2026", "详见")


def find_latest_baseline(explicit: str = None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.exists():
            sys.exit(f"ERROR: baseline not found: {p}")
        return p
    candidates = sorted(REPO.glob("KALI_TOOLS_BASELINE_*.md"),
                        key=lambda p: p.stem.split("_")[-1])
    if not candidates:
        sys.exit("ERROR: no KALI_TOOLS_BASELINE_*.md found in repo root")
    return candidates[-1]


def parse_baseline(path: Path) -> list:
    """Extract (rank, tool, recorded_version, row) from the Top-N table."""
    tools = []
    in_top = False
    for line in path.read_text(errors="ignore").splitlines():
        if line.startswith("## ") and "Top" in line:
            in_top = True
            continue
        if in_top and line.startswith("## "):
            break
        m = re.match(r"^\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|[^|]*\|[^|]*\|[^|]*\|\s*([^|]*?)\s*\|", line)
        if m and "工具" not in m.group(2) and "---" not in line:
            rank, name, version = int(m.group(1)), m.group(2).strip(), m.group(3).strip()
            if name and not name.startswith("("):
                tools.append(dict(rank=rank, tool=name, recorded=version, row=line))
    return tools


def is_rolling(version: str) -> bool:
    return any(marker in version for marker in ROLLING_MARKERS)


def clean_version(recorded: str) -> str:
    """Strip annotations to get a comparable version token."""
    v = re.sub(r"\(.*?\)", "", recorded)
    v = re.sub(r"[⚠️✅⬆=+*].*?(?=\s*\d|\b)", "", v)  # drop markers/bold
    v = v.replace("*", "").replace("LTS", "").strip()
    m = re.search(r"\d+\.\d[\w.+-]*", v)
    return m.group(0) if m else ""


def probe_binary(tool: str) -> str:
    """Try to get an installed version via common CLI flags."""
    binary = tool.split()[0].split("(")[0].strip()
    if not shutil.which(binary):
        return ""
    for flag in VERSION_PROBE_FLAGS:
        try:
            r = subprocess.run([binary, flag], capture_output=True, text=True, timeout=10)
            out = (r.stdout + r.stderr).strip()
        except (subprocess.TimeoutExpired, OSError):
            continue
        m = re.search(r"(\d+\.\d[\w.+-]*)", out)
        if m and out and not out.lower().startswith("usage"):
            return m.group(1)
    return ""


def probe_apt(tool: str) -> str:
    """Kali host: apt-cache policy lookup (first version-ish token)."""
    if not shutil.which("apt-cache"):
        return ""
    pkg = tool.split()[0].split("(")[0].strip()
    try:
        r = subprocess.run(["apt-cache", "policy", pkg], capture_output=True, text=True, timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    m = re.search(r"Candidate:\s*(\S+)", r.stdout)
    return m.group(1) if m else ""


def main() -> None:
    ap = argparse.ArgumentParser(description="Automated baseline drift check")
    ap.add_argument("--baseline", help="baseline file (default: newest KALI_TOOLS_BASELINE_*.md)")
    ap.add_argument("--offline", action="store_true", help="skip live probes, emit checklist only")
    ap.add_argument("--json", action="store_true", dest="as_json", help="JSON output")
    args = ap.parse_args()

    baseline = find_latest_baseline(args.baseline)
    tools = parse_baseline(baseline)
    if not tools:
        sys.exit(f"ERROR: no tools parsed from {baseline.name}")

    results = []
    for t in tools:
        rec_clean = clean_version(t["recorded"])
        entry = dict(rank=t["rank"], tool=t["tool"], recorded=t["recorded"],
                     recorded_token=rec_clean,
                     status="rolling/unspecified" if is_rolling(t["recorded"]) else "versioned")
        if args.offline:
            entry["probe"] = ""
            entry["verdict"] = ("manual-verify (rolling)" if entry["status"] != "versioned"
                                else "manual-verify (offline mode)")
        else:
            probed = probe_apt(t["tool"]) or probe_binary(t["tool"])
            entry["probe"] = probed
            if not probed:
                entry["verdict"] = "not-installed/unreachable"
            elif not rec_clean:
                entry["verdict"] = f"probed:{probed} (baseline rolling — reconcile manually)"
            elif probed.startswith(rec_clean) or rec_clean.startswith(probed.split("+")[0]):
                entry["verdict"] = "match"
            else:
                entry["verdict"] = f"DRIFT baseline={rec_clean} probed={probed}"
        results.append(entry)

    if args.as_json:
        print(json.dumps(dict(baseline=baseline.name, checked=len(results),
                              drift=[r for r in results if r["verdict"].startswith("DRIFT")],
                              results=results), indent=2))
        return

    drift = [r for r in results if r["verdict"].startswith("DRIFT")]
    print("=" * 60)
    print(f"tool-version drift check vs {baseline.name} ({'offline' if args.offline else 'online'} mode)")
    print("=" * 60)
    for r in results:
        mark = "⬆" if r["verdict"].startswith("DRIFT") else ("=" if r["verdict"] == "match" else "?")
        print(f"  [{mark}] #{r['rank']:>2} {r['tool']:<14} baseline={r['recorded_token'] or 'rolling':<12} "
              f"probe={r['probe'] or '-':<12} {r['verdict']}")
    print("-" * 60)
    print(f"checked={len(results)}  drift={len(drift)}  "
          f"(drift items: follow the baseline MAJOR action SOP in the baseline file)")


if __name__ == "__main__":
    main()
