#!/usr/bin/env python3
"""scan-new-cves.py — NVD 2.0 CVE intelligence scanner for Kali tool coverage.

Scans the latest KALI_TOOLS_BASELINE Top-N tools against the NVD API 2.0
keyword search endpoint over a date window, then re-fetches every hit by
cveId (per-CVE verification discipline: only NVD-verified IDs enter the
report; nothing is edited in-place — hits become findings for triage).

Usage:
  python3 validation/scan-new-cves.py --since 11-10                  # all Top-N tools
  python3 validation/scan-new-cves.py --since 11-10 --tools nmap,burp
  python3 validation/scan-new-cves.py --since 11-15 --keywords "nmap,Burp Suite,trivy" --tag selftest
  python3 validation/scan-new-cves.py --since 11-10 --min-cvss 7.0   # HIGH+ only
  python3 validation/scan-new-cves.py --since 11-10 --dry-run        # plan only, no network

Outputs (always written, findings or not):
  validation/evidence/cve-scan/<YYYY-MM-DD>-<tag>.json   machine-readable
  validation/evidence/cve-scan/<YYYY-MM-DD>-<tag>.md     triage report

Exit codes: 0 = clean scan, 1 = findings recorded, 2 = operational error.

NVD API key: optional. Without a key NVD allows 5 req/30s (this tool sleeps
6s per request); with a key 50 req/30s (~0.7s). Pass --api-key or set
NVD_API_KEY. Free key: https://nvd.nist.gov/developers/request-an-api-key
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EVIDENCE_DIR = REPO / "validation" / "evidence" / "cve-scan"

# Tool name (lowercased, parenthetical stripped) -> better NVD keyword.
# Tools absent from this map use their bare name as the keyword.
TOOL_KEYWORDS = {
    "strings": "binutils",
    "burp": "Burp Suite",
    "radare2": "radare2",
    "shodan": "Shodan",
    "hackrf": "HackRF",
    "impacket": "Impacket",
    "bettercap": "bettercap",
    "tor": "Tor",
    "kubectl": "Kubernetes kubectl",
    "terraform": "Terraform",
}

SEVERITY = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW")]


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--since", required=True,
                    help="window start: YYYY-MM-DD or MM-DD (current year)")
    ap.add_argument("--until", default=None,
                    help="window end (default: now)")
    ap.add_argument("--tools", default=None,
                    help="comma-separated tool subset, e.g. nmap,burp (default: all Top-N)")
    ap.add_argument("--keywords", default=None,
                    help="override tool list with explicit comma-separated keywords (self-test)")
    ap.add_argument("--limit", type=int, default=50,
                    help="max CVEs kept per keyword after sort (default 50)")
    ap.add_argument("--min-cvss", type=float, default=0.0,
                    help="drop CVEs below this CVSS base score (default 0 = keep all)")
    ap.add_argument("--tag", default="scan",
                    help="evidence file tag (default: scan)")
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"),
                    help="NVD API key (or env NVD_API_KEY)")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip per-CVE re-fetch (NOT recommended; breaks verification discipline)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the scan plan without any network calls")
    return ap.parse_args()


def parse_since(raw: str) -> datetime:
    """Accept YYYY-MM-DD or MM-DD (current year)."""
    try:
        return datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    m = re.fullmatch(r"(\d{1,2})-(\d{1,2})", raw)
    if m:
        try:
            return datetime(datetime.now(timezone.utc).year, int(m.group(1)),
                            int(m.group(2)), tzinfo=timezone.utc)
        except ValueError:
            pass
    sys.exit("ERROR: --since must be YYYY-MM-DD or MM-DD (e.g. 2026-11-10 or 11-10)")


def find_latest_baseline() -> Path:
    candidates = sorted(REPO.glob("KALI_TOOLS_BASELINE_*.md"),
                        key=lambda p: p.stem.split("_")[-1])
    if not candidates:
        sys.exit("ERROR: no KALI_TOOLS_BASELINE_*.md found in repo root")
    return candidates[-1]


def parse_top_tools(path: Path) -> list:
    """Extract [(rank, tool)] from the Top-N table; placeholder rows are skipped."""
    tools, in_top = [], False
    for line in path.read_text(errors="ignore").splitlines():
        if line.startswith("## ") and "Top" in line:
            in_top = True
            continue
        if in_top and line.startswith("## "):
            break
        m = re.match(r"^\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|", line)
        if m and "工具" not in m.group(2) and "---" not in line:
            name = m.group(2).strip()
            if name and not name.startswith("("):
                tools.append((int(m.group(1)), name))
    return tools


def tool_keyword(tool: str) -> str:
    bare = tool.split("(")[0].strip().lower()
    return TOOL_KEYWORDS.get(bare, tool.split("(")[0].strip())


def build_plan(args) -> list:
    """Return [(keyword, source)] — keyword order = baseline rank order."""
    if args.keywords:
        return [(k.strip(), "explicit") for k in args.keywords.split(",") if k.strip()]
    baseline = find_latest_baseline()
    tools = parse_top_tools(baseline)
    if not tools:
        sys.exit(f"ERROR: no tools parsed from {baseline}")
    if args.tools:
        wanted = {t.strip().lower() for t in args.tools.split(",")}
        tools = [t for t in tools if t[1].split("(")[0].strip().lower() in wanted]
        if not tools:
            sys.exit(f"ERROR: none of --tools {args.tools!r} found in Top-N table")
    return [(tool_keyword(name), f"#{rank} {name}") for rank, name in tools]


class NvdClient:
    def __init__(self, api_key=None, dry=False):
        self.api_key = api_key
        self.dry = dry
        self.delay = 0.7 if api_key else 6.0  # NVD: 50 req/30s w/ key, 5 req/30s w/o
        self._last = 0.0

    def get(self, params: dict) -> dict:
        url = NVD_BASE + "?" + urllib.parse.urlencode(params)
        for attempt in range(4):
            wait = self.delay - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            req = urllib.request.Request(url, headers={
                "User-Agent": "kali-claw-scan-new-cves/1.0",
                **({"apiKey": self.api_key} if self.api_key else {}),
            })
            self._last = time.monotonic()
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                if e.code in (403, 429, 500, 503) and attempt < 3:
                    backoff = 10 * (2 ** attempt)
                    print(f"  NVD {e.code}, retry in {backoff}s ({url[:100]}...)", file=sys.stderr)
                    time.sleep(backoff)
                    continue
                raise
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt < 3:
                    backoff = 10 * (2 ** attempt)
                    print(f"  network error ({e}), retry in {backoff}s", file=sys.stderr)
                    time.sleep(backoff)
                    continue
                raise
        raise RuntimeError("unreachable")


def sev_label(score: float) -> str:
    for threshold, label in SEVERITY:
        if score >= threshold:
            return label
    return "UNRATED"


def extract_cve(entry: dict, keyword: str, source: str) -> dict:
    cve = entry.get("cve", {})
    metrics = (cve.get("metrics", {}).get("cvssMetricV31")
               or cve.get("metrics", {}).get("cvssMetricV30")
               or cve.get("metrics", {}).get("cvssMetricV2") or [{}])
    cvss = metrics[0].get("cvssData", {})
    score = cvss.get("baseScore", 0.0) or 0.0
    descs = [d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"]
    cwes = [w.get("description", [{}])[0].get("value")
            for w in cve.get("weaknesses", []) if w.get("description")]
    return {
        "id": cve.get("id"),
        "verified": False,  # set True only after per-CVE re-fetch
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "cvss": score,
        "cvss_vector": cvss.get("vectorString", ""),
        "severity": sev_label(score),
        "cwe": next((c for c in cwes if c), ""),
        "kev": bool(cve.get("cisaExploitAdd")),
        "description": (descs[0][:400] if descs else ""),
        "references": [r.get("url") for r in cve.get("references", [])][:5],
        "matched": [{"keyword": keyword, "source": source}],
    }


def merge_hit(pool: dict, hit: dict):
    if hit["id"] in pool:
        pool[hit["id"]]["matched"].extend(hit["matched"])
    else:
        pool[hit["id"]] = hit


def verify(c: dict, client: NvdClient):
    """Re-fetch by cveId — the per-CVE NVD verification gate."""
    data = client.get({"cveId": c["id"]})
    entries = data.get("vulnerabilities", [])
    if not entries:
        c["verified"] = False
        c["verify_note"] = "not returned by cveId lookup — DO NOT absorb"
        return
    fresh = extract_cve(entries[0], "", "")
    for k in ("published", "lastModified", "cvss", "cvss_vector", "severity",
              "cwe", "kev", "description", "references"):
        c[k] = fresh[k]
    c["verified"] = True


def main():
    args = parse_args()
    start = parse_since(args.since)
    end = (datetime.fromisoformat(args.until) if args.until
           else datetime.now(timezone.utc))
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    if not start < end:
        sys.exit("ERROR: --since must be before --until")
    if end - start > timedelta(days=120):
        sys.exit("ERROR: NVD API window max is 120 days")

    plan = build_plan(args)
    print(f"plan: {len(plan)} keywords, window {start.date()} → {end.date()}, "
          f"min_cvss={args.min_cvss}, verify={'off' if args.no_verify else 'on'}")
    for kw, src in plan:
        print(f"  - {kw:28s} ({src})")
    if args.dry_run:
        print("dry-run: no network calls, no evidence written")
        return

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    client = NvdClient(args.api_key)
    params_common = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
    }

    pool = {}
    for kw, src in plan:
        data = client.get({**params_common, "keywordSearch": kw})
        hits = [extract_cve(e, kw, src) for e in data.get("vulnerabilities", [])]
        hits.sort(key=lambda h: h["cvss"], reverse=True)
        kept = 0
        for h in hits:
            if h["cvss"] < args.min_cvss:
                continue
            merge_hit(pool, h)
            kept += 1
            if kept >= args.limit:
                break
        print(f"  {kw:28s} raw={len(hits):3d} kept={kept:3d} (totalResults={data.get('totalResults', '?')})")

    findings = sorted(pool.values(), key=lambda c: (not c["kev"], -c["cvss"], c["id"]))
    if not args.no_verify:
        print(f"verifying {len(findings)} CVEs by cveId (NVD gate)...")
        for c in findings:
            verify(c, client)
    else:
        print("WARNING: --no-verify — IDs below are NOT NVD-gated; do not absorb into skills", file=sys.stderr)

    stamp = datetime.now(timezone.utc)
    run = {
        "generated_at": stamp.isoformat(),
        "window": {"since": start.date().isoformat(), "until": end.date().isoformat()},
        "keywords": [{"keyword": kw, "source": src} for kw, src in plan],
        "min_cvss": args.min_cvss,
        "verified": not args.no_verify,
        "counts": {
            "keywords": len(plan),
            "hits": len(findings),
            "kev": sum(c["kev"] for c in findings),
            "critical_or_high": sum(c["cvss"] >= 7.0 for c in findings),
        },
        "findings": findings,
    }
    base = EVIDENCE_DIR / f"{stamp.date().isoformat()}-{args.tag}"
    base.with_suffix(".json").write_text(json.dumps(run, indent=2, ensure_ascii=False) + "\n")

    md = [f"# CVE Scan — {stamp.date().isoformat()} ({args.tag})", "",
          f"- Window: {start.date()} → {end.date()}",
          f"- Keywords: {len(plan)} | hits: {len(findings)} | KEV: {run['counts']['kev']} | CVSS≥7: {run['counts']['critical_or_high']}",
          f"- Verification: {'per-CVE NVD cveId fetch' if run['verified'] else 'SKIPPED (--no-verify) — do not absorb'}", "",
          "## Findings", ""]
    if not findings:
        md.append("_No hits in window._")
    for c in findings:
        flag = " **[KEV]**" if c["kev"] else ""
        vflag = "" if c["verified"] else " ⚠️UNVERIFIED"
        md.append(f"### {c['id']} — {c['severity']} {c['cvss']}{flag}{vflag}")
        md.append(f"- Matched: {', '.join(m['source'] for m in c['matched'])}")
        if c["cwe"]:
            md.append(f"- CWE: {c['cwe']} | Vector: `{c['cvss_vector']}`")
        md.append(f"- Published: {c['published']}")
        md.append(f"- {c['description']}")
        if c["references"]:
            md.append(f"- Refs: {', '.join(c['references'][:3])}")
        md.append("")
    md.append("## Triage")
    md.append("- Absorb only `verified: true` IDs; when in doubt, do not number it.")
    md.append("- Record hits as findings first; skill edits happen in a dedicated pass.")
    base.with_suffix(".md").write_text("\n".join(md) + "\n")
    print(f"evidence: {base.with_suffix('.json').name} / {base.with_suffix('.md').name}")
    print(f"result: {len(findings)} findings ({run['counts']['kev']} KEV, {run['counts']['critical_or_high']} CVSS≥7)")
    return 1 if findings else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
