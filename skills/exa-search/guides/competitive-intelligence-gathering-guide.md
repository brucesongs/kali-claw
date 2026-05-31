# Competitive Intelligence Gathering Guide

> Using search APIs to monitor vendor security advisories, track threat actor publications, and discover emerging security tools for continuous intelligence operations.

## 1. Monitoring Vendor Security Advisories

Set up automated monitoring for security advisories from major vendors:

```python
from exa_py import Exa
from datetime import datetime, timedelta

exa = Exa(api_key="EXA_API_KEY")

VENDOR_DOMAINS = {
    "microsoft": ["msrc.microsoft.com", "techcommunity.microsoft.com"],
    "google": ["cloud.google.com/support/bulletins", "chromereleases.googleblog.com"],
    "apple": ["support.apple.com"],
    "cisco": ["sec.cloudapps.cisco.com"],
    "paloalto": ["security.paloaltonetworks.com"],
    "fortinet": ["fortiguard.fortinet.com"],
}

def check_vendor_advisories(vendor, days_back=7):
    start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
    domains = VENDOR_DOMAINS.get(vendor, [])

    results = exa.search_and_contents(
        f"{vendor} security advisory vulnerability patch",
        type="neural",
        num_results=10,
        start_published_date=start_date,
        include_domains=domains if domains else None,
        highlights=True,
    )

    advisories = []
    for r in results.results:
        advisories.append({
            "title": r.title,
            "url": r.url,
            "date": r.published_date,
            "highlights": r.highlights[:2] if r.highlights else [],
        })
    return advisories

def daily_advisory_sweep():
    print(f"[*] Advisory sweep: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    for vendor in VENDOR_DOMAINS:
        advisories = check_vendor_advisories(vendor, days_back=1)
        if advisories:
            print(f"\n  [{vendor.upper()}] {len(advisories)} new advisory(ies)")
            for a in advisories:
                print(f"    - {a['title']}")
                print(f"      {a['url']}")

daily_advisory_sweep()
```

## 2. Tracking Threat Actor Publications

Monitor known threat actor blogs, paste sites, and dark web mirrors for new disclosures:

```python
from exa_py import Exa
from datetime import datetime, timedelta

exa = Exa(api_key="EXA_API_KEY")

THREAT_QUERIES = [
    "ransomware group claims new victim data leak",
    "APT campaign targeting critical infrastructure 2025",
    "zero-day exploit sold underground forum",
    "new malware family analysis technical report",
    "data breach disclosure stolen database",
]

INTEL_SOURCES = [
    "therecord.media",
    "bleepingcomputer.com",
    "securelist.com",
    "unit42.paloaltonetworks.com",
    "blog.talosintelligence.com",
    "research.checkpoint.com",
    "thedfirreport.com",
]

def track_threat_actors(days_back=3):
    start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
    all_findings = []

    for query in THREAT_QUERIES:
        results = exa.search_and_contents(
            query,
            type="neural",
            num_results=5,
            start_published_date=start_date,
            include_domains=INTEL_SOURCES,
            highlights=True,
        )
        for r in results.results:
            all_findings.append({
                "query": query,
                "title": r.title,
                "url": r.url,
                "date": r.published_date,
                "preview": r.highlights[0][:200] if r.highlights else "",
            })

    # Deduplicate by URL
    seen = set()
    unique = []
    for f in all_findings:
        if f["url"] not in seen:
            seen.add(f["url"])
            unique.append(f)

    print(f"[*] Found {len(unique)} unique threat intel items")
    for f in unique:
        print(f"\n  [{f['date']}] {f['title']}")
        print(f"  {f['url']}")
        if f["preview"]:
            print(f"  > {f['preview'][:150]}...")

    return unique

track_threat_actors(days_back=7)
```

## 3. Discovering New Security Tools

Find recently released or updated security tools relevant to your testing needs:

```python
from exa_py import Exa
from datetime import datetime, timedelta

exa = Exa(api_key="EXA_API_KEY")

TOOL_CATEGORIES = {
    "web_security": "new open source web application security testing tool released",
    "cloud_security": "new cloud security scanner tool AWS Azure GCP open source",
    "network": "network penetration testing tool released 2025 open source",
    "binary_analysis": "reverse engineering binary analysis tool new release",
    "container": "container security scanning tool kubernetes docker new",
    "ai_security": "AI LLM security testing red team tool released",
}

def discover_tools(category, days_back=30):
    start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
    query = TOOL_CATEGORIES[category]

    results = exa.search_and_contents(
        query,
        type="neural",
        num_results=10,
        start_published_date=start_date,
        include_domains=["github.com", "blog.trailofbits.com", "portswigger.net"],
        text=True,
    )

    tools = []
    for r in results.results:
        tools.append({
            "title": r.title,
            "url": r.url,
            "date": r.published_date,
            "description": (r.text or "")[:300],
        })
    return tools

def full_tool_scan():
    print("[*] Scanning for new security tools...")
    for category, _ in TOOL_CATEGORIES.items():
        tools = discover_tools(category, days_back=14)
        if tools:
            print(f"\n  [{category.upper()}]")
            for t in tools[:3]:
                print(f"    - {t['title']}")
                print(f"      {t['url']}")

full_tool_scan()
```

## 4. Patch Gap Analysis

Identify vulnerabilities where patches exist but adoption may be low:

```python
from exa_py import Exa
from datetime import datetime, timedelta
import re

exa = Exa(api_key="EXA_API_KEY")

def find_patch_gaps(days_range=(7, 30)):
    """Find vulns patched 7-30 days ago — likely still unpatched in many orgs."""
    start = (datetime.now() - timedelta(days=days_range[1])).strftime("%Y-%m-%d")
    end = (datetime.now() - timedelta(days=days_range[0])).strftime("%Y-%m-%d")

    results = exa.search_and_contents(
        "critical vulnerability patch released actively exploited",
        type="neural",
        num_results=15,
        start_published_date=start,
        end_published_date=end,
        text=True,
        highlights=True,
    )

    gaps = []
    for r in results.results:
        text = r.text or ""
        cves = list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
        if cves:
            gaps.append({
                "title": r.title,
                "url": r.url,
                "date": r.published_date,
                "cves": cves,
                "actively_exploited": "exploit" in text.lower() or "in the wild" in text.lower(),
            })

    print(f"[*] Patch gap candidates ({days_range[0]}-{days_range[1]} days old):")
    for g in gaps:
        flag = " [EXPLOITED]" if g["actively_exploited"] else ""
        print(f"\n  {g['title']}{flag}")
        print(f"  CVEs: {', '.join(g['cves'][:5])}")
        print(f"  {g['url']}")

    return gaps

find_patch_gaps()
```

## 5. Competitor Tool Benchmarking

Compare security tools and solutions by gathering community feedback and benchmarks:

```python
from exa_py import Exa

exa = Exa(api_key="EXA_API_KEY")

def compare_tools(tool_a, tool_b, category):
    queries = [
        f"{tool_a} vs {tool_b} comparison {category}",
        f"{tool_a} review benchmark performance {category}",
        f"{tool_b} review benchmark performance {category}",
    ]

    all_results = []
    for query in queries:
        results = exa.search_and_contents(
            query,
            type="neural",
            num_results=5,
            highlights=True,
        )
        for r in results.results:
            all_results.append({
                "query": query,
                "title": r.title,
                "url": r.url,
                "highlights": r.highlights[:3] if r.highlights else [],
            })

    print(f"[*] Comparison: {tool_a} vs {tool_b} ({category})")
    seen = set()
    for r in all_results:
        if r["url"] not in seen:
            seen.add(r["url"])
            print(f"\n  {r['title']}")
            print(f"  {r['url']}")
            for h in r["highlights"]:
                print(f"  > {h[:150]}")

    return all_results

compare_tools("Burp Suite", "Caido", "web application security testing")
```

## 6. Automated Intelligence Digest

Generate a periodic intelligence digest combining all sources:

```bash
# Cron job to run daily intelligence gathering
# Add to crontab: 0 8 * * * /path/to/intel_digest.sh

#!/bin/bash
export EXA_API_KEY="your-key-here"
DIGEST_DIR="./intel/digests"
TODAY=$(date +%Y-%m-%d)

mkdir -p "$DIGEST_DIR"
python3 intel_gather.py > "$DIGEST_DIR/${TODAY}_digest.json" 2>&1
echo "[*] Digest generated: $DIGEST_DIR/${TODAY}_digest.json"
```

```python
import json
from datetime import datetime
from pathlib import Path

def generate_digest(output_dir="./intel/digests"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d")

    digest = {
        "date": today,
        "generated_at": datetime.now().isoformat(),
        "sections": {},
    }

    # Collect from all intelligence functions
    digest["sections"]["advisories"] = {
        vendor: check_vendor_advisories(vendor, days_back=1)
        for vendor in ["microsoft", "google", "cisco"]
    }
    digest["sections"]["threats"] = track_threat_actors(days_back=1)
    digest["sections"]["new_tools"] = discover_tools("web_security", days_back=7)
    digest["sections"]["patch_gaps"] = find_patch_gaps(days_range=(7, 21))

    output_path = f"{output_dir}/{today}_digest.json"
    with open(output_path, "w") as f:
        json.dump(digest, f, indent=2)

    total_items = sum(
        len(v) if isinstance(v, list) else sum(len(x) for x in v.values())
        for v in digest["sections"].values()
    )
    print(f"[*] Daily digest: {total_items} items -> {output_path}")
    return digest

generate_digest()
```
