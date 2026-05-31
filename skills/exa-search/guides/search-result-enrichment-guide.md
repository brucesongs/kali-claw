# Search Result Enrichment Guide

> Methods for enriching raw search results with CVE cross-references, IOC extraction, and knowledge graph construction to transform search data into actionable intelligence.

## 1. CVE Cross-Referencing

Automatically enrich search results by extracting and validating CVE identifiers against the NVD:

```python
import re
import json
import requests
from exa_py import Exa

exa = Exa(api_key="EXA_API_KEY")

def extract_cves(text):
    return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))

def enrich_with_nvd(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        return None
    data = resp.json()
    if not data.get("vulnerabilities"):
        return None
    vuln = data["vulnerabilities"][0]["cve"]
    metrics = vuln.get("metrics", {})
    cvss_data = None
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if version in metrics:
            cvss_data = metrics[version][0]["cvssData"]
            break
    return {
        "id": cve_id,
        "description": vuln["descriptions"][0]["value"],
        "cvss_score": cvss_data.get("baseScore") if cvss_data else None,
        "severity": cvss_data.get("baseSeverity") if cvss_data else None,
    }

def enriched_search(query):
    results = exa.search_and_contents(query, type="neural", num_results=10, text=True)
    enriched = []
    for r in results.results:
        cves = extract_cves(r.text or "")
        cve_details = [enrich_with_nvd(cve) for cve in cves[:5]]
        enriched.append({
            "title": r.title,
            "url": r.url,
            "cves_found": len(cves),
            "cve_details": [d for d in cve_details if d],
        })
    return enriched

findings = enriched_search("critical vulnerability Apache 2025")
for f in findings:
    print(f"\n[*] {f['title']}")
    for cve in f["cve_details"]:
        print(f"    {cve['id']} — CVSS {cve['cvss_score']} ({cve['severity']})")
```

## 2. IOC Extraction from Search Results

Parse Indicators of Compromise (IPs, domains, hashes, URLs) from result text:

```python
import re
from dataclasses import dataclass, field

@dataclass
class IOCReport:
    source_url: str = ""
    ipv4: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    md5: list = field(default_factory=list)
    sha256: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    emails: list = field(default_factory=list)

IOC_PATTERNS = {
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domains": r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|ru|cn|tk)\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "urls": r"https?://[^\s\"'<>]+",
    "emails": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
}

EXCLUDE_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8"}

def extract_iocs(text, source_url=""):
    report = IOCReport(source_url=source_url)
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = list(set(re.findall(pattern, text, re.IGNORECASE)))
        if ioc_type == "ipv4":
            matches = [ip for ip in matches if ip not in EXCLUDE_IPS]
        setattr(report, ioc_type, matches)
    return report

def search_and_extract_iocs(query):
    from exa_py import Exa
    exa = Exa(api_key="EXA_API_KEY")
    results = exa.search_and_contents(query, type="neural", num_results=10, text=True)

    all_iocs = []
    for r in results.results:
        iocs = extract_iocs(r.text or "", r.url)
        if any([iocs.ipv4, iocs.domains, iocs.md5, iocs.sha256]):
            all_iocs.append(iocs)
            print(f"\n[*] {r.title}")
            if iocs.ipv4: print(f"    IPs: {iocs.ipv4[:5]}")
            if iocs.md5: print(f"    MD5: {iocs.md5[:3]}")
            if iocs.sha256: print(f"    SHA256: {iocs.sha256[:3]}")
            if iocs.domains: print(f"    Domains: {iocs.domains[:5]}")
    return all_iocs

search_and_extract_iocs("APT29 malware campaign indicators 2025")
```

## 3. Threat Intelligence Correlation

Cross-reference extracted IOCs against threat intelligence feeds:

```python
import requests

def check_virustotal(ioc, api_key, ioc_type="ip"):
    endpoints = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
    }
    resp = requests.get(
        endpoints[ioc_type],
        headers={"x-apikey": api_key},
        timeout=10,
    )
    if resp.status_code != 200:
        return None
    data = resp.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    return {
        "ioc": ioc,
        "type": ioc_type,
        "malicious": stats.get("malicious", 0),
        "total_engines": sum(stats.values()),
        "reputation": data.get("reputation", "unknown"),
    }

def correlate_iocs(ioc_report, vt_api_key):
    results = []
    for ip in ioc_report.ipv4[:10]:
        vt = check_virustotal(ip, vt_api_key, "ip")
        if vt and vt["malicious"] > 0:
            results.append(vt)
            print(f"  [!] {ip} — {vt['malicious']}/{vt['total_engines']} detections")
    for h in ioc_report.sha256[:5]:
        vt = check_virustotal(h, vt_api_key, "hash")
        if vt and vt["malicious"] > 0:
            results.append(vt)
            print(f"  [!] {h[:16]}... — {vt['malicious']}/{vt['total_engines']} detections")
    return results
```

## 4. Building Knowledge Graphs from Results

Structure search results into a connected knowledge graph for pattern analysis:

```python
import json
from collections import defaultdict

class SecurityKnowledgeGraph:
    def __init__(self):
        self.nodes = {}
        self.edges = []

    def add_node(self, node_id, node_type, properties=None):
        self.nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "properties": properties or {},
        }

    def add_edge(self, source, target, relationship):
        self.edges.append({
            "source": source,
            "target": target,
            "relationship": relationship,
        })

    def build_from_search(self, search_results, ioc_reports):
        for result in search_results:
            self.add_node(result["url"], "source", {"title": result["title"]})
            for cve in result.get("cve_details", []):
                self.add_node(cve["id"], "vulnerability", {
                    "cvss": cve.get("cvss_score"),
                    "severity": cve.get("severity"),
                })
                self.add_edge(result["url"], cve["id"], "references")

        for report in ioc_reports:
            for ip in report.ipv4:
                self.add_node(ip, "indicator_ip")
                self.add_edge(report.source_url, ip, "contains_ioc")
            for h in report.sha256:
                self.add_node(h[:16], "indicator_hash")
                self.add_edge(report.source_url, h[:16], "contains_ioc")

    def find_connections(self, node_id):
        connected = []
        for edge in self.edges:
            if edge["source"] == node_id:
                connected.append((edge["relationship"], edge["target"]))
            elif edge["target"] == node_id:
                connected.append((edge["relationship"], edge["source"]))
        return connected

    def export_json(self, path):
        with open(path, "w") as f:
            json.dump({"nodes": list(self.nodes.values()), "edges": self.edges}, f, indent=2)

# Usage
graph = SecurityKnowledgeGraph()
graph.build_from_search(enriched_results, ioc_reports)
graph.export_json("./intel/knowledge_graph.json")
print(f"[*] Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
```

## 5. MITRE ATT&CK Mapping

Map search findings to MITRE ATT&CK techniques for structured threat modeling:

```python
import re

ATTACK_KEYWORDS = {
    "T1566": ["phishing", "spearphishing", "malicious attachment"],
    "T1059": ["command line", "powershell", "bash script", "cmd.exe"],
    "T1078": ["valid accounts", "credential reuse", "stolen credentials"],
    "T1190": ["exploit public-facing", "rce", "remote code execution"],
    "T1071": ["command and control", "c2", "beacon", "callback"],
    "T1486": ["ransomware", "data encrypted", "encryption for impact"],
    "T1053": ["scheduled task", "cron job", "at command"],
    "T1055": ["process injection", "dll injection", "hollowing"],
}

def map_to_attack(text):
    text_lower = text.lower()
    mapped = []
    for technique_id, keywords in ATTACK_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                mapped.append({"technique": technique_id, "matched_keyword": kw})
                break
    return mapped

def enrich_with_attack(search_results):
    for result in search_results:
        text = result.get("text", "") or result.get("title", "")
        techniques = map_to_attack(text)
        if techniques:
            print(f"\n[*] {result.get('title', result.get('url'))}")
            for t in techniques:
                print(f"    ATT&CK {t['technique']} (matched: '{t['matched_keyword']}')")
    return search_results
```

## 6. Automated Enrichment Pipeline

Combine all enrichment steps into a single pipeline:

```bash
# Quick IOC extraction from a URL using command line
curl -s "https://example.com/threat-report" | \
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > iocs_ips.txt

# Cross-reference IPs against AbuseIPDB
while read ip; do
  curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip" \
    -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" | \
    jq "{ip: .data.ipAddress, score: .data.abuseConfidenceScore, country: .data.countryCode}"
done < iocs_ips.txt
```
