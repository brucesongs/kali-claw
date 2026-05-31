# Data Scraper Agent Payloads

## CVE Scraping

### NVD API
```bash
# Search CVEs by keyword
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=apache" | \
  jq '.vulnerabilities[] | {cve: .cve.id, description: .cve.descriptions[0].value}'

# Get specific CVE
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-12345" | \
  jq '.vulnerabilities[0].cve'

# Paginated search (100 per page)
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=nginx&resultsPerPage=100&startIndex=0"

# Filter by date range
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2024-01-01T00:00:00.000&pubEndDate=2024-12-31T23:59:59.999"

# Filter by CVSS severity
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL"
```

### Exploit-DB Scraping
```bash
# Search for exploits
searchsploit apache 2.4

# Export to JSON
searchsploit apache 2.4 --json

# Mirror exploit files locally
searchsploit -m 51234

# Search by CVE
searchsploit --cve 2024-12345

# Update database
searchsploit --update
```

### MITRE CVE List
```bash
# Download full CVE list
curl "https://cveawg.mitre.org/api/cve" -o cve_list.json

# Search recent CVEs by CNA
curl "https://cveawg.mitre.org/api/cve?cnaId=cisco&timeModified.gt=2024-01-01"
```

## GitHub Advisory Scraping

```bash
# Using GitHub API
curl "https://api.github.com/advisories?ecosystem=npm" \
  -H "Accept: application/vnd.github+json" | \
  jq '.[] | {id: .ghsa_id, summary: .summary, severity: .severity}'

# Filter by severity
curl "https://api.github.com/advisories?ecosystem=pip&severity=critical" \
  -H "Accept: application/vnd.github+json"

# Get advisory details
curl "https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx" \
  -H "Accept: application/vnd.github+json"
```

### GitHub Code Search for Secrets
```bash
# Search for exposed API keys
gh search code "AKIA" --language=python --json path,repository

# Search for hardcoded passwords
gh search code "password =" --filename=.env --json path,repository

# Search for private keys
gh search code "BEGIN RSA PRIVATE KEY" --json path,repository
```

## HTML Scraping (BeautifulSoup)

```python
import requests
from bs4 import BeautifulSoup

response = requests.get("https://example.com/advisories")
soup = BeautifulSoup(response.content, 'html.parser')

for advisory in soup.select('.advisory'):
    title = advisory.select_one('.title').text
    cve = advisory.select_one('.cve').text
    print(f"{cve}: {title}")
```

### Table Extraction
```python
import pandas as pd

tables = pd.read_html("https://example.com/vulnerabilities")
vuln_table = tables[0]
vuln_table.to_csv("vulnerabilities.csv", index=False)
```

### JavaScript-Rendered Content
```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto("https://example.com/dynamic-content")
    page.wait_for_selector(".vuln-list")
    content = page.content()
    browser.close()

soup = BeautifulSoup(content, 'html.parser')
```

## RSS/Atom Feed Parsing

```python
import feedparser

# Security advisories feed
feed = feedparser.parse("https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml")
for entry in feed.entries[:10]:
    print(f"{entry.title}: {entry.link}")

# Exploit-DB RSS
feed = feedparser.parse("https://www.exploit-db.com/rss.xml")
```

## Rate Limiting & Session Management

```python
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503])
session.mount("https://", HTTPAdapter(max_retries=retries))

def rate_limited_fetch(url, delay=1.0):
    time.sleep(delay)
    response = session.get(url, timeout=30)
    response.raise_for_status()
    return response.json()
```

### Proxy Rotation
```python
proxies = [
    "http://proxy1:8080",
    "http://proxy2:8080",
    "http://proxy3:8080",
]

import random
proxy = {"http": random.choice(proxies), "https": random.choice(proxies)}
response = requests.get(url, proxies=proxy)
```

## Data Extraction Patterns

### JSON Path Extraction
```bash
# Extract nested fields with jq
cat response.json | jq '.data.items[] | {id: .id, name: .name, severity: .metrics.cvssV3.baseSeverity}'

# Filter by condition
cat response.json | jq '.vulnerabilities[] | select(.cve.metrics.cvssMetricV31[0].cvssData.baseScore > 9.0)'

# Flatten nested arrays
cat response.json | jq '[.results[] | .references[]] | unique'
```

### CSV Output
```python
import csv
import json

with open("cves.json") as f:
    data = json.load(f)

with open("cves.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["CVE_ID", "Description", "CVSS_Score", "Published"])
    for vuln in data["vulnerabilities"]:
        cve = vuln["cve"]
        writer.writerow([
            cve["id"],
            cve["descriptions"][0]["value"][:200],
            cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
            cve.get("published", "N/A")
        ])
```

### Regex-Based Extraction
```python
import re

# Extract CVE IDs from text
cve_pattern = r'CVE-\d{4}-\d{4,7}'
cves = re.findall(cve_pattern, text)

# Extract IP addresses
ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
ips = re.findall(ip_pattern, text)

# Extract URLs
url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
urls = re.findall(url_pattern, text)

# Extract email addresses
email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
emails = re.findall(email_pattern, text)
```

## Threat Intelligence Feeds

```bash
# AlienVault OTX
curl "https://otx.alienvault.com/api/v1/pulses/subscribed" \
  -H "X-OTX-API-KEY: $OTX_KEY" | jq '.results[] | {name, created}'

# VirusTotal file report
curl "https://www.virustotal.com/api/v3/files/$SHA256" \
  -H "x-apikey: $VT_KEY"

# Shodan host lookup
curl "https://api.shodan.io/shodan/host/8.8.8.8?key=$SHODAN_KEY"

# Censys host search
curl "https://search.censys.io/api/v2/hosts/search" \
  -H "Authorization: Basic $CENSYS_AUTH" \
  -d '{"q": "services.http.response.headers.server: Apache/2.4"}'
```

## Caching & Deduplication

```python
import hashlib
import json
from pathlib import Path

CACHE_DIR = Path("./cache")
CACHE_DIR.mkdir(exist_ok=True)

def cached_fetch(url, ttl_hours=24):
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_file = CACHE_DIR / f"{cache_key}.json"
    
    if cache_file.exists():
        age_hours = (time.time() - cache_file.stat().st_mtime) / 3600
        if age_hours < ttl_hours:
            return json.loads(cache_file.read_text())
    
    response = rate_limited_fetch(url)
    cache_file.write_text(json.dumps(response))
    return response
```

## API Endpoint Discovery and Enumeration

### Swagger/OpenAPI Extraction
```bash
# Common Swagger/OpenAPI endpoint paths
for path in /swagger.json /openapi.json /api-docs /swagger/v1/swagger.json \
  /v2/api-docs /v3/api-docs /.well-known/openapi.yaml /docs/openapi.json; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}")
  if [ "$status" = "200" ]; then
    echo "[FOUND] https://target.com${path}"
    curl -s "https://target.com${path}" | jq '.paths | keys[]' 2>/dev/null
  fi
done
```

### API Path Fuzzing with ffuf
```bash
# Fuzz API versioned endpoints
ffuf -u "https://target.com/api/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,301,403 -o api_results.json -of json

# Fuzz with HTTP methods
for method in GET POST PUT DELETE PATCH OPTIONS; do
  ffuf -u "https://target.com/api/v1/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -X "$method" -mc 200,201,204,403 -o "results_${method}.json" -of json
done

# Parameter fuzzing on discovered endpoints
ffuf -u "https://target.com/api/v1/users?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 -fs 0
```

### GraphQL Introspection
```python
import requests

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind } }
        type { name kind ofType { name } }
      }
    }
  }
}
"""

def extract_graphql_schema(url):
    endpoints = ["/graphql", "/graphiql", "/api/graphql", "/query"]
    for endpoint in endpoints:
        target = f"{url.rstrip('/')}{endpoint}"
        resp = requests.post(target, json={"query": INTROSPECTION_QUERY}, timeout=10)
        if resp.status_code == 200 and "__schema" in resp.text:
            schema = resp.json()["data"]["__schema"]
            types = [t for t in schema["types"] if not t["name"].startswith("__")]
            print(f"[+] Schema found at {target}: {len(types)} types")
            for t in types:
                if t["fields"]:
                    fields = [f["name"] for f in t["fields"]]
                    print(f"    {t['name']}: {', '.join(fields[:8])}")
            return schema
    return None
```

### REST API Enumeration with ID Bruteforce
```python
import requests
from concurrent.futures import ThreadPoolExecutor

def enumerate_api_resources(base_url, resource, id_range, headers=None):
    """Enumerate API resources by iterating IDs (IDOR testing)."""
    found = []

    def check_id(rid):
        url = f"{base_url}/{resource}/{rid}"
        resp = requests.get(url, headers=headers or {}, timeout=5)
        if resp.status_code == 200:
            return {"id": rid, "data": resp.json()}
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_id, range(*id_range))
        for result in results:
            if result:
                found.append(result)
                print(f"[+] Found {resource}/{result['id']}")

    return found

# Usage
resources = enumerate_api_resources(
    "https://target.com/api/v1", "users", (1, 500),
    headers={"Authorization": "Bearer <token>"}
)
```

## JavaScript Rendering and SPA Scraping

### Playwright Full Page Extraction
```python
from playwright.sync_api import sync_playwright
import json

def scrape_spa(url, wait_selector=None, scroll=False):
    """Scrape single-page applications with full JS rendering."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            viewport={"width": 1920, "height": 1080}
        )
        page = context.new_page()

        # Intercept API calls made by the SPA
        api_responses = []
        page.on("response", lambda resp: api_responses.append({
            "url": resp.url,
            "status": resp.status,
            "body": resp.json() if "application/json" in resp.headers.get("content-type", "") else None
        }) if "/api/" in resp.url else None)

        page.goto(url, wait_until="networkidle")

        if wait_selector:
            page.wait_for_selector(wait_selector, timeout=15000)

        if scroll:
            # Infinite scroll handling
            prev_height = 0
            while True:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(2000)
                curr_height = page.evaluate("document.body.scrollHeight")
                if curr_height == prev_height:
                    break
                prev_height = curr_height

        html = page.content()
        browser.close()
        return html, api_responses
```

### Intercepting XHR/Fetch Requests
```python
from playwright.sync_api import sync_playwright

def intercept_api_traffic(url, duration_ms=10000):
    """Capture all XHR/Fetch requests made by a page."""
    captured = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        def handle_route(route):
            request = route.request
            if request.resource_type in ("xhr", "fetch"):
                captured.append({
                    "method": request.method,
                    "url": request.url,
                    "headers": request.headers,
                    "post_data": request.post_data
                })
            route.continue_()

        page.route("**/*", handle_route)
        page.goto(url, wait_until="networkidle")
        page.wait_for_timeout(duration_ms)
        browser.close()

    return captured

# Extract hidden API endpoints from SPA
traffic = intercept_api_traffic("https://target.com/dashboard")
for req in traffic:
    print(f"[{req['method']}] {req['url']}")
```

### Puppeteer Stealth with Node.js
```bash
# Install puppeteer with stealth plugin
npm install puppeteer puppeteer-extra puppeteer-extra-plugin-stealth

# Run headless scraper
node -e "
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());

(async () => {
  const browser = await puppeteer.launch({headless: 'new'});
  const page = await browser.newPage();
  await page.goto('https://target.com', {waitUntil: 'networkidle2'});

  // Extract all links including dynamically generated ones
  const links = await page.evaluate(() =>
    Array.from(document.querySelectorAll('a[href]')).map(a => a.href)
  );
  console.log(JSON.stringify(links, null, 2));
  await browser.close();
})();
"
```

### Handling Shadow DOM and Web Components
```python
from playwright.sync_api import sync_playwright

def extract_shadow_dom(url, host_selector):
    """Pierce shadow DOM boundaries to extract content."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, wait_until="networkidle")

        # Access shadow root content
        data = page.evaluate(f"""() => {{
            const host = document.querySelector('{host_selector}');
            if (!host || !host.shadowRoot) return null;
            const items = host.shadowRoot.querySelectorAll('[data-item]');
            return Array.from(items).map(el => ({{
                text: el.textContent.trim(),
                attrs: Object.fromEntries(
                    Array.from(el.attributes).map(a => [a.name, a.value])
                )
            }}));
        }}""")

        browser.close()
        return data
```

## Session Management and Authentication Bypass

### Cookie-Based Session Handling
```python
import requests
from http.cookiejar import MozillaCookieJar

def authenticated_session(login_url, credentials, cookie_file="cookies.txt"):
    """Maintain persistent authenticated sessions across runs."""
    session = requests.Session()
    jar = MozillaCookieJar(cookie_file)

    try:
        jar.load(ignore_discard=True, ignore_expires=True)
        session.cookies = jar
        # Validate session is still active
        resp = session.get(f"{login_url.rsplit('/', 1)[0]}/profile", timeout=10)
        if resp.status_code == 200:
            return session
    except (FileNotFoundError, Exception):
        pass

    # Fresh login
    resp = session.post(login_url, json=credentials, timeout=10)
    resp.raise_for_status()
    jar.save(ignore_discard=True, ignore_expires=True)
    return session

session = authenticated_session(
    "https://target.com/api/login",
    {"username": "researcher", "password": "pass123"}
)
data = session.get("https://target.com/api/protected/data").json()
```

### JWT Token Rotation and Refresh
```python
import requests
import time
import jwt

class TokenManager:
    """Manage JWT tokens with automatic refresh before expiry."""

    def __init__(self, auth_url, credentials):
        self.auth_url = auth_url
        self.credentials = credentials
        self.access_token = None
        self.refresh_token = None
        self.expiry = 0

    def get_token(self):
        if time.time() > self.expiry - 60:
            self._refresh()
        return self.access_token

    def _refresh(self):
        if self.refresh_token:
            resp = requests.post(f"{self.auth_url}/refresh", json={
                "refresh_token": self.refresh_token
            }, timeout=10)
        else:
            resp = requests.post(f"{self.auth_url}/login", json=self.credentials, timeout=10)

        resp.raise_for_status()
        tokens = resp.json()
        self.access_token = tokens["access_token"]
        self.refresh_token = tokens.get("refresh_token", self.refresh_token)
        decoded = jwt.decode(self.access_token, options={"verify_signature": False})
        self.expiry = decoded.get("exp", time.time() + 3600)

    def authenticated_request(self, method, url, **kwargs):
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.get_token()}"
        return requests.request(method, url, headers=headers, **kwargs)
```

### OAuth2 Flow Automation
```python
import requests
from urllib.parse import urlencode, parse_qs, urlparse

def oauth2_client_credentials(token_url, client_id, client_secret, scope="read"):
    """Obtain access token via OAuth2 client credentials grant."""
    resp = requests.post(token_url, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope
    }, timeout=10)
    resp.raise_for_status()
    return resp.json()["access_token"]

def oauth2_authorization_code(auth_url, token_url, client_id, redirect_uri):
    """Generate authorization URL and exchange code for token."""
    params = urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "read write",
        "state": "random_state_value"
    })
    auth_link = f"{auth_url}?{params}"
    print(f"[*] Authorize at: {auth_link}")
    # After user authorizes, exchange code
    callback_url = input("[*] Paste callback URL: ")
    code = parse_qs(urlparse(callback_url).query)["code"][0]

    resp = requests.post(token_url, data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id
    }, timeout=10)
    return resp.json()
```

### Multi-Account Session Pool
```bash
# Rotate between multiple authenticated sessions using curl
declare -A SESSIONS=(
  ["session1"]="cookie_session1.txt"
  ["session2"]="cookie_session2.txt"
  ["session3"]="cookie_session3.txt"
)

# Login and store cookies for each account
for name in "${!SESSIONS[@]}"; do
  curl -s -c "${SESSIONS[$name]}" -X POST "https://target.com/login" \
    -d "user=${name}&pass=password123" -o /dev/null
done

# Rotate sessions for scraping
PAGES=(1 2 3 4 5 6 7 8 9 10)
idx=0
SESSION_KEYS=(${!SESSIONS[@]})

for page in "${PAGES[@]}"; do
  cookie_file="${SESSIONS[${SESSION_KEYS[$((idx % ${#SESSION_KEYS[@]}))]}]}"
  curl -s -b "$cookie_file" "https://target.com/api/data?page=${page}" >> results.json
  idx=$((idx + 1))
  sleep 2
done
```

## Data Exfiltration Patterns

### Structured Table Extraction with CSS Selectors
```python
from bs4 import BeautifulSoup
import requests
import json

def extract_structured_tables(url, table_selector="table"):
    """Extract all tables from a page into structured dictionaries."""
    resp = requests.get(url, timeout=15)
    soup = BeautifulSoup(resp.content, "html.parser")
    results = []

    for table in soup.select(table_selector):
        headers = [th.get_text(strip=True) for th in table.select("thead th, tr:first-child th")]
        rows = []
        for tr in table.select("tbody tr, tr")[1:]:
            cells = [td.get_text(strip=True) for td in tr.select("td")]
            if cells and len(cells) == len(headers):
                rows.append(dict(zip(headers, cells)))
        if rows:
            results.append({"headers": headers, "rows": rows})

    return results

# Extract vulnerability tables
tables = extract_structured_tables("https://target.com/security/advisories")
with open("advisories.json", "w") as f:
    json.dump(tables, f, indent=2)
```

### Recursive Link Crawler with Depth Control
```python
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque

def crawl_and_extract(start_url, max_depth=3, max_pages=100, extract_fn=None):
    """BFS crawler with configurable extraction function."""
    visited = set()
    queue = deque([(start_url, 0)])
    domain = urlparse(start_url).netloc
    extracted_data = []

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                continue
            soup = BeautifulSoup(resp.content, "html.parser")

            # Apply custom extraction
            if extract_fn:
                data = extract_fn(soup, url)
                if data:
                    extracted_data.append(data)

            # Discover new links
            for link in soup.select("a[href]"):
                next_url = urljoin(url, link["href"])
                if urlparse(next_url).netloc == domain:
                    queue.append((next_url, depth + 1))

        except requests.RequestException:
            continue

    return extracted_data

# Example: extract all email addresses from a site
def email_extractor(soup, url):
    import re
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', soup.get_text())
    return {"url": url, "emails": list(set(emails))} if emails else None

results = crawl_and_extract("https://target.com", max_depth=2, extract_fn=email_extractor)
```

### PDF and Document Content Extraction
```python
import requests
import fitz  # PyMuPDF
from io import BytesIO

def extract_pdf_content(url):
    """Download and extract text from PDF documents."""
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()

    doc = fitz.open(stream=BytesIO(resp.content), filetype="pdf")
    pages = []
    for page_num, page in enumerate(doc):
        text = page.get_text()
        links = [link["uri"] for link in page.get_links() if "uri" in link]
        pages.append({
            "page": page_num + 1,
            "text": text.strip(),
            "links": links
        })
    doc.close()
    return pages

# Extract security whitepapers
pdf_data = extract_pdf_content("https://target.com/docs/security-report-2024.pdf")
for page in pdf_data:
    if "vulnerability" in page["text"].lower():
        print(f"Page {page['page']}: {page['text'][:200]}")
```

### Multi-Format Data Normalization
```python
import json
import csv
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from typing import List

@dataclass(frozen=True)
class ScrapedRecord:
    source: str
    identifier: str
    title: str
    severity: str
    description: str
    references: tuple

def normalize_nvd_json(data):
    records = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln["cve"]
        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        records.append(ScrapedRecord(
            source="NVD",
            identifier=cve["id"],
            title=cve["descriptions"][0]["value"][:120],
            severity=cvss.get("baseSeverity", "UNKNOWN"),
            description=cve["descriptions"][0]["value"],
            references=tuple(r["url"] for r in cve.get("references", []))
        ))
    return records

def normalize_nessus_xml(xml_content):
    root = ET.fromstring(xml_content)
    records = []
    for item in root.iter("ReportItem"):
        records.append(ScrapedRecord(
            source="Nessus",
            identifier=item.get("pluginID", ""),
            title=item.get("pluginName", ""),
            severity=item.findtext("risk_factor", "UNKNOWN"),
            description=item.findtext("description", ""),
            references=tuple(ref.text for ref in item.findall("see_also") if ref.text)
        ))
    return records

def export_records(records: List[ScrapedRecord], output_path: str):
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["source", "identifier", "title", "severity", "description", "references"])
        writer.writeheader()
        for record in records:
            row = asdict(record)
            row["references"] = "; ".join(row["references"])
            writer.writerow(row)
```

## Distributed Scraping Architecture

### Async Scraper with aiohttp and Semaphore
```python
import asyncio
import aiohttp
from itertools import cycle

async def distributed_scrape(urls, proxies=None, max_concurrent=20, timeout=15):
    """High-performance async scraper with proxy rotation and concurrency control."""
    semaphore = asyncio.Semaphore(max_concurrent)
    proxy_pool = cycle(proxies) if proxies else cycle([None])
    results = []

    async def fetch(session, url):
        async with semaphore:
            proxy = next(proxy_pool)
            try:
                async with session.get(url, proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        return {"url": url, "status": resp.status, "body": body}
                    elif resp.status == 429:
                        await asyncio.sleep(5)
                        return await fetch(session, url)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                return {"url": url, "status": -1, "error": str(e)}
        return None

    connector = aiohttp.TCPConnector(limit=max_concurrent, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch(session, url) for url in urls]
        results = await asyncio.gather(*tasks)

    return [r for r in results if r]

# Usage
proxies = ["http://proxy1:8080", "http://proxy2:8080", "http://proxy3:8080"]
urls = [f"https://target.com/page/{i}" for i in range(1, 500)]
results = asyncio.run(distributed_scrape(urls, proxies=proxies, max_concurrent=15))
```

### Redis-Based Task Queue for Distributed Workers
```python
import redis
import json
import time
from hashlib import sha256

class ScraperQueue:
    """Distributed scraping queue with deduplication and retry logic."""

    def __init__(self, redis_url="redis://localhost:6379"):
        self.redis = redis.from_url(redis_url)
        self.queue_key = "scraper:tasks"
        self.seen_key = "scraper:seen"
        self.results_key = "scraper:results"
        self.failed_key = "scraper:failed"

    def enqueue(self, url, metadata=None):
        url_hash = sha256(url.encode()).hexdigest()
        if not self.redis.sismember(self.seen_key, url_hash):
            self.redis.sadd(self.seen_key, url_hash)
            task = json.dumps({"url": url, "metadata": metadata, "retries": 0})
            self.redis.lpush(self.queue_key, task)

    def dequeue(self, timeout=5):
        result = self.redis.brpop(self.queue_key, timeout=timeout)
        if result:
            return json.loads(result[1])
        return None

    def store_result(self, url, data):
        self.redis.hset(self.results_key, url, json.dumps(data))

    def mark_failed(self, task, error):
        task["retries"] += 1
        task["last_error"] = error
        if task["retries"] < 3:
            self.redis.lpush(self.queue_key, json.dumps(task))
        else:
            self.redis.hset(self.failed_key, task["url"], json.dumps(task))

# Worker process
def worker(queue):
    import requests
    while True:
        task = queue.dequeue()
        if not task:
            continue
        try:
            resp = requests.get(task["url"], timeout=10)
            queue.store_result(task["url"], {"status": resp.status_code, "length": len(resp.text)})
        except Exception as e:
            queue.mark_failed(task, str(e))
```

### Scrapy Spider with Auto-Throttle
```python
# scrapy_spider.py - Run with: scrapy runspider scrapy_spider.py -o output.jsonl
import scrapy
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor

class SecurityAdvisorySpider(CrawlSpider):
    name = "advisory_spider"
    allowed_domains = ["target.com"]
    start_urls = ["https://target.com/security/advisories"]

    custom_settings = {
        "AUTOTHROTTLE_ENABLED": True,
        "AUTOTHROTTLE_START_DELAY": 1,
        "AUTOTHROTTLE_MAX_DELAY": 10,
        "AUTOTHROTTLE_TARGET_CONCURRENCY": 2.0,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 4,
        "DOWNLOAD_DELAY": 1,
        "ROTATING_PROXY_LIST_PATH": "proxies.txt",
        "USER_AGENT": "Mozilla/5.0 (compatible; SecurityResearchBot/1.0)",
        "FEEDS": {"advisories.jsonl": {"format": "jsonlines"}},
    }

    rules = (
        Rule(LinkExtractor(allow=r"/advisory/\d+"), callback="parse_advisory"),
        Rule(LinkExtractor(allow=r"/advisories\?page=\d+")),
    )

    def parse_advisory(self, response):
        yield {
            "url": response.url,
            "title": response.css("h1::text").get("").strip(),
            "cve_ids": response.css(".cve-id::text").getall(),
            "severity": response.css(".severity-badge::text").get("").strip(),
            "description": response.css(".advisory-body::text").get("").strip(),
            "affected": response.css(".affected-products li::text").getall(),
            "published": response.css("time::attr(datetime)").get(""),
        }
```

### Load Balancing Across Multiple Exit IPs
```bash
# Configure multiple network interfaces for distributed scraping
# Each interface has a different public IP

# Create routing tables for each interface
ip rule add from 10.0.1.100 table 100
ip rule add from 10.0.2.100 table 200
ip rule add from 10.0.3.100 table 300

# Distribute requests across interfaces using curl
INTERFACES=("10.0.1.100" "10.0.2.100" "10.0.3.100")
TARGETS=$(cat urls.txt)
idx=0

for url in $TARGETS; do
  iface="${INTERFACES[$((idx % ${#INTERFACES[@]}))]}"
  curl -s --interface "$iface" "$url" -o "output_${idx}.html" &
  idx=$((idx + 1))
  # Limit concurrent background jobs
  if (( idx % 10 == 0 )); then wait; fi
done
wait
```

## CAPTCHA and WAF Evasion Techniques

### Browser Fingerprint Randomization
```python
import random
from playwright.sync_api import sync_playwright

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edge/120.0.0.0",
]

VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1366, "height": 768},
    {"width": 1440, "height": 900},
    {"width": 2560, "height": 1440},
]

def stealth_browser_context(playwright):
    """Create a browser context with randomized fingerprint."""
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context(
        user_agent=random.choice(USER_AGENTS),
        viewport=random.choice(VIEWPORTS),
        locale=random.choice(["en-US", "en-GB", "de-DE", "fr-FR"]),
        timezone_id=random.choice(["America/New_York", "Europe/London", "Asia/Tokyo"]),
        color_scheme=random.choice(["light", "dark"]),
        has_touch=random.choice([True, False]),
        java_script_enabled=True,
    )
    # Override navigator properties to avoid detection
    context.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
        Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        window.chrome = {runtime: {}};
    """)
    return browser, context
```

### WAF Detection and Header Rotation
```python
import requests
import random
import time

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "__cfduid", "cf-cache-status"],
    "akamai": ["x-akamai-transformed", "akamai-origin-hop"],
    "aws_waf": ["x-amzn-requestid", "x-amz-cf-id"],
    "imperva": ["x-iinfo", "visid_incap"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
}

def detect_waf(url):
    """Identify WAF protecting the target."""
    resp = requests.get(url, timeout=10)
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    detected = []
    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in headers_lower:
                detected.append(waf_name)
                break
    return detected

def evasive_request(url, session=None):
    """Make requests with randomized headers to evade WAF fingerprinting."""
    s = session or requests.Session()
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "de-DE,de;q=0.9"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": random.choice(["no-cache", "max-age=0"]),
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
        "DNT": random.choice(["0", "1"]),
    }
    # Randomize header order by rebuilding
    header_items = list(headers.items())
    random.shuffle(header_items)
    resp = s.get(url, headers=dict(header_items), timeout=15)
    return resp
```

### CAPTCHA Solving Service Integration
```python
import requests
import time

class CaptchaSolver:
    """Integration with CAPTCHA solving services (2captcha/anti-captcha)."""

    def __init__(self, api_key, service="2captcha"):
        self.api_key = api_key
        self.base_url = "http://2captcha.com" if service == "2captcha" else "https://api.anti-captcha.com"

    def solve_recaptcha_v2(self, site_key, page_url):
        """Solve reCAPTCHA v2 and return the response token."""
        # Submit task
        resp = requests.post(f"{self.base_url}/in.php", data={
            "key": self.api_key,
            "method": "userrecaptcha",
            "googlekey": site_key,
            "pageurl": page_url,
            "json": 1
        }, timeout=30)
        task_id = resp.json().get("request")

        # Poll for result
        for _ in range(60):
            time.sleep(5)
            result = requests.get(f"{self.base_url}/res.php", params={
                "key": self.api_key,
                "action": "get",
                "id": task_id,
                "json": 1
            }, timeout=10)
            data = result.json()
            if data.get("status") == 1:
                return data["request"]
            if "ERROR" in data.get("request", ""):
                raise Exception(f"CAPTCHA solve failed: {data['request']}")
        raise TimeoutError("CAPTCHA solving timed out")

    def solve_hcaptcha(self, site_key, page_url):
        """Solve hCaptcha challenge."""
        resp = requests.post(f"{self.base_url}/in.php", data={
            "key": self.api_key,
            "method": "hcaptcha",
            "sitekey": site_key,
            "pageurl": page_url,
            "json": 1
        }, timeout=30)
        task_id = resp.json().get("request")

        for _ in range(60):
            time.sleep(5)
            result = requests.get(f"{self.base_url}/res.php", params={
                "key": self.api_key, "action": "get", "id": task_id, "json": 1
            }, timeout=10)
            if result.json().get("status") == 1:
                return result.json()["request"]
        raise TimeoutError("hCaptcha solving timed out")
```

### Cloudflare Bypass with cloudscraper
```bash
# Install cloudscraper
pip install cloudscraper

# Python usage
python3 -c "
import cloudscraper
import json

scraper = cloudscraper.create_scraper(
    browser={'browser': 'chrome', 'platform': 'linux', 'desktop': True},
    delay=10
)

# Bypass Cloudflare challenge page
resp = scraper.get('https://target.com/protected-page')
print(f'Status: {resp.status_code}')
print(f'Content length: {len(resp.text)}')

# Extract data after bypass
data = scraper.get('https://target.com/api/data').json()
print(json.dumps(data, indent=2))
"
```

## Dark Web and .onion Scraping

### Tor SOCKS Proxy Configuration
```bash
# Start Tor service
sudo systemctl start tor

# Verify Tor is running
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
# Should return: {"IsTor": true, "IP": "x.x.x.x"}

# Fetch .onion site via Tor
curl --socks5-hostname 127.0.0.1:9050 \
  "http://example.onion/page" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0" \
  --max-time 60

# Resolve .onion and fetch with retry
for attempt in 1 2 3; do
  result=$(curl -s --socks5-hostname 127.0.0.1:9050 "http://example.onion/" --max-time 120)
  if [ -n "$result" ]; then
    echo "$result"
    break
  fi
  echo "[*] Attempt $attempt failed, retrying..."
  sleep 10
done
```

### Python Tor Session with Circuit Renewal
```python
import requests
import time
from stem import Signal
from stem.control import Controller

class TorSession:
    """Manage Tor sessions with circuit renewal for IP rotation."""

    def __init__(self, socks_port=9050, control_port=9051, control_password=""):
        self.socks_port = socks_port
        self.control_port = control_port
        self.control_password = control_password
        self.session = self._create_session()

    def _create_session(self):
        session = requests.Session()
        session.proxies = {
            "http": f"socks5h://127.0.0.1:{self.socks_port}",
            "https": f"socks5h://127.0.0.1:{self.socks_port}"
        }
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
        })
        return session

    def renew_circuit(self):
        """Request a new Tor circuit for a fresh exit IP."""
        with Controller.from_port(port=self.control_port) as controller:
            controller.authenticate(password=self.control_password)
            controller.signal(Signal.NEWNYM)
        time.sleep(5)  # Wait for new circuit

    def get(self, url, timeout=60, retries=3):
        for attempt in range(retries):
            try:
                resp = self.session.get(url, timeout=timeout)
                return resp
            except requests.RequestException:
                if attempt < retries - 1:
                    self.renew_circuit()
        return None

    def get_current_ip(self):
        resp = self.get("https://check.torproject.org/api/ip")
        if resp:
            return resp.json().get("IP")
        return None

# Usage
tor = TorSession(control_password="my_tor_password")
print(f"[*] Current exit IP: {tor.get_current_ip()}")
resp = tor.get("http://example.onion/data")
tor.renew_circuit()
print(f"[*] New exit IP: {tor.get_current_ip()}")
```

### Hidden Service Directory Enumeration
```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

ONION_DIRECTORIES = [
    "http://darkfailenbsdla5mal2mxn2uz66od5vbd5a4w6xgxtmheszqhcnzcp3ad.onion",
    "http://jaz45aabn5vkemy4jkg4mi4syheisqn2wn2n4fsuitpccdackjwxplad.onion",
]

COMMON_PATHS = [
    "/", "/login", "/register", "/api", "/admin",
    "/robots.txt", "/sitemap.xml", "/.well-known/",
    "/status", "/health", "/info", "/docs"
]

def enumerate_onion_paths(onion_url, paths, socks_port=9050):
    """Enumerate accessible paths on a hidden service."""
    session = requests.Session()
    session.proxies = {
        "http": f"socks5h://127.0.0.1:{socks_port}",
        "https": f"socks5h://127.0.0.1:{socks_port}"
    }
    found = []

    def check_path(path):
        try:
            url = f"{onion_url.rstrip('/')}{path}"
            resp = session.get(url, timeout=30)
            if resp.status_code in (200, 301, 302, 403):
                return {"path": path, "status": resp.status_code, "size": len(resp.content)}
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(check_path, p): p for p in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                print(f"  [{result['status']}] {result['path']} ({result['size']} bytes)")

    return found
```

### Onion Service Monitoring and Change Detection
```python
import hashlib
import json
import time
import requests
from datetime import datetime
from pathlib import Path

class OnionMonitor:
    """Monitor .onion services for content changes over time."""

    def __init__(self, state_file="onion_state.json", socks_port=9050):
        self.state_file = Path(state_file)
        self.socks_port = socks_port
        self.state = self._load_state()
        self.session = requests.Session()
        self.session.proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}"
        }

    def _load_state(self):
        if self.state_file.exists():
            return json.loads(self.state_file.read_text())
        return {}

    def _save_state(self):
        self.state_file.write_text(json.dumps(self.state, indent=2))

    def check_service(self, onion_url):
        """Check if service is up and detect content changes."""
        try:
            resp = self.session.get(onion_url, timeout=60)
            content_hash = hashlib.sha256(resp.content).hexdigest()
            timestamp = datetime.utcnow().isoformat()

            prev = self.state.get(onion_url, {})
            changed = prev.get("hash") != content_hash

            entry = {
                "hash": content_hash,
                "status": resp.status_code,
                "size": len(resp.content),
                "last_checked": timestamp,
                "last_changed": timestamp if changed else prev.get("last_changed"),
                "is_up": True,
                "changed": changed
            }
            self.state[onion_url] = entry
            self._save_state()
            return entry

        except requests.RequestException as e:
            entry = {
                "is_up": False,
                "last_checked": datetime.utcnow().isoformat(),
                "error": str(e)
            }
            self.state[onion_url] = {**self.state.get(onion_url, {}), **entry}
            self._save_state()
            return entry

    def monitor_loop(self, urls, interval=300):
        """Continuously monitor a list of onion services."""
        print(f"[*] Monitoring {len(urls)} services every {interval}s")
        while True:
            for url in urls:
                result = self.check_service(url)
                status = "UP" if result["is_up"] else "DOWN"
                changed = " [CHANGED]" if result.get("changed") else ""
                print(f"  [{status}]{changed} {url[:50]}...")
            time.sleep(interval)
```

## NVD API Advanced Pagination

### Date-Range Segmented Scraping
```python
import requests
import time
from datetime import datetime, timedelta

def scrape_nvd_by_date_range(keyword, start_date, end_date, chunk_days=30):
    """Scrape NVD by splitting date range into chunks to avoid timeouts."""
    all_cves = []
    current = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")

    while current < end:
        chunk_end = min(current + timedelta(days=chunk_days), end)
        params = {
            "keywordSearch": keyword,
            "pubStartDate": current.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": chunk_end.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": 2000
        }
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, timeout=60
        )
        data = resp.json()
        all_cves.extend(data.get("vulnerabilities", []))
        print(f"  [{current.date()} to {chunk_end.date()}]: {len(data.get('vulnerabilities', []))} CVEs")
        current = chunk_end + timedelta(days=1)
        time.sleep(6)

    return all_cves

cves = scrape_nvd_by_date_range("apache", "2023-01-01", "2024-12-31")
print(f"Total CVEs collected: {len(cves)}")
```

### NVD CVE Detail Extraction Pipeline
```python
import json
from dataclasses import dataclass
from typing import Optional, List

@dataclass(frozen=True)
class CVEDetail:
    cve_id: str
    description: str
    cvss_v3_score: Optional[float]
    cvss_v3_severity: Optional[str]
    attack_vector: Optional[str]
    published: str
    last_modified: str
    references: tuple
    cwe_ids: tuple

def parse_nvd_response(data):
    """Parse NVD API response into structured CVE records."""
    records = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln["cve"]
        metrics = cve.get("metrics", {})
        cvss_data = {}
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]

        records.append(CVEDetail(
            cve_id=cve["id"],
            description=cve["descriptions"][0]["value"] if cve.get("descriptions") else "",
            cvss_v3_score=cvss_data.get("baseScore"),
            cvss_v3_severity=cvss_data.get("baseSeverity"),
            attack_vector=cvss_data.get("attackVector"),
            published=cve.get("published", ""),
            last_modified=cve.get("lastModified", ""),
            references=tuple(r["url"] for r in cve.get("references", [])),
            cwe_ids=tuple(w["value"] for w in cve.get("weaknesses", [{}])
                         for d in w.get("description", []) if w.get("description"))
        ))
    return records
```

## Exploit-DB Automation

### Bulk Exploit Download and Categorization
```bash
# Download all exploits for a product and categorize by type
searchsploit apache httpd --json | jq -r '.RESULTS_EXPLOIT[].Code' | while read code; do
  searchsploit -m "$code" 2>/dev/null
done

# Categorize downloaded exploits by platform
for file in /usr/share/exploitdb/exploits/*/*; do
  platform=$(echo "$file" | cut -d'/' -f6)
  echo "$platform: $(basename "$file")"
done | sort | uniq -c | sort -rn
```

### Exploit Metadata Enrichment
```python
import subprocess
import json
import re

def enrich_exploit_data(query):
    """Fetch exploit data and enrich with CVE cross-references and metadata."""
    result = subprocess.run(
        ["searchsploit", query, "--json"],
        capture_output=True, text=True
    )
    data = json.loads(result.stdout)
    enriched = []

    for item in data.get("RESULTS_EXPLOIT", []):
        entry = {
            "exploit_id": item.get("Code", "").split("/")[-1],
            "title": item.get("Title", ""),
            "type": item.get("Type", ""),
            "platform": item.get("Platform", ""),
            "date": item.get("Date", ""),
            "author": item.get("Author", ""),
        }
        # Try to extract CVE IDs from title
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, item.get("Title", ""))
        entry["cve_references"] = cves

        # Get CVE mapping from searchsploit
        if cves:
            for cve in cves:
                cve_result = subprocess.run(
                    ["searchsploit", "--cve", cve],
                    capture_output=True, text=True
                )
                entry["cve_exploit_count"] = len(
                    cve_result.stdout.strip().split("\n")
                ) - 2  # Subtract header lines

        enriched.append(entry)

    return enriched

exploits = enrich_exploit_data("nginx")
for e in exploits:
    print(f"[{e['exploit_id']}] {e['title']}")
    if e['cve_references']:
        print(f"  CVEs: {', '.join(e['cve_references'])}")
```

## GitHub Advisory Deep Parsing

### GraphQL Advisory Query
```python
import requests

GITHUB_GRAPHQL = "https://api.github.com/graphql"

def fetch_advisory_detail(ghsa_id, token):
    """Fetch full advisory details via GraphQL including version ranges."""
    query = """
    query($id: String!) {
      securityAdvisory(ghsaId: $id) {
        ghsaId
        summary
        severity
        publishedAt
        updatedAt
        references { url }
        vulnerabilities(first: 20) {
          nodes {
            package { name ecosystem }
            vulnerableVersionRange
            firstPatchedVersion { identifier }
            severity
            advisory { ghsaId }
          }
        }
      }
    }
    """
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.post(GITHUB_GRAPHQL, json={"query": query, "variables": {"id": ghsa_id}},
                         headers=headers, timeout=15)
    return resp.json().get("data", {}).get("securityAdvisory")

# Fetch advisory and build version impact matrix
advisory = fetch_advisory_detail("GHSA-xxxx-xxxx-xxxx", GITHUB_TOKEN)
if advisory:
    for vuln in advisory.get("vulnerabilities", {}).get("nodes", []):
        pkg = vuln["package"]["name"]
        affected = vuln.get("vulnerableVersionRange", "unknown")
        patched = vuln.get("firstPatchedVersion", {}).get("identifier", "NO PATCH")
        print(f"  {pkg}: {affected} -> patched in {patched}")
```

### Advisory Deduplication and Merging
```python
import hashlib
import json
from typing import Dict, List

class AdvisoryDeduplicator:
    """Deduplicate advisories across NVD, GitHub, and vendor sources."""

    def __init__(self):
        self.cve_index: Dict[str, List[dict]] = {}

    def add_advisory(self, source, advisory):
        """Index advisory by CVE ID for cross-source deduplication."""
        for cve_id in advisory.get("cve_ids", []):
            if cve_id not in self.cve_index:
                self.cve_index[cve_id] = []
            entry = {
                "source": source,
                "title": advisory.get("title", ""),
                "severity": advisory.get("severity", ""),
                "url": advisory.get("url", ""),
                "published": advisory.get("published", "")
            }
            # Avoid duplicate from same source
            existing = [e for e in self.cve_index[cve_id] if e["source"] == source]
            if not existing:
                self.cve_index[cve_id].append(entry)

    def get_merged(self, cve_id):
        """Get all sources for a specific CVE, sorted by publication date."""
        entries = self.cve_index.get(cve_id, [])
        return sorted(entries, key=lambda e: e.get("published", ""))

    def conflicts(self):
        """Find CVEs where sources disagree on severity."""
        conflicts = []
        for cve_id, entries in self.cve_index.items():
            severities = set(e["severity"] for e in entries if e.get("severity"))
            if len(severities) > 1:
                conflicts.append({
                    "cve_id": cve_id,
                    "severities": list(severities),
                    "sources": [e["source"] for e in entries]
                })
        return conflicts

    def export(self, output_path):
        """Export merged advisory database to JSON."""
        data = {cve_id: self.get_merged(cve_id) for cve_id in sorted(self.cve_index)}
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
```

## RSS Feed Monitoring Pipeline

### Multi-Source Feed Aggregator
```python
import feedparser
import hashlib
import json
import time
from pathlib import Path
from datetime import datetime

class SecurityFeedAggregator:
    """Aggregate security advisories from multiple RSS/Atom feeds."""

    FEEDS = {
        "nvd": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
        "exploitdb": "https://www.exploit-db.com/rss.xml",
        "us_cert": "https://www.cisa.gov/news.xml",
        "schneier": "https://www.schneier.com/feed/",
    }

    def __init__(self, state_dir="feed_state"):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(exist_ok=True)
        self.state = self._load_state()

    def _load_state(self):
        state_file = self.state_dir / "seen.json"
        if state_file.exists():
            return set(json.loads(state_file.read_text()))
        return set()

    def _save_state(self):
        state_file = self.state_dir / "seen.json"
        state_file.write_text(json.dumps(list(self.state)))

    def check_all_feeds(self):
        """Check all feeds and return new entries."""
        new_entries = []
        for name, url in self.FEEDS.items():
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries:
                    entry_hash = hashlib.sha256(
                        f"{name}:{entry.get('id', entry.get('link', ''))}".encode()
                    ).hexdigest()
                    if entry_hash not in self.state:
                        new_entries.append({
                            "source": name,
                            "title": entry.get("title", ""),
                            "link": entry.get("link", ""),
                            "date": entry.get("published", ""),
                            "summary": entry.get("summary", "")[:500]
                        })
                        self.state.add(entry_hash)
            except Exception as e:
                print(f"[ERROR] Feed {name}: {e}")
        self._save_state()
        return new_entries

    def run_monitor(self, interval=300, callback=None):
        """Run continuous monitoring loop."""
        while True:
            new = self.check_all_feeds()
            if new and callback:
                callback(new)
            time.sleep(interval)

aggregator = SecurityFeedAggregator()
new = aggregator.check_all_feeds()
for entry in new:
    print(f"[{entry['source']}] {entry['title']}")
```

### Severity-Based Alert Filter
```python
CRITICAL_KEYWORDS = [
    "critical", "remote code execution", "rce", "zero-day", "0day",
    "actively exploited", "emergency patch", "unauthenticated",
    "arbitrary code execution", "privilege escalation"
]

def filter_critical(entries):
    """Filter feed entries for critical-severity findings."""
    critical = []
    for entry in entries:
        text = f"{entry['title']} {entry['summary']}".lower()
        if any(kw in text for kw in CRITICAL_KEYWORDS):
            critical.append(entry)
    return critical
```
```
