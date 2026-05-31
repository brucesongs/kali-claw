# Rate Limiting and Stealth Guide

> Techniques for rate limiting, request rotation, proxy chains, and user-agent rotation to avoid detection during web scraping operations.

## Prerequisites

- Python 3.8+ with requests/httpx
- Proxy service access (residential or datacenter)
- curl and basic networking tools

## 1. Adaptive Rate Limiting

### Basic Throttling

```bash
# Simple rate-limited requests with curl
for url in $(cat urls.txt); do
    curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" "$url"
    sleep $(shuf -i 2-5 -n 1)  # Random 2-5 second delay
done

# Rate limit with GNU parallel (max 2 concurrent, 3s delay)
cat urls.txt | parallel -j 2 --delay 3 'curl -s -o /dev/null -w "%{http_code} {}\n" {}'
```

### Python Adaptive Rate Limiter

```python
import time
import random
import httpx

class AdaptiveRateLimiter:
    def __init__(self, base_delay=1.0, max_delay=30.0, backoff_factor=2.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.current_delay = base_delay

    def wait(self):
        jitter = random.uniform(0.5, 1.5)
        time.sleep(self.current_delay * jitter)

    def success(self):
        self.current_delay = max(self.base_delay, self.current_delay / self.backoff_factor)

    def throttled(self):
        self.current_delay = min(self.max_delay, self.current_delay * self.backoff_factor)

limiter = AdaptiveRateLimiter(base_delay=1.0)

with httpx.Client(timeout=30) as client:
    for url in target_urls:
        limiter.wait()
        resp = client.get(url)
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 10))
            limiter.throttled()
            time.sleep(retry_after)
        elif resp.status_code == 200:
            limiter.success()
            process(resp)
```

## 2. Proxy Rotation

### Proxy Chain Configuration

```bash
# Test proxy connectivity
curl -x socks5://127.0.0.1:9050 https://check.torproject.org/api/ip
curl -x http://user:pass@proxy.example.com:8080 https://httpbin.org/ip

# Rotate through proxy list
while IFS= read -r proxy; do
    curl -x "$proxy" -s --max-time 10 https://httpbin.org/ip && echo " via $proxy"
done < proxies.txt

# proxychains configuration (/etc/proxychains4.conf)
# dynamic_chain
# proxy_dns
# [ProxyList]
# socks5 127.0.0.1 9050
# http 10.0.0.1 8080 user pass
```

### Python Proxy Rotator

```python
import itertools
import httpx

class ProxyRotator:
    def __init__(self, proxy_list: list[str]):
        self.proxies = itertools.cycle(proxy_list)
        self.failed = set()

    def get_next(self) -> str:
        for _ in range(len(self.failed) + 1):
            proxy = next(self.proxies)
            if proxy not in self.failed:
                return proxy
        raise RuntimeError("All proxies exhausted")

    def mark_failed(self, proxy: str):
        self.failed.add(proxy)

proxies = [
    "socks5://127.0.0.1:9050",
    "http://user:pass@dc1.proxy.io:8080",
    "http://user:pass@dc2.proxy.io:8080",
]
rotator = ProxyRotator(proxies)

for url in target_urls:
    proxy = rotator.get_next()
    try:
        resp = httpx.get(url, proxy=proxy, timeout=15)
        process(resp)
    except httpx.ConnectError:
        rotator.mark_failed(proxy)
```

## 3. User-Agent Rotation

### Realistic User-Agent Pool

```python
import random

USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

def get_headers() -> dict:
    ua = random.choice(USER_AGENTS)
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
```

### Curl with Rotating Headers

```bash
# Random user-agent from file
UA=$(shuf -n 1 user-agents.txt)
curl -H "User-Agent: $UA" \
     -H "Accept: text/html,application/xhtml+xml" \
     -H "Accept-Language: en-US,en;q=0.9" \
     --compressed \
     "https://target.example.com/page"
```

## 4. Session Fingerprint Consistency

```python
import httpx
import random

class StealthSession:
    """Maintains consistent fingerprint per session while rotating between sessions."""

    def __init__(self, proxy: str | None = None):
        ua = random.choice(USER_AGENTS)
        self.client = httpx.Client(
            proxy=proxy,
            headers={
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9"]),
                "Accept-Encoding": "gzip, deflate, br",
            },
            follow_redirects=True,
            timeout=20,
        )

    def get(self, url: str) -> httpx.Response:
        return self.client.get(url)

    def close(self):
        self.client.close()

# Rotate sessions every N requests
SESSION_LIFETIME = random.randint(10, 25)
session = StealthSession(proxy=rotator.get_next())
for i, url in enumerate(target_urls):
    if i > 0 and i % SESSION_LIFETIME == 0:
        session.close()
        session = StealthSession(proxy=rotator.get_next())
    resp = session.get(url)
```

## 5. Request Timing Patterns

```python
import time
import random
import numpy as np

def human_delay():
    """Simulate human browsing patterns with log-normal distribution."""
    delay = np.random.lognormal(mean=1.0, sigma=0.5)
    return max(0.5, min(delay, 15.0))

def burst_pattern(batch_size=5, burst_delay=0.3, pause_range=(5, 15)):
    """Simulate burst reading: quick page loads then pause."""
    for i in range(batch_size):
        yield burst_delay + random.uniform(0, 0.2)
    yield random.uniform(*pause_range)

# Usage
for url in target_urls:
    time.sleep(human_delay())
    fetch(url)
```

## 6. Detection Evasion Checklist

```bash
# Verify your fingerprint is not flagged
curl -s https://httpbin.org/headers | jq .headers

# Check if IP is blacklisted
curl -s "https://check.torproject.org/api/ip"

# Test TLS fingerprint (JA3)
curl -s --tlsv1.3 https://tls.browserleaks.com/json | jq '{ja3: .ja3_hash, cipher: .cipher_suite}'

# Validate proxy is working
curl -x socks5://proxy:1080 -s https://httpbin.org/ip | jq .origin
```

## Quick Reference

| Technique | Purpose | Key Consideration |
|-----------|---------|-------------------|
| Adaptive delay | Avoid rate limits | Back off on 429 responses |
| Proxy rotation | Distribute requests | Use residential for sensitive targets |
| UA rotation | Avoid fingerprinting | Keep consistent per session |
| Session cycling | Reset server-side tracking | Rotate every 10-25 requests |
| Human timing | Evade behavioral analysis | Log-normal distribution |

## Integration with Other Skills

- **data-scraper-agent**: Core stealth layer for all scraping operations
- **osint**: Passive reconnaissance without alerting targets
- **web-pentest**: Avoiding WAF detection during testing
