# Exa Search Payloads

## Setup
```bash
export EXA_API_KEY="your_api_key_here"
```

## Basic Search
```bash
curl -X POST "https://api.exa.ai/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "CVE-2024 affecting nginx",
    "num_results": 10,
    "use_autoprompt": true
  }'
```

## Date Filtering
```bash
# Only results from last 30 days
curl -X POST "https://api.exa.ai/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Spring Boot vulnerabilities",
    "num_results": 10,
    "start_published_date": "2024-04-01"
  }'
```

## Domain Filtering
```bash
# Search only GitHub and security blogs
curl -X POST "https://api.exa.ai/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "JWT security best practices",
    "num_results": 10,
    "include_domains": ["github.com", "portswigger.net", "owasp.org"]
  }'
```

## Content Extraction
```bash
# Get full text content
curl -X POST "https://api.exa.ai/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Log4Shell exploitation techniques",
    "num_results": 5,
    "contents": {
      "text": true
    }
  }'
```

## Security Research Query Examples

```bash
# CVE research
"CVE-2024 affecting AWS services"
"Recent critical vulnerabilities in container runtimes"

# Exploit techniques
"SSRF bypass in cloud metadata services"
"SQL injection in GraphQL implementations"

# Tool research
"Best open-source SAST tools for Go"
"Automated exploit frameworks 2024"

# Threat intelligence
"APT groups targeting financial sector"
"Ransomware campaigns in healthcare 2024"
```
