# Web API Fuzzing Guide — RESTler and ffuf

> Practical guide to fuzzing REST and web APIs using Microsoft RESTler for smart grammar-based fuzzing and ffuf for high-speed endpoint and parameter discovery. Covers setup, methodology, and command recipes.

---

## Introduction

APIs expose application logic directly, often without the input validation layers that traditional web UIs enforce. Fuzzing APIs is therefore one of the highest-yield testing activities: malformed parameters, unexpected content types, and boundary-violating payloads frequently uncover authentication bypasses, injection flaws, and logic errors. This guide focuses on two complementary tools — RESTler for intelligent grammar-based REST API fuzzing and ffuf for fast brute-force discovery of endpoints and parameters.

---

## Hands-on Exercise

### 1. RESTler Setup and Basics

RESTler is Microsoft's REST API fuzzer. It compiles an OpenAPI specification into a grammar, then generates and sends requests that exercise the API in ways developers never anticipated.

```bash
# Install RESTler
pip install restler-fuzzer

# Compile the API grammar from an OpenAPI spec
restler-compile --api_spec /path/to/openapi.json

# Run the fuzzing engine
restler-fuzz --grammar_file Compile/grammar.py --dictionary_file Compile/dict.json --target_ip api.target.com --target_port 443 --use_ssl

# Run with authentication token
restler-fuzz --grammar_file Compile/grammar.py --dictionary_file Compile/dict.json --target_ip api.target.com --target_port 443 --use_ssl --token_refresh_cmd "curl -s -X POST https://auth.target.com/oauth/token -d 'grant_type=client_credentials&client_id=ID&client_secret=SECRET' | jq -r '.access_token'"
```

Key modes:
- **BFS (Breadth-First Search)**: Quick smoke test — one request per endpoint.
- **DFS (Depth-First Search)**: Deeper exploration of each endpoint's parameter space.
- **Test-all**: Exhaustive testing of all combinations.

### 2. ffuf for API Endpoint Discovery

Use ffuf to brute-force discover hidden or undocumented API endpoints before deeper fuzzing.

```bash
# Discover API paths
ffuf -u https://api.target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,401,403 -t 50

# Discover API version endpoints
ffuf -u https://api.target.com/vFUZZ/users -w /usr/share/seclists/Fuzzing/numbers-1-20.txt -mc 200,401

# Fuzz path parameters (e.g., /api/users/{id})
ffuf -u https://api.target.com/api/users/FUZZ -w /usr/share/seclists/Fuzzing/numbers-1-1000.txt -mc 200 -t 100
```

### 3. Parameter Fuzzing with ffuf

Test specific parameters for injection, type confusion, and boundary violations.

```bash
# Fuzz query parameters
ffuf -u "https://api.target.com/api/users?sort=FUZZ" -w /usr/share/seclists/Fuzzing/sql-injection.txt -mc 500 -t 30

# Fuzz POST body JSON values
ffuf -u https://api.target.com/api/users -X POST -H "Content-Type: application/json" -d '{"role":"FUZZ"}' -w /usr/share/seclists/Usernames/roles.txt -mc 200,201 -t 20

# Fuzz HTTP headers
ffuf -u https://api.target.com/api/admin -H "X-Forwarded-For: FUZZ" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -t 50
```

### 4. Content-Type Fuzzing

APIs may behave differently depending on the Content-Type header. Testing alternative content types can bypass validation.

```bash
# Test different content types for the same endpoint
for ct in "application/json" "application/xml" "application/x-www-form-urlencoded" "text/plain" "multipart/form-data"; do
  echo "--- Testing: $ct ---"
  curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: $ct" -d '{"name":"test"}' https://api.target.com/api/users
  echo ""
done
```

### 5. Authentication Boundary Testing

Verify that unauthenticated and low-privilege users cannot access admin endpoints.

```bash
# Test without any token
ffuf -u https://api.target.com/api/admin/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200 -t 30

# Test with a low-privilege user token
ffuf -u https://api.target.com/api/admin/FUZZ -H "Authorization: Bearer LOW_PRIV_TOKEN" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200 -t 30
```

---

## References

- RESTler GitHub: [https://github.com/microsoft/restler-fuzzer](https://github.com/microsoft/restler-fuzzer)
- RESTler Paper: "RESTler: Stateful REST API Fuzzing" (Microsoft Research, 2019)
- ffuf Documentation: [https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf)
- SecLists API Wordlists: [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
- OWASP API Security Top 10: [https://owasp.org/API-Security/editions/2023/en/0x11-t10/](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
