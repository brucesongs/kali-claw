# Rate Limiting Implementation Guide

> Practical implementation patterns for rate limiting including token bucket, sliding window, and distributed rate limiting. Covers algorithm selection, Redis-backed implementations, and bypass detection.

---

## 1. Token Bucket Algorithm

The token bucket algorithm allows bursts while enforcing an average rate. Tokens are added at a fixed rate; each request consumes one token. When the bucket is empty, requests are rejected.

```python
# Python — Token bucket implementation with Redis
import time
import redis

class TokenBucket:
    """Redis-backed token bucket rate limiter."""

    def __init__(self, redis_client: redis.Redis, capacity: int, refill_rate: float):
        self.redis = redis_client
        self.capacity = capacity          # max tokens
        self.refill_rate = refill_rate    # tokens per second

    def allow_request(self, key: str) -> bool:
        """Check if request is allowed, consuming one token if so."""
        pipe = self.redis.pipeline()
        now = time.time()
        bucket_key = f"ratelimit:bucket:{key}"

        # Atomic check-and-update
        pipe.watch(bucket_key)
        data = self.redis.hgetall(bucket_key)

        tokens = float(data.get(b'tokens', self.capacity))
        last_refill = float(data.get(b'last_refill', now))

        # Calculate refilled tokens
        elapsed = now - last_refill
        tokens = min(self.capacity, tokens + elapsed * self.refill_rate)

        if tokens >= 1:
            tokens -= 1
            allowed = True
        else:
            allowed = False

        pipe.multi()
        pipe.hset(bucket_key, mapping={'tokens': tokens, 'last_refill': now})
        pipe.expire(bucket_key, int(self.capacity / self.refill_rate) + 60)
        pipe.execute()

        return allowed
```

## 2. Sliding Window Log Algorithm

Tracks exact timestamps of each request within the window. More memory-intensive but provides precise rate limiting without boundary issues.

```python
# Python — Sliding window with Redis sorted sets
import time
import redis

class SlidingWindowLog:
    """Precise sliding window rate limiter using sorted sets."""

    def __init__(self, redis_client: redis.Redis, max_requests: int, window_seconds: int):
        self.redis = redis_client
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    def allow_request(self, key: str) -> tuple[bool, dict]:
        """Returns (allowed, metadata) with remaining quota info."""
        now = time.time()
        window_start = now - self.window_seconds
        zset_key = f"ratelimit:sliding:{key}"

        pipe = self.redis.pipeline()
        # Remove expired entries
        pipe.zremrangebyscore(zset_key, 0, window_start)
        # Count current window
        pipe.zcard(zset_key)
        # Add current request timestamp
        pipe.zadd(zset_key, {f"{now}": now})
        pipe.expire(zset_key, self.window_seconds + 1)
        results = pipe.execute()

        current_count = results[1]
        allowed = current_count < self.max_requests

        if not allowed:
            # Remove the optimistically added entry
            self.redis.zrem(zset_key, f"{now}")

        return allowed, {
            'remaining': max(0, self.max_requests - current_count - (1 if allowed else 0)),
            'reset_at': int(now + self.window_seconds),
            'limit': self.max_requests
        }
```

## 3. Distributed Rate Limiting with Consistent Hashing

```yaml
# nginx — Rate limiting configuration for distributed deployments
http:
  # Define rate limit zones
  limit_req_zone $binary_remote_addr zone=api_general:10m rate=100r/s;
  limit_req_zone $binary_remote_addr zone=auth_endpoints:5m rate=5r/m;
  limit_req_zone $http_x_api_key zone=api_key_limit:20m rate=1000r/m;

  server {
    # General API rate limit — allow burst of 20
    location /api/ {
      limit_req zone=api_general burst=20 nodelay;
      limit_req_status 429;
      proxy_pass http://backend;
    }

    # Strict limit on authentication endpoints
    location /api/auth/ {
      limit_req zone=auth_endpoints burst=2 nodelay;
      limit_req_status 429;
      add_header Retry-After 60;
      proxy_pass http://backend;
    }
  }
}
```

## 4. Rate Limit Response Headers

```python
# Python Flask — Middleware adding standard rate limit headers
from functools import wraps
from flask import request, jsonify, make_response

def rate_limit_headers(limiter_result: dict):
    """Add standard rate limit headers to response."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            allowed, meta = limiter.allow_request(get_client_key())
            if not allowed:
                resp = make_response(jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': meta['reset_at'] - int(time.time())
                }), 429)
            else:
                resp = make_response(f(*args, **kwargs))

            # Standard headers (RFC 6585 / draft-ietf-httpapi-ratelimit-headers)
            resp.headers['X-RateLimit-Limit'] = str(meta['limit'])
            resp.headers['X-RateLimit-Remaining'] = str(meta['remaining'])
            resp.headers['X-RateLimit-Reset'] = str(meta['reset_at'])
            return resp
        return wrapper
    return decorator
```

## 5. Rate Limit Bypass Detection

```bash
# Detect rate limit evasion attempts
# Common bypass techniques to monitor:

# 1. IP rotation detection — many IPs hitting same endpoint pattern
grep "429" /var/log/nginx/access.log | \
  awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# 2. Header manipulation detection
# Watch for X-Forwarded-For spoofing attempts
grep -E "X-Forwarded-For:.*,.*,.*," /var/log/nginx/access.log

# 3. Monitor for distributed attacks (same user-agent, different IPs)
grep "/api/auth/login" /var/log/nginx/access.log | \
  awk -F'"' '{print $6}' | sort | uniq -c | sort -rn | head -10
```

## 6. Algorithm Selection Guide

| Algorithm | Memory | Precision | Burst Handling | Best For |
|-----------|--------|-----------|----------------|----------|
| Token Bucket | Low | Medium | Allows bursts | API gateways |
| Sliding Window Log | High | Exact | Strict | Auth endpoints |
| Sliding Window Counter | Medium | Approximate | Moderate | General use |
| Fixed Window | Low | Low | Boundary spikes | Simple cases |
| Leaky Bucket | Low | Medium | Smooths traffic | Queue-based |

Choose token bucket for APIs that need burst tolerance. Use sliding window log for security-critical endpoints (login, password reset) where precision matters more than memory cost.
