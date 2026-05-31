# Browser QA Test Cases

## TC-BQ-001: Auth Flow Testing
**Objective**: Test login, session handling, logout
**Severity**: HIGH
**Prerequisites**: Headless browser (Playwright/Puppeteer) installed, target application running with login form

**Remediation**: Ensure session cookies use HttpOnly+Secure+SameSite flags; implement session timeout; invalidate server-side session on logout

**Steps**:
1. Navigate to login page
2. Fill username and password
3. Submit form
4. Verify session cookie set with HttpOnly + Secure flags
5. Navigate to protected page
6. Logout
7. Verify session cookie deleted

**Expected Output**: Session lifecycle verified end-to-end

**Pass Criteria**:
- [ ] Login succeeds with valid creds
- [ ] Session cookie has HttpOnly=true, Secure=true
- [ ] Logout clears session

## TC-BQ-002: CSRF Token Validation
**Objective**: Check CSRF protection on state-changing requests
**Severity**: HIGH
**Prerequisites**: Headless browser (Playwright/Puppeteer) installed, target application running with authenticated session

**Remediation**: Implement anti-CSRF tokens on all state-changing forms; validate tokens server-side on every POST/PUT/DELETE request; use SameSite=Strict cookie attribute as defense-in-depth; implement double-submit cookie pattern for API endpoints

**Steps**:
1. Navigate to form page
2. Extract CSRF token from hidden input
3. Submit form normally
4. Monitor POST request for CSRF token in body/header
5. Repeat without CSRF token (should fail)

**Expected Output**: CSRF protection confirmed present and enforced

**Pass Criteria**:
- [ ] CSRF token present in form
- [ ] Token sent with POST request
- [ ] Request without token is rejected

## TC-BQ-003: XSS via Form Input
**Objective**: Test XSS payloads via form submission
**Severity**: CRITICAL
**Prerequisites**: Headless browser installed, target application with form inputs (search, comments, profile fields)

**Remediation**: Implement context-aware output encoding for all user-supplied data; use Content-Security-Policy headers to restrict script execution; sanitize input server-side using allowlists; implement HttpOnly cookies to prevent JavaScript access to session tokens

**Steps**:
1. Fill form with XSS payload: `<script>alert('XSS')</script>`
2. Submit form
3. Check if payload executed (alert fired or DOM contains unescaped payload)
4. Test additional payloads: `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`

**Expected Output**: All payloads properly sanitized

**Pass Criteria**:
- [ ] Payload NOT executed (properly escaped/sanitized)
- [ ] No unescaped user input in DOM

## TC-BQ-004: Cookie Security Audit
**Objective**: Verify all cookies have appropriate security flags
**Severity**: MEDIUM
**Prerequisites**: Headless browser installed, target application running with authenticated and unauthenticated pages

**Remediation**: Set HttpOnly flag on all session cookies to prevent XSS-based theft; set Secure flag on all cookies served over HTTPS; use SameSite=Lax or SameSite=Strict; set reasonable expiration times; avoid storing sensitive data directly in cookie values

**Steps**:
1. Navigate to target application
2. Authenticate if required
3. Enumerate all cookies via `page.context.cookies()`
4. Check each cookie for HttpOnly, Secure, SameSite attributes
5. Identify session cookies with missing flags

**Expected Output**: Cookie audit report with security flag status

**Pass Criteria**:
- [ ] All session cookies have HttpOnly flag
- [ ] All cookies have Secure flag on HTTPS sites
- [ ] SameSite attribute set (Lax or Strict)
- [ ] No excessive cookie lifetimes (> 1 year)

## TC-BQ-005: Network Request Interception
**Objective**: Intercept and analyze API calls for sensitive data leakage
**Severity**: HIGH
**Prerequisites**: Headless browser installed, target application with API endpoints, network monitoring configured

**Remediation**: Use HTTPS for all API communications; avoid placing sensitive tokens or credentials in URL parameters; implement proper Authorization headers instead of cookie-based API auth; redact sensitive fields from API responses; apply rate limiting on API endpoints

**Steps**:
1. Setup request interception with `page.on("request")`
2. Navigate through application workflow
3. Capture all API requests and responses
4. Analyze for sensitive data in URLs (tokens, passwords)
5. Check for unencrypted requests (HTTP instead of HTTPS)

**Expected Output**: Network traffic analysis report

**Pass Criteria**:
- [ ] No sensitive data in URL parameters
- [ ] All API calls use HTTPS
- [ ] No credentials sent in GET requests
- [ ] Authorization headers not leaked in redirects

## TC-BQ-006: CSP Header Validation
**Objective**: Validate Content-Security-Policy headers are present, correctly configured, and effectively preventing inline script execution and unauthorized resource loading
**Severity**: HIGH
**Prerequisites**: Headless browser installed, target application accessible over HTTPS, browser DevTools Protocol access for violation monitoring

**Remediation**: Deploy a strict Content-Security-Policy header with default-src 'self'; avoid 'unsafe-inline' and 'unsafe-eval' directives; use nonce-based or hash-based CSP for legitimate inline scripts; implement report-uri or report-to directive for ongoing monitoring; test CSP with Google's CSP Evaluator before deployment

**Steps**:
1. Navigate to each major page of the application
2. Extract CSP header from HTTP response using `page.on("response")`
3. Parse CSP directives and check for weak configurations:
   - `default-src 'none'` or `'self'` (strict)
   - No `'unsafe-inline'` in script-src
   - No `'unsafe-eval'` in script-src
   - frame-ancestors directive present (clickjacking protection)
4. Inject inline script via `page.evaluate` and verify CSP blocks execution
5. Monitor CSP violation events via `SecurityPolicyViolationEvent`
6. Test loading resources from external domains to verify allowed origins
7. Document all CSP weaknesses found

**Expected Output**: CSP audit report with directive analysis and violation evidence

**Pass Criteria**:
- [ ] CSP header present on all pages
- [ ] No 'unsafe-inline' or 'unsafe-eval' in script-src
- [ ] Inline script injection blocked by CSP
- [ ] frame-ancestors directive prevents framing (clickjacking protection)
- [ ] CSP violation reports generated for blocked resources

## TC-BQ-007: Clickjacking Detection
**Objective**: Test whether the application can be framed by a malicious page and whether UI elements can be hijacked to trick users into performing unintended actions
**Severity**: HIGH
**Prerequisites**: Headless browser installed, target application running, test HTML server for hosting malicious frames

**Remediation**: Set X-Frame-Options header to DENY or SAMEORIGIN; implement frame-ancestors 'none' or 'self' in Content-Security-Policy; use JavaScript frame-busting code as defense-in-depth; apply JavaScript frame validation on sensitive action handlers

**Steps**:
1. Check X-Frame-Options and CSP frame-ancestors headers on all pages
2. Create a test page that iframes the target application:
   ```html
   <html>
   <body>
   <iframe src="https://target.example.com/settings" style="opacity:0.5;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
   <div style="position:absolute;top:200px;left:200px">Click to win a prize</div>
   </body>
   </html>
   ```
3. Load the test page in headless browser and verify the iframe loads successfully
4. Attempt to click elements inside the iframe via Playwright
5. Test drag-and-drop attacks between iframe and parent page
6. Test with different opacity values (0, 0.01, 0.5) to confirm UI deception
7. Document pages that allow framing without protection

**Expected Output**: Clickjacking vulnerability report with affected pages and frame-bypass evidence

**Pass Criteria**:
- [ ] X-Frame-Options header checked on all pages
- [ ] CSP frame-ancestors directive evaluated
- [ ] Pages that load inside iframe documented
- [ ] Click events can reach framed application elements
- [ ] No framing protection on sensitive action pages confirmed as finding

## TC-BQ-008: WebSocket Security Analysis
**Objective**: Analyze WebSocket connections for authentication enforcement, data encryption, input validation, and sensitive data exposure in real-time communication channels
**Severity**: HIGH
**Prerequisites**: Headless browser installed, target application with WebSocket endpoints, network interception configured

**Remediation**: Authenticate WebSocket connections using token-based auth during handshake; validate and sanitize all incoming WebSocket messages server-side; implement rate limiting on message frequency; use wss:// (WebSocket Secure) exclusively; avoid sending sensitive data in cleartext over WebSocket frames

**Steps**:
1. Navigate to application pages that use WebSocket connections
2. Intercept WebSocket handshake via `page.on("websocket")`
3. Capture all WebSocket frames (sent and received) over a 60-second session
4. Analyze frame content for sensitive data (tokens, credentials, personal information)
5. Test authentication by connecting to the WebSocket endpoint without session cookies:
   ```python
   import websockets
   async with websockets.connect("wss://target.example.com/ws") as ws:
       await ws.send('{"action": "get_user_data"}')
       response = await ws.recv()
   ```
6. Inject malformed and oversized messages to test input validation
7. Test Origin header validation by connecting from a different origin
8. Document all findings with frame captures

**Expected Output**: WebSocket security report with authentication status, data exposure analysis, and injection test results

**Pass Criteria**:
- [ ] WebSocket connection URL and protocol documented (ws:// vs wss://)
- [ ] Authentication enforced on WebSocket handshake
- [ ] No sensitive data transmitted in cleartext over frames
- [ ] Malformed message injection handled gracefully (no crash/error leak)
- [ ] Origin validation prevents cross-origin WebSocket connections

## TC-BQ-009: Service Worker Security Testing
**Objective**: Enumerate registered service workers, analyze their scope and permissions, test for scope escalation, and verify that service workers cannot intercept requests from different origins or access sensitive APIs without proper restrictions
**Severity**: MEDIUM
**Prerequisites**: Headless browser installed, target application with HTTPS, browser DevTools Protocol access for ServiceWorker inspection

**Remediation**: Restrict service worker scope to the minimum necessary path; validate all fetch events within the service worker; avoid caching sensitive responses (authentication tokens, personal data); implement proper Cache-Control headers to prevent sensitive page caching; use ServiceWorker-Allowed header only when absolutely necessary

**Steps**:
1. Navigate to the target application and enumerate registered service workers:
   ```javascript
   const registrations = await navigator.serviceWorker.getRegistrations();
   for (const reg of registrations) {
       console.log(`Scope: ${reg.scope}, State: ${reg.active?.state}`);
   }
   ```
2. Check service worker scope against the application's URL structure
3. Intercept fetch events handled by the service worker:
   ```javascript
   await page.evaluate(() => {
       navigator.serviceWorker.addEventListener('message', (event) => {
           console.log('SW Message:', JSON.stringify(event.data));
       });
   });
   ```
4. Test if the service worker can be registered on a broader scope than intended
5. Check cached responses for sensitive data:
   ```javascript
   const cacheNames = await caches.keys();
   for (const name of cacheNames) {
       const cache = await caches.open(name);
       const requests = await cache.keys();
       // Check each cached response for sensitive headers/data
   }
   ```
6. Test if a malicious page can register a service worker on overlapping scope
7. Verify Cache-Control headers on responses served by the service worker

**Expected Output**: Service worker audit report with scope analysis, cached data inventory, and permission assessment

**Pass Criteria**:
- [ ] All registered service workers enumerated with scope and state
- [ ] Service worker scope limited to necessary application paths
- [ ] Cached responses do not contain sensitive authentication tokens or personal data
- [ ] Scope escalation attempts fail (cannot register on broader path)
- [ ] Cache-Control headers properly set on SW-cached responses

## TC-BQ-010: Browser Storage Security Audit
**Objective**: Audit all browser storage mechanisms (localStorage, sessionStorage, IndexedDB, Cache API) for sensitive data storage, proper cleanup on logout, and cross-origin access protections
**Severity**: MEDIUM
**Prerequisites**: Headless browser installed, target application with authenticated session, application logout functionality available

**Remediation**: Never store sensitive data (tokens, passwords, PII) in localStorage or sessionStorage; use HttpOnly cookies for session management; clear all storage on logout; encrypt any data stored client-side; implement storage event listeners to detect unauthorized access; use IndexedDB only for non-sensitive offline data

**Steps**:
1. Authenticate to the application and navigate through key pages
2. Extract all localStorage entries:
   ```javascript
   const ls = Object.fromEntries(
     Object.keys(localStorage).map(k => [k, localStorage.getItem(k)])
   );
   ```
3. Extract all sessionStorage entries similarly
4. Enumerate IndexedDB databases and extract stored records:
   ```javascript
   const dbs = await indexedDB.databases();
   for (const db of dbs) {
       console.log(`DB: ${db.name}, Version: ${db.version}`);
   }
   ```
5. Search all stored data for sensitive patterns (tokens, passwords, emails, API keys, PII)
6. Perform logout action and re-check all storage mechanisms
7. Verify that authentication tokens are removed from storage after logout
8. Test if stored data persists across browser sessions (close and reopen)
9. Check if any storage data is accessible from subdomains or different origins

**Expected Output**: Browser storage audit report with data inventory, sensitive findings, and logout cleanup verification

**Pass Criteria**:
- [ ] All localStorage and sessionStorage entries catalogued
- [ ] IndexedDB databases enumerated with stored data types
- [ ] No plaintext passwords or session tokens found in browser storage
- [ ] All storage cleared on logout (localStorage, sessionStorage, IndexedDB)
- [ ] Storage data does not persist authentication state across sessions
