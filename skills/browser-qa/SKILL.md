# Browser QA

## Skill Identity

| Attribute | Value |
|-----------|-------|
| Domain | Security Testing |
| Skill ID | browser-qa |
| Version | 1.0.0 |
| Hacker Laws | Law 1 (Know Your Battlefield), Law 3 (Intelligence Over Force) |
| Related Skills | api-security, web-xss, web-auth |

## Purpose

Automated browser-based security testing using Playwright and browser devtools. Interact with web applications as a user would — click, type, navigate — while monitoring network traffic, JavaScript execution, and DOM changes for security issues.

## Core Capabilities

1. **Automated Navigation**: Click links, fill forms, submit data
2. **Network Monitoring**: Capture HTTP requests/responses, detect API calls
3. **JavaScript Execution**: Run custom scripts in page context
4. **DOM Inspection**: Query selectors, extract data, detect XSS sinks
5. **Screenshot/Video**: Document findings visually

## Use Cases

- **Auth Flow Testing**: Test login, logout, session handling, password reset
- **CSRF Detection**: Check for CSRF tokens in state-changing requests
- **XSS Testing**: Submit payloads via forms and monitor DOM
- **Cookie Analysis**: Check HttpOnly, Secure, SameSite flags
- **Client-Side Security**: CSP headers, SRI, HTTPS enforcement

## Tools

- **Playwright**: Node.js/Python library for browser automation
- **Puppeteer**: Chrome-only automation (legacy)
- **Browser DevTools Protocol**: Direct CDP access for advanced use

## Methodology

1. **Baseline capture** — record clean network traffic and console logs before injecting payloads.
2. **Stateful navigation** — drive multi-step flows (login → dashboard → settings) so client-side state mirrors real users.
3. **Differential observation** — diff request/response pairs across attacker vs. victim contexts to surface authorization gaps.
4. **Evidence-first** — capture screenshots, HAR files, and DOM snapshots before mutating state further.

## Test Patterns

- **Headed vs. headless** — run smoke tests headless for speed, but switch to headed mode for tricky DOM races and anti-bot heuristics.
- **Storage isolation** — use Playwright's `browserContext` per test to avoid cookie/localStorage cross-contamination.
- **Request interception** — `page.route()` to mock responses, inject delays, or replay captured payloads deterministically.
- **CDP escape hatch** — drop to `client.send('Network.setExtraHTTPHeaders', ...)` for headers Playwright's API doesn't expose.

## Anti-Detection Considerations

- Default Playwright fingerprints (navigator.webdriver, missing Chrome runtime fields) are trivially detected; use stealth patches for realistic testing.
- Mouse-movement simulation matters for CAPTCHA-protected flows — synthesize trajectories, not just instant clicks.
- TLS fingerprinting (JA3) leaks Playwright's Chromium signature; route through a customized proxy if testing anti-bot defenses.
- Respect target's anti-bot policy in authorized engagements — log every detection event for the report.

## Common Pitfalls

- **Flaky selectors** — relying on auto-generated class names breaks across deployments; prefer `data-testid` or role-based selectors.
- **Timing assumptions** — `waitForTimeout` masks real race conditions; use `waitForResponse`/`waitForLoadState` instead.
- **Cookie leakage** — failing to clear storage between tests causes authenticated/unauthenticated flow confusion.
- **Silent JS errors** — without `page.on('pageerror')` listeners, CSP violations and client-side crashes go unnoticed.

## Authentication Testing

- Drive full login/logout/password-reset cycles with `page.fill()` + `page.click()` — avoid shortcuts that skip client-side validation.
- After authentication, verify session cookies carry correct flags (HttpOnly, Secure, SameSite=Strict/Lax).
- Test account lockout by iterating wrong credentials and checking for rate-limiting responses (HTTP 429 or progressive delays).
- Validate "remember me" tokens — long-lived cookies should be rotated on server-side, not static across sessions.

## Session and State Management

- Enumerate all client-side storage: localStorage, sessionStorage, IndexedDB, and cookies — each is a potential auth-data leak vector.
- Verify CSRF tokens are present in every state-changing request and are rotated per-request (not per-session).
- Test session fixation by injecting a known session ID before login and confirming the server issues a new one.
- Check logout invalidation: after logout, the old session cookie must not grant access (server-side revocation).

## Network Traffic Analysis

- Capture full HAR files during testing: `page.context().storageState()` for cookies, `page.route()` for request/response logging.
- Identify all XHR/fetch calls the application makes — hidden API endpoints often lack the same authz checks as page routes.
- Monitor for credential leakage in URLs (tokens in query strings) and referrer headers (sensitive paths leaked to third-party origins).
- Check for mixed content: HTTP subresources on HTTPS pages downgrade security guarantees.

## Reporting and Evidence

- Use `page.screenshot({ fullPage: true })` for every finding — full-page captures preserve context that viewport-only shots miss.
- Record video traces for complex multi-step exploits: `browser.newContext({ recordVideo: { dir: 'evidence/' } })`.
- Export console messages filtered by severity: `page.on('console', msg => { if (msg.type() === 'error') log(msg) })`.
- Generate HAR exports with `page.context().tracing.start()` and `tracing.stop({ path })` for complete request-level evidence.

## Advanced Techniques

- Combine Playwright with Burp Suite upstream proxy for passive traffic analysis while browser tests execute.
- Use `page.addScriptTag()` to inject custom monitoring hooks that log DOM mutations (MutationObserver) and network requests (PerformanceObserver).
- Parallelize independent test flows across multiple browser contexts for faster regression suites.

## Integration

- Use with **web-xss** skill for payload delivery
- Use with **api-security** skill to analyze intercepted API calls
- Use with **knowledge-ops** to store findings
