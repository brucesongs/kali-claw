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

## Integration

- Use with **web-xss** skill for payload delivery
- Use with **api-security** skill to analyze intercepted API calls
- Use with **knowledge-ops** to store findings
