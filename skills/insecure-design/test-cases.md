# Insecure Design Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases with severity ratings.

---

## Statistics

| Category | Count | Severity Distribution |
|------|------|-------------|
| A. Business Logic | 3 | CRITICAL x2, HIGH x1 |
| B. Race Conditions | 2 | CRITICAL x1, HIGH x1 |
| C. Asset Management | 2 | HIGH x1, MEDIUM x1 |
| D. Design Flaws | 3 | CRITICAL x1, HIGH x1, MEDIUM x1 |
| **Total** | **10** | **CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 0, INFO: 1** |

---

## A. Business Logic (3 cases)

### TC-BL-001: Workflow Step Bypass

| Attribute | Value |
|------|-----|
| **ID** | TC-BL-001 |
| **Name** | Workflow Step Bypass |
| **Severity** | CRITICAL |
| **Category** | Business Logic |
| **OWASP** | A06:2025 - Insecure Design |
| **Description** | bypassbusinessprocessin 必needStep（such as jumpoverpaymentdirectTriggershipping） |
| **Prerequisites** | havehasnormaluseraccountandeffective token |
| **Test Steps** | 1. createaneworder，Recordorder ID<br>2. notperformpaymentoperation<br>3. directtuneuseshippinginterface `POST /api/orders/{id}/ship`<br>4. Checkresponseiswhethersuccess |
| **Expected Results（vulnerabilityexists）** | HTTP 200 andorderstatuschangeas"already shipping" |
| **Expected Results（security ）** | HTTP 403/409 denyoperation，orderstatusnotchange |
| **Remediation** | backendforceVerifystatusmachine，shippingbeforemustexistsalready complete paymentRecord |

### TC-BL-002: Negative Amount / Value Manipulation

| Attribute | Value |
|------|-----|
| **ID** | TC-BL-002 |
| **Name** | Negative Amount / Value Manipulation |
| **Severity** | CRITICAL |
| **Category** | Business Logic |
| **OWASP** | A06:2025 - Insecure Design |
| **Description** | throughcommit负numberamountor零ValuebypasspaymentorObtainnotwhen利益 |
| **Prerequisites** | havehasnormaluseraccountandeffective token |
| **Test Steps** | 1. initiatetransferrequest，amount setas负number（such as -1000）<br>2. initiatechargeValuerequest，amount setas 0<br>3. Checkbalancechangeizeandexchange易Record |
| **Expected Results（vulnerabilityexists）** | 负numbertransfercause收clause方balanceincrease，or零Valueoperationgenerateabnormalstatus |
| **Expected Results（security ）** | serviceenddeny负numberand零Value，return 400 error |
| **Remediation** | serviceendforcechecksumamountmustas正numberandincombinemethodscopeinner |

### TC-BL-003: State Machine Illegal Transition

| Attribute | Value |
|------|-----|
| **ID** | TC-BL-003 |
| **Name** | State Machine Illegal Transition |
| **Severity** | HIGH |
| **Category** | Business Logic |
| **OWASP** | A06:2025 - Insecure Design |
| **Description** | willorder/worksingle/taskdirectfromnotcombinemethod beforeconfigurationstatustransformtoObjectivestatus |
| **Prerequisites** | havehasnormaluseraccountandeffective token |
| **Test Steps** | 1. createorder，statusas"pending payment"<br>2. directsend `PATCH /api/orders/{id}` request，body inset `status: completed`<br>3. Checkorderstatusiswhethersuccesschange |
| **Expected Results（vulnerabilityexists）** | orderstatusdirectchangeas"already complete"，jumpover paymentandshippingStep |
| **Expected Results（security ）** | serviceenddenyillegalstatustransform，return 409 error |
| **Remediation** | backendrealnowstrictly statusmachine，Definitioncombinemethod statustransformtable，denyall notintransformtablein change |

---

## B. Race Conditions (2 cases)

### TC-RC-001: Single-Item Double Purchase (TOCTOU)

| Attribute | Value |
|------|-----|
| **ID** | TC-RC-001 |
| **Name** | Single-Item Double Purchase (TOCTOU) |
| **Severity** | CRITICAL |
| **Category** | Race Conditions |
| **OWASP** | A06:2025 - Insecure Design |
| **Description** | whenlibrarystoreonlyhas 1 piecewhen ，throughconcurrentrequestletmultipleusersamewhen 购买success |
| **Prerequisites** | librarystoreas 1 限amountproduct；multipleuseraccount；竞态conditionTestscript |
| **Test Steps** | 1. Confirmproductlibrarystoreas 1<br>2. Use 50 concurrentlineprocess（barrier synchronous）samewhen send购买request<br>3. Checksuccessresponsenumberandactuallibrarystorechangeize |
| **Expected Results（vulnerabilityexists）** | successresponsenumber > 1，librarystorechangeas负number，multipleuserobtainsameaproduct |
| **Expected Results（security ）** | only 1 requestsuccess，its余returnlibrarystorenotenougherror |
| **Remediation** | Usedatabaserowlevel锁or乐观锁（version Field）保证operation originalsubity |

### TC-RC-002: Double Withdraw / Coupon Reuse

| Attribute | Value |
|------|-----|
| **ID** | TC-RC-002 |
| **Name** | Double Withdraw / Coupon Reuse |
| **Severity** | HIGH |
| **Category** | Race Conditions |
| **OWASP** | A06:2025 - Insecure Design |
| **Description** | throughconcurrentrequestrepeatUseatimeitycouponorrepeatextractnow |
| **Prerequisites** | aatimeitycouponcodeorextractnowinterface；竞态conditionTestscript |
| **Test Steps** | 1. Obtainatimeitycouponcode<br>2. Use 20 concurrentlineprocesssamewhen sendapplicationcouponrequest<br>3. Checkcouponbyapplication timenumberandmost终discountamount |
| **Expected Results（vulnerabilityexists）** | couponbymultipletimeapplication，discountamount远super预period |
| **Expected Results（security ）** | coupononlybyapplicationatime，follow-uprequestreturn"already Use"error |
| **Remediation** | indatabaselayer面Use唯aconstraintor幂etc.ity token preventrepeatoperation |

---

## C. Asset Management (2 cases)

### TC-AM-001: Exposed API Documentation and Debug Endpoints

| Attribute | Value |
|------|-----|
| **ID** | TC-AM-001 |
| **Name** | Exposed API Documentation and Debug Endpoints |
| **Severity** | HIGH |
| **Category** | Asset Management |
| **OWASP** | A06:2025 - Insecure Design |
| **Description** | productionenvironmentinexposure API documentation（Swagger/OpenAPI）、debugendpointorenvironmentConfigurefile |
| **Prerequisites** | Objectivesystem URL |
| **Test Steps** | 1. Scancommon documentationpath：`/swagger-ui.html`, `/api-docs`, `/openapi.json`, `/graphql`<br>2. Scandebugendpoint：`/debug`, `/actuator/env`, `/.env`<br>3. Checkeachpath HTTP statuscodeandresponseContent |
| **Expected Results（vulnerabilityexists）** | return HTTP 200 andContentcontains API documentationorsensitiveConfigureinformation |
| **Expected Results（security ）** | return 404 or 403，all debuganddocumentationendpointalready disable |
| **Remediation** | productionenvironmentremoveall documentationanddebugendpoint，orthroughaccesscontrollimitationasinternalnetwork |

### TC-AM-002: Deprecated API Version Still Active

| Attribute | Value |
|------|-----|
| **ID** | TC-AM-002 |
| **Name** | Deprecated API Version Still Active |
| **Severity** | MEDIUM |
| **Category** | Asset Management |
| **OWASP** | A06:2025 - Insecure Design |
| **Description** | oldversion API 仍然can accessandmissingcurrentversionin security fixcomplex |
| **Prerequisites** | already knowObjectiveexistsmultiple API version（v1, v2, v3） |
| **Test Steps** | 1. Enumerate API versionpath（`/api/v1/`, `/api/v2/`, `/api/v3/`）<br>2. foreachversionsendidentical sensitiverequest（such as administratoroperation）<br>3. than较eachversion responseandsecurity controlsdifference |
| **Expected Results（vulnerabilityexists）** | oldversion API missingauthentication、authorizationorinputVerifyetc.security controls |
| **Expected Results（security ）** | oldversion API return 410 (Gone) orall versiontoolhasconsistent security controls |
| **Remediation** | belowlineall already 弃use API version，oringatewaylayerunifiedrealimplementsecurity policy |

---

## D. Design Flaws (3 cases)

### TC-DF-001: Client-Side Security Control Reliance

| Attribute | Value |
|------|-----|
| **ID** | TC-DF-001 |
| **Name** | Client-Side Security Control Reliance |
| **Severity** | CRITICAL |
| **Category** | Design Flaws |
| **OWASP** | A06:2025 - Insecure Design |
| **Description** | security controlsonlyinfrontendrealnow，backendnot dophaseshouldVerify（such as hideby钮、JS checksum、hidden field 定price） |
| **Prerequisites** | Objectivesystemhasfrontendinterface；can use Burp Suite or curl directoperation API |
| **Test Steps** | 1. infrontendfindtobyhide managementsuccesscanorrestrictedoperation<br>2. throughdirecttuneuse API bypassfrontendlimitation<br>3. Attemptmodify hidden field in price格ordiscountparameter<br>4. commit JS already filter illegalinput |
| **Expected Results（vulnerabilityexists）** | backendacceptandExecutefrontendalready prohibit operationordata |
| **Expected Results（security ）** | backendindependentVerifyall operationpermissionanddatacombinemethodity，denyillegalrequest |
| **Remediation** | all security controlsmustinfrontendandbackenddouble重realnow，backendVerifyasauthoritysource |

### TC-DF-002: Implicit Trust Between Internal Services

| Attribute | Value |
|------|-----|
| **ID** | TC-DF-002 |
| **Name** | Implicit Trust Between Internal Services |
| **Severity** | HIGH |
| **Category** | Design Flaws |
| **OWASP** | A06:2025 - Insecure Design |
| **Description** | 微serviceintervalorinternal API tuneusenoconditioninformation任，lack ofauthenticationandauthorizationmechanism |
| **Prerequisites** | can accessinternalnetworkoralready Discoverinternal API endpoint |
| **Test Steps** | 1. Identify微serviceintervalcommunicationendpoint<br>2. directtuneuseinternal API，not携bandany authenticationinformation<br>3. CheckiswhetherreturnsensitivedataorExecuteprivilegeoperation |
| **Expected Results（vulnerabilityexists）** | internal API noneedauthenticationi.e.can accesssensitivedataorExecutemanagementoperation |
| **Expected Results（security ）** | internal API requirementserviceintervalauthentication（such as mTLS、JWT），denynot authorizationrequest |
| **Remediation** | realimplementzero trustarchitecture，all serviceintervalcommunicationUse mTLS orserviceidentity token |

### TC-DF-003: Missing Fail-Safe Default

| Attribute | Value |
|------|-----|
| **ID** | TC-DF-003 |
| **Name** | Missing Fail-Safe Default |
| **Severity** | MEDIUM |
| **Category** | Design Flaws |
| **OWASP** | A06:2025 - Insecure Design |
| **Description** | abnormalorerrorsituationbelowsystemdefaultallowandnondeny（such as permissionChecksuperwhen when defaultallowsaccess） |
| **Prerequisites** | ObjectivesystemhaspermissionCheckorexternaldependency（such as Redis cacheused forpermission） |
| **Test Steps** | 1. 制造externaldependencyfault（such as let Redis superwhen ）<br>2. inabnormalstatusbelowsendrequirespermissionCheck request<br>3. 制造formaterror token orpermissiondata<br>4. Checksystemisdenyalsoisallow |
| **Expected Results（vulnerabilityexists）** | abnormalwhen systemallowrequest，return 200 andnondeny |
| **Expected Results（security ）** | abnormalwhen systemdefaultdenyaccess，return 403 or 500 |
| **Remediation** | all security relatedCheckinabnormalwhen defaultdeny（fail-closed），realnow断pathtoolmode |

---

## Severity Definitions

| Level | Meaning | Typical Impact |
|------|------|----------|
| CRITICAL | can causesystemcomplete沦陷or重large财务损失 | 免费Obtainproduct、资金盗retrieve、completebypassauthentication |
| HIGH | can causedataleakageorseverebusiness logicbypass | 越authorityaccess、repeatUseatimeityresource、internalserviceexposure |
| MEDIUM | can causehas限 security impact | informationleakage、old版 API vulnerability、downgradelevelattack |
| LOW | lightweight微security problem | informationityDiscover、bestpractice偏差 |
| INFO | informationityDiscover，nodirectsecurity impact | architectureimproverecommend、documentationsupplement |
