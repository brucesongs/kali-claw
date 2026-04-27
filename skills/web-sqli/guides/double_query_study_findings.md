# Double Query Injection Learning Summary

## 🔍 practiceDiscovery

### problem诊断
**SQLi-Labs Less-5 TestResult**:
- ✅ injection pointexists：single quoteclosure
- ❌ extractvalue()/updatexml() in Web Environmentinnoterror
- ✅ floor()+rand()+group by inCommandrowincan use
- ❌ Web Environmentin SQL errorcause HTTP 500，Error Messagenot display

### originalbecauseAnalysis
1. **extractvalue()/updatexml() problem**:
 - MySQL somesomeversionin，whenparameterContainssubquerywhen return NULL andnoterror
 - onlyhasdirecttransmitinputillegal XPATH stringwhen 才triggererror

2. **Web Environmentlimitation**:
 - PHP error_reporting(0) disable errordisplay
 - SQL errorcausescriptabnormal退output（HTTP 500）
 - mysqli_error() Outputbyhide

3. **floor()+rand() Method**:
 - CommandrowTestsuccess：`Duplicate entry 'security1'`
 - Web Environmentintrigger HTTP 500 error

---

## 💡 correct LearningMethod

### Method 1: modify PHP Configurationdisplayerror
```php
// 在 Less-5/index.php 中添加
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
```

### Method 2: UseitsotherEnvironmentTest
- local MySQL CommandrowVerificationPrinciple
- Usespecialized门 Error-based injectionTestEnvironment
- Use DVWA、Pikachu etc.lab environment

### Method 3: Practicein Error-based injection
**suitableuseScenario**:
- Error Messagedirectdisplayinpage
- HTTP ResponseinContainsdetailed error
- logFilecan Access

**oftenuse Payload**:
```sql
-- extractvalue()
' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+

-- updatexml()
' and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--+

-- floor()+rand()
' and (select 1 from(select count(*),concat((select database()),floor(rand(0)*2))x from information_schema.tables group by x)a)--+

-- exp()
' and exp(~(select * from(select database())a))--+
```

---

## 🎯 PracticeApplicationRecommendation

### 1. judgeiswhetherSupportsError-based injection
- commitsingle quote，observeiswhetherhas SQL Error Message
- Check HTTP Responsecodeanderrorpage
- viewpagesource codein Error Message

### 2. selectappropriate errorfunction
- **MySQL 5.1+**: extractvalue()、updatexml()
- **MySQL 5.5+**: exp()
- **general**: floor()+rand()+group by

### 3. bypassfilter
- keywordfilter：Usemixed case、encoding
- functionfilter：attemptitsothererrorfunction
- lengthdegreelimitation：segmentExtractData

---

## 📚 recommendLearningresource

### Theorydeepize
1. MySQL Official Documentation：XML function、number学function
2. SQL injectionAttackandDefense（书籍）
3. OWASP Testing Guide - SQL Injection

### practiceplatform
1. DVWA (Damn Vulnerable Web App)
2. Pikachu Vulnerabilitylab environment
3. WebGoat
4. PortSwigger Web Security Academy

### ToolUse
1. sqlmap: `--technique=E` parameter
2. Burp Suite: Manual TestingAssistant
3. fromdefinition Python script

---

## 🚀 Next Steprowdynamicplan

### 立i.e.rowdynamic
1. ✅ understand Double Query injectionPrinciple
2. ✅ inCommandrowinVerificationeachkinderrorfunction
3. ✅ Identify Web Environmentin limitation
4. ⏭️ Configuration SQLi-Labs displayError Message
5. ⏭️ initsotherlab environmentinpracticeError-based injection

### deep research
1. research MySQL notsameversion difference
2. LearningitsotherDatabase Error-based injection（PostgreSQL、MSSQL）
3. developmentautomated Error-based injectionTool
4. summaryrealVulnerabilitycasein Error-based injectionexploit

---

**Learning Status**: 🟡 Theory Mastery，Requiresmoremultiplepractice
**Capabilitiesetc.level**: inlevel（understandPrinciple，RequiresPracticeVerification）
**Recommendation**: inSupportserrordisplay Environmentindeep exercise
