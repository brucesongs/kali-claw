# Photon - quick OSINTcrawler

**Learningwhen interval**: 2026-03-16
**Tool Purpose**: Web contentcollectandOSINTobtain
**Status**: 🟡 Learning

---

## 🎯 Tool Introduction

Photon isaclausequick andFunctionpowerful OSINT（OSINT）crawler，specializedasquick andcomplete 地captureretrieveWebsitecontentanddesign。itSupportsmulti-threadedcrawl、Subdomain Enumeration、linkDiscovery、Filedownloadetc.Function，isperformWebsitereconnaissanceandInformation Gathering ImportantTool。

### mainFunction
- quick multi-threadedWebsitecrawl
- Subdomain EnumerationandDiscovery
- all linkExtract（includingJavaScriptlink）
- common Filedownload（PDF、DOC、XLS、PPTetc.）
- formDetection
- PasswordFieldanditsotherSensitive InformationDiscovery
- SupportsfromdefinitionUserproxyandproxy
- OutputtoJSON、CSVandTXTformat

---

## 🚀 basic UseMethod

### Simple Scan
```bash
photon -u http://example.com
```

### Detailed Scan
```bash
photon -u http://example.com -t 50 -o /home/user/photon-output
```

---

## 📊 Common Options

### Scan Options
- `-u <url>`: Target URL
- `-t <threads>`: lineprocessnumber（default25）
- `-o <dir>`: Outputdirectory（default: /home/user/photon/Targetdomain name）

### Behavior Options
- `-e <extensions>`: 要download Fileextensionname（such as "pdf,doc,xls"）
- `-d <depth>`: crawldeepdegree（default2）
- `-c <crawl>`: fromdefinitioncrawlerbehavior（such as "--crawl 3"）

### Other Options
- `-p <proxy>`: UseproxyServer（such as "http://127.0.0.1:8080"）
- `-a <agent>`: UsefromdefinitionUserproxy
- `-s <timeout>`: Requestsuperwhen （seconds）
- `-r <retries>`: Requestfailurewhen 重testtimenumber（default0）

---

## 🔍 Example Usage

### Simple Crawl
```bash
photon -u http://testphp.vulnweb.com
```

### Detailed Crawl
```bash
photon -u http://testphp.vulnweb.com -t 50 -o /home/parallels/photon-testphp -d 3
```

### Download Files
```bash
photon -u http://testphp.vulnweb.com -e pdf,doc,xls,ppt
```

### Useproxy
```bash
photon -u http://testphp.vulnweb.com -p http://127.0.0.1:8080
```

---

## 📈 Learning Progress

### Completed
- [x] Toolbasic UseMethod
- [x] Common Optionsandparameter
- [x] LearningExample Usage

### To Do
- [ ] Practical Drills and Testing
- [ ] Learningadvanced Usetips
- [ ] anditsotherToolcoordinateUse

---

## 🎯 Next Stepplan

1. Test photon basic Function
2. Use photon crawlTestWebsite
3. Analysis photon OutputResult
4. Learningsuch as whatanditsotherToolcoordinateUse

---

**Last Updated**: 2026-03-16 23:58 CST
