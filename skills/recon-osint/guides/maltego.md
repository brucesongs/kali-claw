# Maltego - OSINTandforensicsApplication

**Learningwhen interval**: 2026-03-16
**Tool Purpose**: OSINTAnalysisandforensics
**Status**: 🟡 Learning

---

## 🎯 Tool Introduction

Maltego isaclausepowerful OSINT（OSINT）andforensicsApplicationprocess序，itProvides acan viewize informationAnalysisplatform，helpUserThrougheachkinddata sourcesandtransformcomecollect、AnalysisandLink Information。Maltego mainused forSecuritytune查、NetworkintelligenceAnalysisanddigital forensics。

### mainFunction
- can viewizeinformationAnalysisandrelated
- rich transform（Transform）library
- multipleintegration data sources（Whois、Shodan、DNS、Social Mediaetc.）
- quick diagramtableGenerationandExport
- collaborationFunctionandReportGeneration
- Supportsfromdefinitiontransformanddata sources

---

## 🚀 basic UseMethod

### start Maltego
```bash
maltego
```

### GUI Operation Flow
1. **Create New Graph**: File → New Graph
2. **Add Entity**: indiagramon右键 → Add Entity → Choose Entity Type
3. **Run Transform**: selectinentity → Right-click → Run Transform → Choose Transform
4. **Link Information**: viewtransformResult，拖拽relatedentitytodiagramon
5. **AnalysisNetwork**: Usediagramcomeunderstandinformationofinterval related
6. **ExportResult**: File → Export → Choose Format

---

## 📊 Common Entity Types

### Basic Entities
- **Domain**: domain nameInformation Gathering
- **IP Address**: IP addressInformation Gathering
- **Person**: person物Information Gathering
- **Email Address**: electricsubEmailInformation Gathering

### Advanced Entities
- **Website**: WebsiteInformation Gathering
- **File**: File Information and Download
- **Company**: companyInformation Gathering
- **Phone Number**: phone numberInformation Gathering

---

## 🔍 Example Usage

### simpleInformation Gathering
```bash
maltego
```
1. Create New Graph
2. Search and Add Domain entity
3. Enter "example.com"
4. Right-click Entity → Run Transform → To DNS Names
5. viewResultandcontinuecontinueitsothertransform

### Domain Analysis
```bash
maltego
```
1. add Domain entity: example.com
2. Run Transform: To DNS Names
3. Run Transform: To DNS Name To IP Address
4. Run Transform: To IP Address To AS Number
5. Run Transform: To AS Number To IP Address Range

---

## 📈 Learning Progress

### Completed
- [x] Understand basic tool concepts
- [x] Understand basic concepts of entities and transforms
- [x] Learn tool interface layout

### To Do
- [ ] Learningsuch as whatInstallationandConfigurationtransform
- [ ] Practice entity operations and transform execution
- [ ] Learningsuch as whatUse Maltego performcomplex intelligenceAnalysis
- [ ] Learningsuch as whatExportandpart享Result

---

## 🎯 Next Stepplan

1. Complete Maltego initial setup and configuration
2. Learningsuch as whatUsetransformlibrary
3. performsimple Domain Analysispractice
4. Learn how to create custom transforms

---

**Last Updated**: 2026-03-16 23:59 CST
