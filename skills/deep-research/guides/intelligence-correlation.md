# Intelligence Correlation Guide

> Guide for the deep-research skill — covers multi-source correlation, confidence scoring, entity relationships, and MITRE ATT&CK mapping.

## Overview

Phase 8 of deep research transforms raw findings from multiple sources into a coherent intelligence picture. The core challenge: same entities appear in different sources with different names, different levels of detail, and sometimes conflicting information. Correlation resolves this into a unified, confidence-scored view.

## Correlation Process

```
Source A (vendor report)  ──┐
Source B (security blog)  ──┼──→ Entity Extraction ──→ Dedup & Merge ──→ Confidence Scoring ──→ Relationship Mapping
Source C (MITRE ATT&CK)   ──┤
Source D (GitHub)          ──┘
```

## Step 1: Entity Extraction

Extract structured entities from unstructured text.

### Entity Types

| Entity Type | Pattern | Example |
|-------------|---------|---------|
| IP Address | `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b` | 192.168.1.100 |
| Domain | `\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b` | evil.example.com |
| SHA256 Hash | `\b[a-fA-F0-9]{64}\b` | a1b2c3d4... |
| CVE ID | `CVE-\d{4}-\d{4,}` | CVE-2026-12345 |
| MITRE Technique | `T\d{4}(?:\.\d{3})?` | T1059.001 |
| Threat Actor | Named entity (manual) | APT28, Lazarus Group |
| Malware Family | Named entity (manual) | Cobalt Strike, X-Agent |

### Extraction Script

```bash
extract_all_entities() {
  local file="$1"
  local prefix="$2"

  # Automated extraction
  grep -oP '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' "$file" | sort -u > "${prefix}_ips.txt"
  grep -oP '\b[a-fA-F0-9]{64}\b' "$file" | sort -u > "${prefix}_sha256.txt"
  grep -oP '\b[a-fA-F0-9]{40}\b' "$file" | sort -u > "${prefix}_sha1.txt"
  grep -oP '\b[a-fA-F0-9]{32}\b' "$file" | sort -u > "${prefix}_md5.txt"
  grep -oP 'CVE-\d{4}-\d{4,}' "$file" | sort -u > "${prefix}_cves.txt"
  grep -oP 'T\d{4}(?:\.\d{3})?' "$file" | sort -u > "${prefix}_techniques.txt"
  grep -oP 'https?://[^\s<>"'\'']+' "$file" | sort -u > "${prefix}_urls.txt"

  echo "Extracted entities to ${prefix}_*.txt"
}
```

## Step 2: Deduplication and Merging

### Cross-Source IOC Merge

```bash
# Merge IOCs from all sources, count overlap
merge_and_score() {
  local entity_type="$1"  # e.g., "ips", "sha256", "cves"

  # Collect from all sources
  cat source_*_${entity_type}.txt | sort | uniq -c | sort -rn > merged_${entity_type}.txt

  # Format: count, entity
  # Higher count = appears in more sources = higher confidence
}

merge_and_score "ips"
merge_and_score "sha256"
merge_and_score "cves"
```

### Alias Resolution

Threat actors and malware families have multiple names across vendors.

```
# Common alias mappings
APT28 = Fancy Bear = Sofacy = Sednit = Pawn Storm = Strontium = Forest Blizzard
APT29 = Cozy Bear = The Dukes = Nobelium = Midnight Blizzard
Lazarus Group = Hidden Cobra = Zinc = Diamond Sleet
APT41 = Double Dragon = Barium = Wicked Panda

# When merging, normalize to one canonical name
# Use MITRE ATT&CK group ID as the stable identifier (e.g., G0007 for APT28)
```

## Step 3: Confidence Scoring

### Scoring Framework

| Score | Label | Criteria |
|-------|-------|----------|
| 5 | **CONFIRMED** | 3+ authoritative sources independently confirm; direct evidence |
| 4 | **HIGH** | 2 authoritative sources confirm; strong corroboration |
| 3 | **MEDIUM** | 1 authoritative + 1 non-authoritative; or 2 non-authoritative |
| 2 | **LOW** | Single source; or claim from non-authoritative source |
| 1 | **UNVERIFIED** | Rumor, single anonymous claim, or unattributed data |

### Source Authority Tiers

| Tier | Source Type | Examples |
|------|-----------|----------|
| **Tier 1** (Authoritative) | Government advisories, vendor security teams | CISA, NVD, Microsoft MSRC, Google Project Zero |
| **Tier 2** (Professional) | Security research firms, threat intel companies | CrowdStrike, Mandiant, Recorded Future |
| **Tier 3** (Community) | Security blogs, conference talks | Personal blogs, DEF CON talks, Reddit /r/netsec |
| **Tier 4** (Unverified) | Anonymous posts, dark web forums | Pastebin, dark web market listings |

### Confidence Calculation

```
For each claim or IOC:
  source_count = number of independent sources confirming
  max_tier = highest authority tier among confirming sources
  recency = age of most recent confirmation

  if source_count >= 3 and max_tier <= 2: confidence = CONFIRMED
  elif source_count >= 2 and max_tier <= 2: confidence = HIGH
  elif source_count >= 2 or max_tier == 1: confidence = MEDIUM
  elif source_count == 1 and max_tier <= 3: confidence = LOW
  else: confidence = UNVERIFIED

  # Decay: reduce confidence by 1 level if oldest source is > 12 months old
```

## Step 4: Entity Relationship Mapping

### Core Relationship Model

```
Threat Actor ──uses──→ Malware Family
     │                      │
     │                      ├──communicates_with──→ C2 Domain/IP
     │                      │
     │                      └──identified_by──→ Hash (SHA256)
     │
     ├──targets──→ Industry/Organization
     │
     ├──exploits──→ Vulnerability (CVE)
     │                  │
     │                  └──affects──→ Software/Technology
     │
     └──employs──→ Technique (MITRE ATT&CK ID)
                       │
                       └──detected_by──→ Detection Rule (Sigma/YARA)
```

### Building the Relationship Map

```markdown
## Entity Relationship Summary

### Threat Actor: APT28 (G0007)
- **Aliases**: Fancy Bear, Sofacy, Forest Blizzard [CONFIRMED]
- **Uses malware**: X-Agent, X-Tunnel, Zebrocy [HIGH]
- **Targets**: Government, military, media in NATO countries [CONFIRMED]
- **Exploits**: CVE-2026-XXXXX (Outlook), CVE-2025-YYYYY (Exchange) [HIGH]
- **Techniques**: T1566.001 (Spearphishing), T1078 (Valid Accounts), T1071 (Application Layer Protocol) [CONFIRMED]
- **C2 Infrastructure**: [list of domains/IPs with confidence scores]

### Connections
- X-Agent hash ABC123 → C2 domain evil.example[.]com [HIGH]
- evil.example[.]com resolves to 198.51.100.1 [CONFIRMED]
- 198.51.100.1 also hosts other-evil[.]com [MEDIUM]
- other-evil[.]com linked to campaign XYZ [LOW - single source]
```

## Step 5: MITRE ATT&CK Integration

### Technique Coverage Analysis

```bash
# Given a list of observed technique IDs
observed="T1059.001,T1053.005,T1078,T1071.001,T1566.001"

# Identify ATT&CK tactic coverage
# Execution: T1059.001 ✓
# Persistence: T1053.005 ✓
# Defense Evasion: (none observed)  ← GAP
# Credential Access: (none observed) ← GAP
# Lateral Movement: (none observed)  ← GAP
# C2: T1071.001 ✓
# Initial Access: T1566.001 ✓
```

### Gap Analysis

Tactics without observed techniques suggest either:
1. **Detection gap**: the actor uses techniques in this tactic but we haven't observed them
2. **Actual gap**: the actor doesn't operate in this tactic (less likely for mature APTs)

Prioritize detection engineering for gap tactics.

## Correlation Report Template

```markdown
# Intelligence Correlation Report
*Sources analyzed: [N] | Entities extracted: [N] | Period: [dates]*

## Confidence Summary
| Level | Count |
|-------|-------|
| CONFIRMED | X |
| HIGH | X |
| MEDIUM | X |
| LOW | X |
| UNVERIFIED | X |

## Key Correlated Findings
1. [Finding with confidence level and source count]
2. [Finding]

## Entity Relationships
[Relationship map as described above]

## ATT&CK Coverage
[Tactic coverage with gaps identified]

## Intelligence Gaps
- [What we don't know yet]
- [Suggested follow-up research]

## Sources
[Full source list with authority tier]
```
