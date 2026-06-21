# Multi-Source Intelligence Synthesis Guide

> Hands-on methodology for triangulating findings across heterogeneous sources, scoring confidence, filtering bias, and producing defensible intelligence products. Walkthrough style — read end-to-end before applying to a live engagement.

---

## Introduction and Objective

### Why this guide exists

Deep research is rarely bottlenecked by *finding* information. Search engines return thousands of hits per query, CVE databases are exhaustively indexed, threat intelligence vendors publish daily, and forums generate terabytes of discussion. The bottleneck is **synthesis**: turning that firehose into a single coherent picture that a decision-maker can act on without second-guessing the source.

This guide focuses on the synthesis layer that sits between raw collection (covered in `payloads.md`) and report writing (covered in `SKILL.md` Phase 6). It is deliberately opinionated about:

- **Triangulation** — requiring multiple independent vectors before a claim becomes actionable
- **Confidence scoring** — turning "I think this is real" into a reproducible numeric verdict
- **Bias filtering** — stripping vendor marketing, ideological framing, and stale conventional wisdom
- **Citation chain verification** — chasing every claim back to its primary source rather than accepting aggregator restatements

Senior pentesters need this because their findings drive real-world decisions: patch now, isolate the host, escalate to CIRT, brief the CISO, file a regulator notification. Each of those decisions has a cost. Synthesis quality is what separates a research product that drives correct decisions from one that causes false alarms or, worse, missed incidents.

### What you will be able to do

After working through this guide you should be able to:

1. Decompose a research question into a triangulation plan with named source vectors.
2. Score the confidence of any individual claim using a transparent rubric.
3. Detect and discount common cognitive and commercial biases in security content.
4. Verify citation chains back to their primary origin, even when intermediate aggregators strip attribution.
5. Resolve contradictions between sources without resorting to "the loudest voice wins."
6. Produce a synthesis document that a reviewer can audit step by step.

### How this guide differs from sibling guides

| Guide | Focus | Output |
|-------|-------|--------|
| `iterative-search-patterns.md` | How to expand and contract search queries | A query log |
| `continuous-monitoring.md` | How to keep watching a topic over time | A monitoring pipeline |
| `intelligence-correlation.md` | How to link entities (IP, hash, CVE, actor) across sources | A correlation graph |
| `source-validation-guide.md` | How to score the credibility of one source | A credibility score |
| `mcp-integration.md` | How to wire MCP servers into the research loop | An MCP configuration |
| **`multi-source-synthesis-guide.md`** (this file) | **How to fuse everything into one defensible verdict** | **A synthesis product** |

Synthesis is the outer loop. The other guides produce inputs; this guide consumes them.

---

## Core Concept: The Triangulation Principle

### Definition

**Triangulation** is the practice of requiring evidence from at least three *independent* vectors before elevating a claim to "confirmed" status. The word *independent* is doing heavy lifting here — three blog posts that all cite the same vendor advisory count as one source, not three.

### The three vectors

A robust synthesis draws from at least one source in each of three categories:

1. **Authoritative vector** — NVD, MITRE ATT&CK, vendor PSIRT, CISA KEV, academic paper, court filing. These are the canonical records.
2. **Practitioner vector** — independent security firm blogs, conference talks (DEF CON, Black Hat, OffensiveCon), researcher Twitter/Mastodon threads, GitHub PoC repositories. These are the people doing the work.
3. **Community vector** — Reddit `/r/netsec`, HackerNews, StackOverflow, vendor support forums, Discord captures. These reflect how the issue manifests in the wild.

If a claim appears in only one vector, it stays at `LOW` confidence regardless of how authoritative that single vector is. NVD has been wrong before. Vendor advisories have understated severity. Researchers have retracted claims. Triangulation is the defense.

### Independence test

Before counting a source as independent, ask:

- Does this source cite the other sources I have already collected? If yes, it is a **derivative** source, not independent.
- Does this source share an author, employer, or funding source with another source I have? If yes, treat them as one.
- Did this source publish *before* or *after* the other sources? A post-publishing date close to another source's publication suggests derivation.

```python
from dataclasses import dataclass
from datetime import date

@dataclass(frozen=True)
class CollectedSource:
    name: str
    vector: str           # "authoritative" | "practitioner" | "community"
    url: str
    published_on: date
    cites: tuple[str, ...]   # URLs this source references
    author: str
    org: str

def independence_pairs(sources: list[CollectedSource]) -> list[tuple[str, str]]:
    """Return pairs of sources that should NOT be counted as independent."""
    pairs = []
    for i, a in enumerate(sources):
        for b in sources[i+1:]:
            same_org = a.org.lower() == b.org.lower() and a.org != ""
            a_cites_b = b.url in a.cites
            b_cites_a = a.url in b.cites
            same_author = a.author.lower() == b.author.lower() and a.author != ""
            if same_org or a_cites_b or b_cites_a or same_author:
                pairs.append((a.name, b.name))
    return pairs

def distinct_vector_count(sources: list[Collected_source]) -> set[str]:
    return {s.vector for s in sources}
```

The output of `independence_pairs` tells you which apparent corroborations to throw out before scoring confidence.

---

## Confidence Scoring Rubric

### The four-level scale

Every claim in a synthesis product carries one of four confidence levels. The rubric is mechanical so that two analysts reviewing the same evidence arrive at the same score.

| Level | Definition | Required Evidence | Example Use |
|-------|------------|-------------------|-------------|
| **CONFIRMED** | Verified, ready to drive action | 3+ independent sources across all 3 vectors, primary source located, no unresolved contradictions | "Patch CVE-2025-XXXX immediately — RCE confirmed, public PoC, CISA KEV listed" |
| **LIKELY** | Strong evidence, minor gap | 2+ independent sources across 2+ vectors, primary source located, contradictions resolved with explanation | "APT-XX likely uses this technique — vendor report + MITRE mapping, no independent PoC yet" |
| **POSSIBLE** | Plausible, needs more work | 1-2 sources, single vector coverage, or primary source not located | "This misconfiguration may lead to RCE — blog describes theory, no observed exploitation" |
| **UNVERIFIED** | Claim exists, cannot yet evaluate | Single source, no primary reference, contradictory authoritative sources | "Forum post claims 0-day, no CVE, no advisory, no corroboration" |

### Scoring worksheet

For each claim, fill in this worksheet before assigning a level:

```
Claim ID: C-014
Statement: "CVE-2025-XXXX is being actively exploited in the wild"

Authoritative vector sources (NVD, KEV, vendor):
  [ ] NVD: yes/no — notes
  [ ] CISA KEV: yes/no — added date
  [ ] Vendor PSIRT: yes/no — vendor name

Practitioner vector sources (researchers, firms):
  [ ] Vendor-independent research blog: yes/no — firm, date
  [ ] Conference talk: yes/no — venue, date
  [ ] PoC repository: yes/no — URL, stars, last commit

Community vector sources (forums, social):
  [ ] Forum/thread: yes/no — community, signal-to-noise
  [ ] Incident report: yes/no — sector, region

Independence check:
  [ ] Are any two sources co-published or co-cited? List pairs
  [ ] Are all sources post-event, or did one break the story?

Contradictions:
  [ ] List any sources that dispute the claim
  [ ] Resolution: how was the dispute adjudicated

Primary source:
  [ ] Located: yes/no — URL
  [ ] If no, what is the closest secondary

Confidence: [CONFIRMED | LIKELY | POSSIBLE | UNVERIFIED]
Rationale: one sentence citing the deciding factor
```

Storing these worksheets alongside the final synthesis product is what makes the product *auditable*. A reviewer who disagrees with the confidence verdict can point at the specific worksheet line where the evidence was characterized differently.

### Numeric confidence for automation

For pipeline use, the same rubric collapses to a 0-100 score:

```python
def confidence_score(sources: list[CollectedSource], primary_located: bool, contradictions_unresolved: int) -> int:
    distinct_vectors = len({s.vector for s in sources})
    independent_count = len(sources) - len(set(p[0] for p in independence_pairs(sources)))

    base = 0
    base += min(distinct_vectors, 3) * 15          # up to 45 for vector coverage
    base += min(independent_count, 5) * 5          # up to 25 for independent corroboration
    base += 15 if primary_located else 0           # 15 for primary source
    base += 15 if contradictions_unresolved == 0 else max(0, 15 - contradictions_unresolved * 5)
    return min(base, 100)

def label_for(score: int) -> str:
    if score >= 85: return "CONFIRMED"
    if score >= 65: return "LIKELY"
    if score >= 40: return "POSSIBLE"
    return "UNVERIFIED"
```

---

## Bias Filtering

### Why bias filtering matters

Security content is produced by people and organizations with incentives. A vendor selling an EDR product has every reason to amplify the severity of a technique that their product detects. A consultancy looking for clients in a specific sector has every reason to publish a report about threats to that sector. A researcher who built a tool has every reason to overstate the problem the tool solves.

This is not a accusation of bad faith — most of the time the bias is unconscious. But if a synthesis product simply aggregates what sources say, the bias propagates into the decisions the synthesis drives. Bias filtering is the discipline of asking "what does this source want me to believe, and would they benefit if I believed it?"

### The bias catalog

The following biases appear routinely in security research content. Each one has a tell — a pattern you can grep for or a question you can ask.

**Vendor commercial bias.** Source sells a product; the threat described is one the product mitigates. Tell: the write-up ends with a product recommendation or a demo link. Mitigation: subtract 0.15 from the source credibility score and require a non-vendor corroboration before accepting.

**Disclosed-but-not-exploited bias.** Source treats a CVE with public PoC as if it were being exploited in the wild. Tell: phrases like "researchers warn," "could allow," "potential for." Mitigation: require CISA KEV listing or incident report before treating as in-the-wild.

**Single-researcher echo.** Many secondary sources all trace back to one researcher's thread. Tell: all derivative posts link to the same tweet or blog. Mitigation: treat the entire cluster as a single source.

**Stale conventional wisdom.** Claim was accurate five years ago and has been repeated ever since, but the underlying facts changed. Tell: sources citing the claim all reference each other in a chain that bottoms out at an old (5+ years) primary. Mitigation: locate the primary source and check its date; if no recent corroboration exists, downgrade confidence.

**Ideological framing.** Threat is framed politically in a way that aligns the author with a government or political movement. Tell: heavy use of nation-state attribution without evidence, emotive language ("merciless," "nefarious," "hostile"). Mitigation: separate the technical claims (which may be valid) from the attribution claims (which may be speculation) and score them independently.

**Hype cycle bias.** A topic is fashionable and attracts coverage disproportionate to its actual impact. Tell: many sources published in a short window, all citing each other, with little new technical detail after the first wave. Mitigation: weight earlier primary sources over later aggregators.

### Bias detection script

```python
import re

VENDOR_TELLS = [
    r"our product",
    r"protected by",
    r"learn more about our",
    r"request a demo",
    r"\bfor enterprises\b",
]

HYPERBOLER_TELLS = [
    r"\bmassive\b",
    r"\bdevastating\b",
    r"\bunprecedented\b",
    r"\bmerciless\b",
    r"\bnefarious\b",
    r"\bsilent epidemic\b",
    r"\bcatastrophic\b",
]

STALENESS_TELLS = [
    r"\bin recent years\b",       # Often a sign of no specific recent event
    r"\btraditionally\b",
    r"\bhas long been\b",
]

def detect_bias(content: str) -> dict:
    """Flag bias indicators in a source's content."""
    text = content.lower()
    return {
        "vendor_signals": [t for t in VENDOR_TELLS if re.search(t, text)],
        "hyperbole": [t for t in HYPERBOLER_TELLS if re.search(t, text)],
        "staleness_phrases": [t for t in STALENESS_TELLS if re.search(t, text)],
    }

def bias_adjustment(flags: dict) -> float:
    """Return a credibility adjustment in [-0.3, 0]."""
    penalty = 0.0
    penalty += 0.15 * (len(flags["vendor_signals"]) > 0)
    penalty += 0.05 * min(len(flags["hyperbole"]), 3)
    penalty += 0.05 * min(len(flags["staleness_phrases"]), 2)
    return max(-penalty, -0.3)
```

### Bias-aware credibility scoring

Combine bias filtering with the credibility score from `source-validation-guide.md`:

```python
def bias_aware_credibility(source: Source, content: str) -> float:
    base = score_credibility(source)            # from source-validation-guide.md
    bias = bias_adjustment(detect_bias(content))
    return max(0.0, min(1.0, base + bias))
```

A NVD entry starts at 1.0 and stays there because it has no marketing language. A vendor blog starts at 0.6 and may drop to 0.45 if it asks the reader to request a demo. The numeric gap forces the synthesis to weigh the NVD entry more heavily.

---

## Citation Chain Verification

### The problem with aggregator restatement

A typical threat intelligence report looks like this: "Threat actor X uses technique Y to achieve Z." The report does not name a primary source. Another blog picks it up: "According to [report A], actor X uses technique Y." Three more blogs pick up the second one. Within a week, the claim has "broad support" across the industry.

But when you chase the chain back, every link cites another link, and the chain bottoms out at either (a) one original claim with no supporting evidence or (b) a misreading of an unrelated primary source. Citation chain verification is the discipline of always asking: "Where did this *originally* come from?"

### The chain-walk procedure

```bash
#!/bin/bash
# chain-walk.sh — Walk a claim back to its primary source
# Usage: ./chain-walk.sh <url> [depth]

URL="${1:?Usage: chain-walk.sh <url> [depth]}"
DEPTH="${2:-5}"
SEEN=()

walk() {
    local current="$1"
    local depth="$2"

    # Stop conditions
    [[ $depth -le 0 ]] && return
    for s in "${SEEN[@]}"; do [[ "$s" == "$current" ]] && return; done
    SEEN+=("$current")

    echo "[$depth] Inspecting: $current"

    # Fetch and look for outbound security-relevant citations
    local body
    body=$(curl -sL --max-time 15 "$current" 2>/dev/null)
    if [[ -z "$body" ]]; then
        echo "    (unreachable)"
        return
    fi

    # Extract likely primary references
    local refs
    refs=$(echo "$body" | grep -oE 'href="https?://[^"]+"' \
         | sed 's/href="//;s/"$//' \
         | grep -iE 'cve\.mitre|nvd\.nist|attack\.mitre|cisa\.gov|github\.com/advisories|first\.org|vendor security|/security/advisories|PSIRT' \
         | sort -u | head -5)

    if [[ -z "$refs" ]]; then
        echo "    -> NO PRIMARY REFERENCE FOUND (claim rests on aggregator)"
        # Look for any outbound citation as fallback
        local fallback
        fallback=$(echo "$body" | grep -oE 'href="https?://[^"]+"' \
                 | sed 's/href="//;s/"$//' \
                 | grep -viE "$(basename "$current")|twitter\.com|linkedin\.com|facebook\.com" \
                 | sort -u | head -3)
        if [[ -n "$fallback" ]]; then
            echo "    fallback citations:"
            echo "$fallback" | sed 's/^/      /'
        fi
        return
    fi

    while IFS= read -r ref; do
        echo "    primary candidate: $ref"
        walk "$ref" $((depth - 1))
    done <<< "$refs"
}

walk "$URL" "$DEPTH"
```

### Interpreting chain-walk output

The chain-walk output falls into one of three patterns:

**Clean chain.** The walk terminates at a vendor advisory, NVD entry, or MITRE page. The original claim is well-founded; carry it forward with high confidence.

**Self-referential cluster.** The walk bounces between blogs that all cite each other and never reaches a primary source. The claim is unsupported; downgrade confidence to `UNVERIFIED` and note the cluster in the worksheet.

**Mutated chain.** The walk reaches a primary source, but the primary source says something subtly different from what the aggregator claims. This is the most dangerous pattern — the claim *appears* well-sourced but the source has been restated. Document the mutation explicitly and re-score the claim based on what the primary source actually says.

---

## Contradiction Resolution

### When sources disagree

Sources disagree routinely. Severity estimates vary by 2 CVSS points. Affected version lists differ. Attribution claims conflict. A synthesis that papers over contradictions produces a confident-sounding report that collapses under cross-examination.

The right move is to surface contradictions explicitly and resolve them by weight, not by vote.

### Resolution procedure

1. **Tabulate the disagreement.** List each source's claim and the evidence it offers.
2. **Score source weight.** Use `bias_aware_credibility` from earlier in this guide.
3. **Check for primary.** Does any source link to a primary that resolves the question definitively?
4. **Check freshness.** For changing facts (exploit status, affected versions), prefer the most recent credible source.
5. **Adjudicate.** Pick the winner and document why. If the disagreement cannot be resolved, present both positions in the synthesis product rather than picking one.

```python
@dataclass(frozen=True)
class ContradictingClaim:
    statement: str
    positions: tuple[dict, ...]   # [{"source": ..., "claim": ..., "weight": ..., "evidence": ...}, ...]

def resolve(contradiction: ContradictingClaim) -> dict:
    positions = sorted(contradiction.positions, key=lambda p: p["weight"], reverse=True)
    top = positions[0]
    runner_up = positions[1] if len(positions) > 1 else None

    # If top weight is not clearly ahead, do not adjudicate
    if runner_up and (top["weight"] - runner_up["weight"]) < 0.15:
        return {
            "verdict": "unresolved",
            "note": "Insufficient weight differential; present both positions",
            "positions": positions,
        }

    return {
        "verdict": "resolved",
        "winner": top,
        "runner_up": runner_up,
        "rationale": f"{top['source']} outranks {runner_up['source'] if runner_up else 'others'} "
                     f"by weight {top['weight']:.2f} vs {runner_up['weight']:.2f if runner_up else 0:.2f}",
    }
```

### Common contradiction patterns

| Pattern | Example | Resolution |
|---------|---------|------------|
| Severity disagreement | NVD says 7.5, blog says 9.8 | Trust NVD unless blog shows NVD's score misweights a factor |
| Affected versions | Vendor says 1.x, PoC works on 2.x | Re-test in lab; trust observed PoC over vendor advisory for scope |
| Attribution | Vendor A says APT-28, vendor B says APT-29 | Present both; do not pick unless primary evidence (indictment, government advisory) exists |
| Exploit status | Forum says "0-day in the wild," vendor says "no reports" | Require KEV or incident report before treating as exploited |

---

## Synthesis Product Structure

### The synthesis product

The output of this whole process is not the same as a research report. The synthesis product is an *auditable* document that lets a reviewer trace every claim back to its evidence. It has these sections:

```
# Synthesis: [Topic]

## 1. Scope
Research questions investigated, sub-questions, time horizon, scope exclusions.

## 2. Evidence Inventory
Total sources collected, breakdown by vector, independence analysis, sources discarded as derivative.

## 3. Claims Register
Numbered list of every claim made in the synthesis, with confidence level and citation chain summary.

## 4. Contradictions Log
Every contradiction encountered and how it was resolved (or flagged as unresolved).

## 5. Bias Audit
Bias flags raised during analysis and the credibility adjustments applied.

## 6. Findings
The narrative product — this is what stakeholders read.

## 7. Open Questions
Claims that could not be resolved, follow-up research needed.

## 8. Provenance
Full citation list with role (primary, secondary, aggregator) and confidence contribution.
```

Sections 1-5 and 7-8 are not optional. They are what makes the synthesis defensible. Section 6 is the only section most consumers will read, but it cannot stand alone — every sentence in section 6 must trace back to a numbered claim in section 3.

### Minimal viable synthesis template

```markdown
# Synthesis: [Topic]

*Generated: [date] | Analyst: [name] | Confidence ceiling: [HIGH/MED/LOW]*

## 1. Scope
- Primary question: [the one-sentence question]
- Sub-questions:
  1. [sub-q 1]
  2. [sub-q 2]
  3. [sub-q 3]
- Time horizon: sources published between [start] and [end]
- Out of scope: [topics explicitly excluded]

## 2. Evidence Inventory
- Total sources: [N]
- Authoritative vector: [count] ([list])
- Practitioner vector: [count] ([list])
- Community vector: [count] ([list])
- Discarded as derivative: [count]
- Distinct independent sources: [count]

## 3. Claims Register
- C-001 [CONFIRMED] [statement] — primary: [url] — corroborated by: [urls]
- C-002 [LIKELY]   [statement] — primary: [url] — corroborated by: [url]
- C-003 [POSSIBLE] [statement] — primary: not located
- C-004 [UNVERIFIED] [statement] — single source: [url]

## 4. Contradictions Log
- D-001: [topic]. [Source A] says [X]; [Source B] says [Y]. Resolution: [rationale].

## 5. Bias Audit
- Source [S-003]: vendor commercial bias (-0.15) — adjusts credibility from 0.70 to 0.55
- Source [S-008]: hyperbole density (3 tells) — minor penalty

## 6. Findings
[Narrative. Each sentence ends with [C-XXX] referencing the claims register.]

## 7. Open Questions
- [OQ-1]: [question] — follow-up needed on [specific gap]

## 8. Provenance
| ID | URL | Role | Vector | Weight | Notes |
|----|-----|------|--------|--------|-------|
| S-001 | [url] | primary | authoritative | 0.95 | NVD entry |
| S-002 | [url] | primary | practitioner | 0.80 | researcher blog |
| ... | ... | ... | ... | ... | ... |
```

---

## Hands-on Practice: CVE Synthesis Walkthrough

Let us walk through a complete synthesis using a hypothetical but realistic scenario.

### Scenario

You have been asked: "Is CVE-2025-XXXX being actively exploited in the wild, and should we patch out-of-cycle?"

### Step 1: Decompose into sub-questions

```
Primary question: Is CVE-2025-XXXX being actively exploited?
Sub-questions:
  SQ-1: What does the vendor advisory say about exploitation status?
  SQ-2: Is the CVE listed in CISA KEV?
  SQ-3: Are there public PoCs, and what is their quality?
  SQ-4: Are there incident reports from independent firms?
  SQ-5: What is the community signal (forums, social) about active exploitation?
```

### Step 2: Plan the collection

For each sub-question, identify which vector will answer it:

```
SQ-1 -> authoritative (vendor PSIRT)
SQ-2 -> authoritative (CISA KEV)
SQ-3 -> practitioner (GitHub, Exploit-DB)
SQ-4 -> practitioner (security firm blogs)
SQ-5 -> community (Reddit, forums)
```

### Step 3: Collect

```bash
# SQ-1: Vendor advisory
curl -sL "https://REPLACE_WITH_YOUR_VENDOR/psirt/advisory/CVE-2025-XXXX" \
  | grep -iE "exploit|active|in.the.wild|kev"

# SQ-2: CISA KEV
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  | jq '.vulnerabilities[] | select(.cveID == "CVE-2025-XXXX")'

# SQ-3: PoC search
gh search code "CVE-2025-XXXX" --limit 20
searchsploit "CVE-2025-XXXX"

# SQ-4: Security firm coverage
# Use search engines: "CVE-2025-XXXX" analysis (site:REPLACE_WITH_YOUR_FIRM_OR_ANY_SECURITY_BLOG)

# SQ-5: Community signal
# "CVE-2025-XXXX" site:reddit.com/r/netsec
# "CVE-2025-XXXX" exploit observed
```

### Step 4: Build the evidence inventory

Suppose you collected:

```
Authoritative:
  S-001: Vendor PSIRT advisory (weight: 0.90)
  S-002: NVD entry (weight: 1.00)
  S-003: CISA KEV — NOT LISTED (weight: 1.00, negative evidence)

Practitioner:
  S-004: Vendor-independent research blog with PoC (weight: 0.80)
  S-005: GitHub PoC repository (weight: 0.70)
  S-006: EDR vendor blog recommending their product (weight: 0.55 after bias adjustment)

Community:
  S-007: Reddit /r/netsec thread, mixed signal (weight: 0.40)
  S-008: Forum post claiming exploitation (weight: 0.30, single source)
```

### Step 5: Independence check

```
S-005 and S-004: independent (different authors, S-005 does not cite S-004)
S-006 cites S-004: derivative — do not double-count
S-007 cites S-005: derivative — do not double-count
S-008 cites S-007: derivative — do not double-count

Effective distinct sources: S-001, S-002, S-003, S-004, S-005
```

### Step 6: Run chain-walk on the exploitation claim

```bash
./chain-walk.sh "https://REPLACE_WITH_YOUR_FORUM_URL/post/CVE-2025-XXXX-exploited" 5
```

Suppose the walk reaches the forum post, which cites a Reddit thread, which cites a Twitter thread, which makes the original claim without evidence. The chain terminates at a single tweet. Primary source: not located. Mutation: claim escalates from "PoC published" to "exploited in the wild" across the chain.

### Step 7: Score the claim

```python
sources_for_claim = [S-001, S-002, S-003, S-004, S-005, S-008]
primary_located = False
contradictions_unresolved = 1   # S-003 says not in KEV vs S-008 says exploited

score = confidence_score(sources_for_claim, primary_located, contradictions_unresolved)
# distinct_vectors: authoritative + practitioner + community = 3 -> 45
# independent_count: 5 -> 25
# primary_located: False -> 0
# contradictions_unresolved: 1 -> 10
# total = 80 -> LIKELY
```

But wait — we should adjust because `S-003` (CISA KEV not listing) is strong negative evidence. Re-running with that explicit:

```python
# Recompute treating "KEV does not list" as contradictory authoritative
contradictions_unresolved = 2
score = 45 + 25 + 0 + 5 = 75 -> LIKELY (low end)
```

### Step 8: Adjudicate

The synthesis says: PoC exists, KEV does not list, no incident reports from independent firms, community signal exists but traces to a single tweet. **Verdict: POSSIBLE, not CONFIRMED.** Patch on normal cycle unless business context (high-value target, internet-exposed) raises priority.

This is a much more defensible answer than "Reddit says it is being exploited, patch now."

---

## Anti-Patterns to Avoid

### Aggregation without verification

"I found 10 sources that all say X" — but they all cite the same primary, which is shaky. Count primary sources, not aggregators.

### Vendor-weighted scoring

A vendor's white paper is not authoritative for the threat it is selling protection against. Treat vendor content as practitioner vector with a mandatory bias adjustment.

### Recency worship

The most recent source is not automatically the most correct. For static facts (protocol behavior, cryptographic primitives), older primary sources remain authoritative. Reserve recency preference for changing facts (exploit status, affected version lists).

### Confidence inflation

Reviewers tend to round POSSIBLE up to LIKELY and LIKELY up to CONFIRMED under deadline pressure. The numeric rubric exists to make this rounding visible. If a claim is POSSIBLE, write POSSIBLE — do not let the narrative drift toward CONFIRMED in section 6.

### Single-source amplification

A single high-quality source can be correct. But the synthesis must mark it as single-source and refuse to elevate to CONFIRMED no matter how authoritative the single source is. NVD entries have been wrong. CISA KEV has been wrong. Vendor advisories have been wrong. Triangulation is non-negotiable.

---

## Quality Checklist for Synthesis Products

Before delivering a synthesis product, confirm:

- [ ] Every claim in section 6 traces to a numbered claim in the claims register (section 3)
- [ ] Every claim in section 3 has a confidence level assigned via the rubric
- [ ] Independence check has been performed and derivative sources marked
- [ ] Citation chain has been walked for any CONFIRMED claim
- [ ] Bias audit has been performed for every practitioner and community source
- [ ] Contradictions are logged in section 4 with explicit resolutions
- [ ] Open questions are listed honestly — no known gaps are hidden
- [ ] Provenance table is complete with weights and roles

A synthesis product that passes this checklist will withstand review by a second analyst. One that does not will collapse under the first hard question.

---

## Integration with Sibling Guides

This guide is the outer synthesis loop. It consumes outputs from the other guides:

- **From `iterative-search-patterns.md`**: the queries that produced the source pool
- **From `continuous-monitoring.md`**: the time-series of detections that inform confidence over time
- **From `intelligence-correlation.md`**: the entity graph that links IOCs to campaigns and actors
- **From `source-validation-guide.md`**: the per-source credibility scores that feed `bias_aware_credibility`
- **From `mcp-integration.md`**: the automation hooks that pull sources into the pipeline

When all five are wired together, the synthesis loop runs continuously: collection feeds scoring, scoring feeds synthesis, synthesis surfaces gaps that drive new collection. The result is a research product that improves over time rather than degrading as sources go stale.

---

## References and Further Reading

- **Sherman Kent School**: classic CIA analytic tradecraft — the origin of confidence language like "likely" and "almost certainly"
- **Heuer, R. J.**: *Psychology of Intelligence Analysis* — bias catalog and structured analytic techniques
- **FIRST.org**: CVSS, EPSS, and SSVC scoring frameworks that complement the confidence rubric here
- **CISA KEV**: Known Exploited Vulnerabilities catalog — primary authoritative source for in-the-wild exploitation
- **MITRE ATT&CK**: adversary behavior reference — primary authoritative source for technique attribution
- **NIST NVD**: National Vulnerability Database — primary authoritative source for CVE metadata
- **Project Zero**: practitioner-vector reference for vulnerability research depth
- **Internal**: `source-validation-guide.md`, `intelligence-correlation.md`, `continuous-monitoring.md`, `iterative-search-patterns.md`, `mcp-integration.md`
