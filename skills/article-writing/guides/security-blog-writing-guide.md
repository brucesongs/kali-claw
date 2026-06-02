# Security Blog Writing Guide

## Introduction

Security blogs translate technical research into accessible knowledge. Whether covering a new CVE, sharing a methodology, or explaining an attack technique, effective writing maximizes impact and builds your professional reputation. This guide covers structure, style, and publishing strategy.

## Practical Steps

### 1. Post Types and Structure

**Vulnerability Analysis:**
```
# Title: [Product] [Vuln Type] — Root Cause Analysis

## TL;DR
[1-2 sentence summary with severity and affected version]

## Background
[What the product does, why the component matters]

## The Vulnerability
[Technical walkthrough with code excerpts]

## Root Cause
[Why the bug exists — design flaw, missing check, etc.]

## Exploitation
[How to trigger it, what an attacker gains]

## Fix
[How the vendor patched it, or how to mitigate]

## Takeaways
[Broader lessons for developers and security teams]
```

**Methodology/Tutorial:**
```
# Title: How to [Achieve Goal] — A Practical Guide

## Overview
[What you'll learn, prerequisites, tools needed]

## Step 1: [Setup/Recon]
[Detailed instructions with commands and screenshots]

## Step 2: [Core Technique]
[The main content — be specific, include real output]

## Step 3: [Exploitation/Analysis]
[Show the result, explain what happened]

## Step 4: [Cleanup/Remediation]
[How to fix or defend against this]

## Conclusion
[Summary of what was achieved, further reading]
```

### 2. Writing Style Rules

1. **Lead with impact** — the first paragraph must answer "why should I care?"
2. **Show, don't tell** — use code blocks, command output, and screenshots
3. **Explain the "why"** — don't just show commands, explain what each does
4. **Be reproducible** — include versions, OS, tool flags, and environment details
5. **Link to sources** — CVEs, vendor advisories, related research

### 3. Code and Command Formatting

```markdown
Good: Include context and explain flags
\`\`\`bash
# -sV: version detection, -sC: default scripts, -p-: all ports
nmap -sV -sC -p- -oA full_scan 10.10.10.10
\`\`\`

Bad: Bare command without explanation
\`\`\`bash
nmap -sV -sC -p- 10.10.10.10
\`\`\`
```

### 4. Visual Elements

- **Architecture diagrams** — show data flow and trust boundaries
- **Packet captures** — highlight relevant fields with annotations
- **Exploit chain diagrams** — show multi-step attacks visually
- **Before/after comparisons** — demonstrate the impact clearly

### 5. Publishing Strategy

| Platform | Audience | Best For |
|----------|----------|----------|
| Personal blog | General security | Long-form research |
| Medium | Broader tech | Accessible analysis |
| GitHub Pages | Developers | Technical deep-dives |
| Dev.to | Developers | Tutorials |
| LinkedIn | Professionals | Career insights |

### 6. SEO and Discovery

- Use descriptive titles with keywords (product name, vuln type, CVE ID)
- Include meta descriptions under 160 characters
- Add tags: product name, vulnerability class, technique
- Cross-post to relevant communities (r/netsec, Hacker News, Twitter/X)

## References

- [PortSwigger Research Blog](https://portswigger.net/research)
- [Google Project Zero Blog](https://googleprojectzero.blogspot.com/)
- [Trail of Bits Blog](https://blog.trailofbits.com/)
- [Krebs on Security](https://krebsonsecurity.com/)
- [HDR — Technical Writing for Security](https://github.com/HackerReviews/)
