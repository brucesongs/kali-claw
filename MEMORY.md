# MEMORY.md - Long-term Memory

_Carefully selected distilled knowledge. Like human long-term memory — not raw logs, but the essence of experience._

**Last Updated**: 2026-05-22

---

## Current Status

- **Project Phase**: Skill domain maturation + cross-platform portability
- **Tools Mastered**: 518/518 (100%) Kali Linux tools
- **Skill Domains**: 49/49 at FULL enrichment (SKILL.md + payloads.md + test-cases.md + guides/)
- **Uptime**: ~10 weeks (since 2026-03-14 launch)
- **Current Focus**: All skills at FULL status; focus shifts to practice validation and cross-skill integration

---

## Key Decisions

### 2026-03-14: Project Launch
- Established 24/7 continuous learning mode
- Chose the comprehensive learning path for all 518 Kali Linux tools
- Built a layered memory system (daily + MEMORY.md + chronicle)

### 2026-03-18: Binary Analysis Direction Choice
- Selected radare2 as the primary reverse engineering tool (open source, lightweight, CLI-first)
- Subsequently achieved expert-level mastery (including plugin system, automation scripts)

### 2026-03-26: SQLi-Labs Fully Completed
- All 65 levels completed, Double Query injection reached expert level
- Developed automated testing tools

### 2026-05-14: Attack Surface Expansion (v0.1.5)
- Added AI Fuzzing (coverage-guided fuzzing with AFL++, libFuzzer) and Council (multi-perspective security analysis)
- Enhanced mobile-security, cloud-security, and security-bounty-hunter with deep-dive guides
- Established three-perspective framework: Attack / Defense / Audit

### 2026-05-14: Infrastructure Operationalization (v0.1.6)
- Enriched 10 infrastructure skills from "understand" to "executable" using three-tier strategy (FULL/PARTIAL/MINIMAL)
- Three-tier enrichment proved effective: prioritize operational skills first, meta-skills last

### 2026-05-16: Frontier Domains (v0.1.7)
- Added 4 new FULL domains: AI Security, Hardware Security, Multi-Agent Collaboration, MCP Server Patterns
- Expanded from 45 to 49 skill domains

### 2026-05-19: Cross-Platform Portability (migration guides)
- Created 10 migration guides (5 platforms x 2 languages) for Hermes, Claude Code, Codex, OpenCode, and OpenClaw
- Established key principle: kali-claw skills are portable — platforms read files in-place, never modify skills/

### 2026-05-22: Skill Gap Elimination (v0.1.8)
- Completed all 49 skills to FULL enrichment: added payloads+test-cases for 3 MINIMAL skills, guides/ for 10 skills
- Every skill now has SKILL.md + payloads.md + test-cases.md + guides/

---

## Lessons Learned

### Technical
- **Automation First**: Write tools before executing batch tasks (e.g., SQLi-Labs automation)
- **Attack Chain Thinking**: A single tool's value lies in its position within the attack chain; learning in isolation is inefficient
- **Hands-on Verification**: Every tool must be operated practically; theoretical learning alone is insufficient to build muscle memory

### Workflow
- **Documentation as Memory**: Writing things down is more reliable than remembering; memory files are the foundation of continuity
- **Chronicle System**: chronicle/ helps quickly locate historical events, 30x more efficient than browsing memory files
- **Regular Archiving**: Memory files older than 30 days should have their highlights extracted and then be archived to prevent file bloat
- **Three-Tier Enrichment**: Prioritizing FULL enrichment for operational skills, PARTIAL for support skills, and MINIMAL for meta-skills allows systematic skill completion without bottlenecks
- **Portable Skill Design**: Markdown-based skill packs work across AI agent platforms without modification — the key is configuring each platform to read existing files rather than converting them

---

## Key Findings

### Penetration Testing Results
-

---

## Follow-ups

- [ ] Practice validation: execute at least 1 test case per FULL skill domain
- [ ] Cross-skill integration testing: validate ECC Pipeline end-to-end flows
- [ ] Skill quality scoring system: automated coverage metrics for payloads/test-cases/guides

---

## Archive Index

> The following data has been archived from MEMORY.md to dedicated files; an index is retained here.

- **Full Tool Inventory**: `tools/` (518 tools / 65 categories)
- **Tool Mastery Details**: Raw data migrated to the above files
- **Scanned Targets**: Detailed information moved to `penetration/` directory
- **Learning Module Completion Records**: Detailed logs in `memory/` and `chronicle/`

---

_This file is maintained by you. Regularly distill highlights from daily notes._
