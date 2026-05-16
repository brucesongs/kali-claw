# kali-claw v0.1.7 Release

**Released**: 2026-05-16  
**Skill Domains**: 45 → 49  
**Theme**: Frontier Domains — AI Security, Hardware, Multi-Agent, MCP Integration

---

## What's New

v0.1.7 adds 4 new FULL skill domains targeting emerging attack surfaces: AI/LLM systems, hardware and embedded devices, coordinated multi-agent operations, and MCP tool integration. Each domain ships with SKILL.md, payloads.md, test-cases.md, and a deep-dive guide.

---

## New Skill Domains

### `ai-security` — AI/LLM System Security

The AI attack surface is now a first-class pentest target. This skill covers the full spectrum from direct prompt injection to supply chain compromise of model weights.

**Key capabilities**:
- 8 direct prompt injection payload variants (token smuggling, zero-width spaces, base64, delimiter confusion)
- 5 jailbreak frameworks (DAN, developer mode, many-shot 20-pair, fictional/research framing)
- Model extraction probe sequences and training data extraction patterns
- RAG knowledge base poisoning (3 document templates)
- AI API fuzzing and multimodal injection
- OWASP LLM Top 10 mapped test cases (TC-AS-001 to TC-AS-006)
- Guide: `guides/llm-attack-methodology.md` — attack chain construction, jailbreak taxonomy, STRIDE for LLMs

**ECC Pattern**: Learning Cycle (AI attack techniques evolve weekly — this skill continuously updates)

---

### `hardware-security` — Hardware and Embedded System Security

IoT and embedded device security from physical access to firmware exploitation.

**Key capabilities**:
- UART baud rate enumeration and root shell access
- JTAG discovery (JTAGulator) and memory dump via OpenOCD
- Firmware extraction: SPI flash (CH341A/Bus Pirate), JTAG readout, U-Boot serial exfil, OTA interception
- Full binwalk analysis workflow: scan → entropy → extract → mount → inventory
- RFID/NFC cloning with Proxmark3 (EM4100, MIFARE Classic, UID spoofing)
- Fault injection setup with ChipWhisperer
- 5 test cases (4 rated Critical)
- Guide: `guides/embedded-firmware-analysis.md` — FCC ID lookup, PCB annotation, extraction decision tree, vulnerability patterns

**ECC Pattern**: Sequential Pipeline (physical → interface → extract → analyze → exploit)

---

### `multi-agent-collaboration` — Coordinated Multi-Agent Penetration Testing

Orchestrate specialist agents in parallel for large-scope, time-constrained engagements.

**Key capabilities**:
- 4 collaboration models: phase decomposition, target parallelization, tool specialization, coordinator-worker
- Task decomposition templates with scope/target/time-budget placeholders
- 5 agent role prompts (Recon, Web Tester, Network Scanner, Binary Analyst, Report Writer)
- Standardized finding JSON schema for cross-agent result aggregation
- 5-step deduplication + 7-step conflict resolution (including mandatory human escalation for Criticals)
- Coverage verification matrix — spot gaps at a glance
- 7 failure mode mitigations (scope creep, format mismatch, coordinator overload, partial coverage)
- Guide: `guides/coordinated-pentest-playbook.md` — when to use, role design, task decomposition, communication protocol

**ECC Pattern**: Batch Processing (coordinator dispatches → workers execute in parallel → results aggregated)

---

### `mcp-server-patterns` — MCP Security Tool Integration

Wrap Kali Linux security tools as secure MCP servers for AI agent integration — and audit those servers for vulnerabilities.

**Key capabilities**:
- Complete Python MCP server scaffold (~40 lines working code)
- 3 full tool implementations: nmap, nikto, generic safe command pattern (no shell=True)
- Input validation: IP/CIDR, URL, port range, file path allowlist, scope enforcement
- `hmac.compare_digest` constant-time authentication middleware
- Thread-safe sliding-window rate limiter
- Security testing commands: schema bypass, injection, auth bypass, rate limit probing
- 7 non-negotiable secure wrapping rules
- 5 test cases from basic wrapping (TC-MP-001) to full security audit (TC-MP-005)
- Guide: `guides/security-mcp-server-design.md` — tool selection criteria, MCP protocol fundamentals, implementation walkthrough

**ECC Pattern**: Sequential Pipeline (analyze → design → implement → test → deploy)

---

## Other Changes

- **IDENTITY.md** — Skill Tags table expanded from 18 to 32 rows: 10 infrastructure skills from v0.1.6 backfilled + 4 new domains
- **README.md** — Skill count updated to 49; Future Exploration table updated
- **CHANGELOG.md / UPDATELOG.md** — v0.1.7 entries added

---

## Statistics

| Metric | Count |
|--------|-------|
| New skill domains | 4 |
| New files created | 16 |
| Total lines added | ~6,600 |
| IDENTITY.md rows added | 14 |

---

## Next Steps (v0.2.0)

- `strategic-compact` — Long-engagement context management and priority-based information compression
- `ai-assisted-exploit-dev` — AI-driven exploit development and payload customization
- Deep skill enrichment pass: supply chain security, crypto attacks, digital forensics
