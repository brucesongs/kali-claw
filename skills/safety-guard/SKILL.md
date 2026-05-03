# Safety Guard

Safety enforcement layer for penetration testing operations. Provides scope checking, dangerous command interception, and incident response protocols.

## Activation

- Before executing ANY potentially destructive or irreversible command
- When a command targets production or critical infrastructure
- When operating under a defined rules of engagement (ROE)
- When a loop or automated sequence is about to start
- User says "safe?", "is this safe?", "check scope", "safety check"

## Three Safety Modes

### Mode 1: Careful (Default)

Standard safety checks applied to every operation:

- Verify target is within authorized scope
- Check command for known dangerous patterns
- Confirm no unintended side effects
- Log operation with evidence protocol

**Applied to:** All normal penetration testing operations

### Mode 2: Freeze

Pause and require explicit operator confirmation:

- Any command that modifies the target system
- Any operation that could cause service disruption
- Any credential-based attack (brute force, password spray)
- Any exploit that could cause system instability

**Applied to:** Operations that cross from passive to active

### Mode 3: Guard

Block the operation entirely:

- Commands targeting out-of-scope systems
- Operations that could cause irreversible damage
- Attacks that could propagate beyond the target
- Commands that could expose or exfiltrate real user data

**Applied to:** Operations that violate safety boundaries

## Scope Enforcement

### Scope Check Protocol

Before any operation, verify:

```markdown
## Scope Check
- **Target:** [IP / hostname / URL / CIDR]
- **Operation:** [What will be done]
- **In authorized scope?** [YES / NO / UNCLEAR]
- **Potential impact:** [None / Low / Medium / High / Critical]
- **Reversible?** [YES / NO]
- **Third-party systems affected?** [YES / NO]
- **User data at risk?** [YES / NO]
```

**Decision rules:**

| In Scope? | Impact | Reversible? | Action |
|-----------|--------|-------------|--------|
| YES | Low-Medium | YES | Proceed with Careful mode |
| YES | High | YES | Switch to Freeze mode |
| YES | Any | NO | Switch to Freeze mode |
| NO | Any | Any | Switch to Guard mode (block) |
| UNCLEAR | Any | Any | Switch to Freeze mode, ask operator |

## Dangerous Command Patterns

The following command patterns trigger enhanced safety checks:

### Block (Guard Mode)

| Pattern | Why | Example |
|---------|-----|---------|
| Mass deletion | Irreversible data loss | `rm -rf /`, `DROP DATABASE` |
| Public network exposure | Unauthorized service exposure | Binding to `0.0.0.0` |
| Credential exfiltration | Data breach risk | Uploading `/etc/shadow` to external service |
| Fork bomb | System crash | `:(){ :|:& };:` |
| Writing to critical system files | System instability | Overwriting `/etc/passwd`, `/etc/shadow` |
| Mass scanning of public ranges | Legal/ethics violation | `nmap -sS 0.0.0.0/0` |

### Pause (Freeze Mode)

| Pattern | Why | Example |
|---------|-----|---------|
| Exploit execution | Target may crash | Running `exploit/multi/handler` |
| Brute force attacks | Account lockout risk | `hydra`, `medusa`, `ncrack` |
| Denial of service patterns | Service disruption | `hping3 --flood`, `slowloris` |
| Modification of target files | System changes | Uploading web shells, modifying configs |
| Privilege escalation commands | System state change | `sudo` commands on target |
| Network tunneling | Traffic routing changes | `ssh -R`, `chisel`, proxychains |

### Warn (Careful Mode)

| Pattern | Why | Example |
|---------|-----|---------|
| Active port scanning | May trigger IDS | `nmap -sS`, `nmap -sV` |
| Vulnerability scanning | May trigger alerts | `nessus`, `openvas`, `nikto` |
| Directory enumeration | Access logs | `gobuster`, `dirb`, `ffuf` |
| DNS enumeration | May trigger rate limits | `dnsrecon`, `dnstracer` |

## Rate Limiting Guidance

### Per-Target Rate Limits

| Target Type | Max Requests/sec | Burst Allowance |
|------------|-----------------|-----------------|
| Web application | 10 | 20 |
| API endpoint | 5 | 10 |
| SSH service | 1 | 3 |
| DNS resolver | 20 | 50 |
| SMB service | 5 | 10 |
| Database | 5 | 10 |

### Backoff Strategy

When rate limiting is detected (HTTP 429, connection drops, etc.):

```
1st detection: Wait 5 seconds, reduce rate by 50%
2nd detection: Wait 30 seconds, reduce rate by 75%
3rd detection: STOP, report to operator
```

## Engagement Rules Template

```markdown
## Rules of Engagement: [Engagement Name]

### Authorized Scope
- **IP ranges:** [CIDR blocks]
- **Domains:** [hostname list]
- **Applications:** [URL list]
- **Excluded:** [What is explicitly OUT of scope]

### Authorized Activities
- [ ] Passive reconnaissance (OSINT, DNS lookups)
- [ ] Active scanning (port scan, service enumeration)
- [ ] Vulnerability scanning (automated tools)
- [ ] Manual exploitation (specific techniques)
- [ ] Post-exploitation (privilege escalation, lateral movement)
- [ ] Social engineering (phishing, vishing)
- [ ] Physical security testing
- [ ] Denial of service testing

### Constraints
- **Time window:** [Start datetime] to [End datetime]
- **Max concurrent connections:** [Number]
- **Credentials provided:** [Yes/No, details]
- **Notification required before:** [Specific actions]

### Emergency Contact
- **Client contact:** [Name, phone, email]
- **Abort procedure:** [What to do if something goes wrong]

### Reporting
- **Evidence format:** [Required format]
- **Encryption required:** [Yes/No, method]
- **Delivery method:** [How to deliver report]
```

## Pre-Action Safety Checklist

Before any potentially impactful operation:

```markdown
## Pre-Action Checklist
- [ ] Target confirmed in authorized scope
- [ ] Operation type authorized in ROE
- [ ] Current time within authorized time window
- [ ] Rate limits respected
- [ ] Evidence capture ready (terminal-ops protocol)
- [ ] Rollback plan identified
- [ ] No third-party systems will be affected
- [ ] No real user data will be accessed or modified
- [ ] Operator available for escalation if needed
```

## Incident Response Protocol

If something goes wrong during testing:

### Level 1: Minor Issue

Service restarted, non-critical log entry generated, test visible to target admin.

**Response:**
1. Stop current operation
2. Log the incident with timestamp
3. Continue testing after a brief pause
4. Note in final report

### Level 2: Service Impact

Target service degraded or temporarily unavailable, unexpected data exposure.

**Response:**
1. Stop ALL operations immediately
2. Log the incident with full evidence
3. Notify operator within 5 minutes
4. Wait for operator decision before continuing
5. Document in final report with root cause analysis

### Level 3: Critical Incident

Target system crashed, data loss occurred, unauthorized access to production data, out-of-scope system affected.

**Response:**
1. Stop ALL operations immediately
2. Disconnect from target network if applicable
3. Log ALL evidence immediately (before cleanup)
4. Notify operator IMMEDIATELY
5. Do NOT attempt to fix or cover up
6. Preserve all logs and evidence
7. Full incident report required before any further testing

## Integration with Other Skills

| Skill | Safety Guard Role |
|-------|------------------|
| `autonomous-loops` | Scope lock enforcement, rate limiting, abort conditions |
| `terminal-ops` | Pre-action safety checks before evidence-captured operations |
| `verification-loop` | Safety checks before verification execution |
| `network-pentest` | Scope checking for network operations |
| `web-sqli` / `web-xss` | Dangerous command pattern checks |
| `post-exploitation` | Freeze mode for privilege escalation and lateral movement |
| `docker-patterns` | Ensure lab environments don't leak to public interfaces |
| `all skills` | Universal safety layer applied to every operation |

## Anti-Patterns

- **Skipping scope checks** — "I'm sure it's in scope" is not acceptable
- **Disabling safety for speed** — Safety never slows you down as much as an incident
- **Assuming test data** — Always verify you're not affecting real user data
- **Not having a rollback plan** — If you can't undo it, don't do it
- **Ignoring rate limits** — Target stability is always more important than test speed
- **Testing without ROE** — Never test without defined rules of engagement
