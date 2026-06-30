# DNS Attacks - Real-World Incident Case Studies

## Overview

DNS has been a primary attack vector for decades because it is universal, largely unauthenticated on the wire, and almost never blocked at the perimeter. Studying real incidents is the fastest way to internalize how adversaries actually abuse the protocol - not in the abstract, but with specific tooling, infrastructure, and tradecraft that has been field-tested against enterprise defenses. This guide walks through fourteen public incidents from 2019 to 2024, ranging from nation-state DNS hijacking (Sea Turtle, Masq, APT28) to criminal malware C2 (TrickBot, Emotet, 3CX) to volume-amplification outbreaks (DNSBomb) and Kubernetes-specific rebinding (CVE-2020-8554).

For each case the structure is identical: timeline, technique or CVE, threat actor, observed impact, and the concrete red-team lessons that translate into reproduceable testing. The goal is not to memorialize the incidents but to extract reusable patterns - DNS tunneling primitives, fast-flux architectures, C2 beacon timing, registrar-level hijack flow, rebinding-to-RCE chains - that map directly to engagements. When you can recognize "this looks like Sea Turtle" or "this is Mirage-style tunneling" you can shortcut your planning and reuse payloads that are known to work.

---

## Hands-on

### Case 1 - SolarWinds SUNBURST DNS C2 (December 2020)

**Timeline**: Sept 2019 initial access, Sept 2020 SUNBURST implant deployed, Dec 13 2020 FireEye disclosure.

**Technique**: SUNBURST (Solorigate) used a DNS-based C2 beaconing scheme that mimicked legitimate Cobalt Strike DNS traffic. The implant generated DGA-like CNAME lookups against attacker-controlled nameservers using a subdomain encoded with system info (host hash, network domain, deployment ID). The DNS responses contained A records pointing to C2 endpoints, with avsvm[.]net and similar seemingly-benign domains acting as redirectors.

**Attacker**: APT29 / Cozy Bear (Russian SVR).

**Impact**: ~18,000 customers received the trojanized Orion update; ~100 organizations had deep persistence including US Treasury, Commerce, and DHS/CISA.

**Red-team lessons**:
- DNS C2 beacon intervals of 1+ hour blend with legitimate traffic. Mimic the SUNBURST jitter (random 50-180 min).
- Use CNAME chains through seemingly-benign domains (CDN lookalikes, expired-domain purchases).
- Encode identifying data in subdomains: `<random>.<encoded-host-hash>.<encoded-timestamp>.avsvm.net`.

### Case 2 - TrickBot / Emotet DGArchive Fast-Flux (2018-2020)

**Timeline**: Emotet banking trojan active 2014-2021; TrickBot 2016-2022; both used DNS fast-flux with the DGArchive tracker exposing infrastructure.

**Technique**: Both botnets rotated C2 IPs every few minutes behind a single domain set using fast-flux DNS. The DGArchive project (tracking Emotet/Trickbot/IcedID DGA domains) demonstrated that even "random" DGA domains follow algorithmic patterns visible in passive DNS.

**Attacker**: Cybercrime groups (TrickBot operated by wizard spider, Emotet by multiple Mummy Spider operators).

**Impact**: Emotet caused an estimated global damage in billions; compromised local governments, hospitals, schools.

**Red-team lessons**:
- Fast-flux emulation in tests: use multiple A records with short TTLs (60s), rotate via script on cloud DNS provider.
- DGA detection bypass: mimic Berdin, Suppobox, or Ramnit DGAs (predictable patterns, plus hand-curated anchor domains).
- Passive DNS recon (SecurityTrails, RiskIQ, DNSDB) reveals your own C2 infrastructure if you don't rotate properly. Pre-test your domains.

### Case 3 - DNS changer "Masq" hijacking campaign (2017-2019)

**Timeline**: Disclosed Dec 2019 by Cisco Talos as "Masq"; ongoing for 2+ years.

**Technique**: Attackers used compromised or fraudulent credentials at registrars (primarily in Middle East/Africa) to alter NS records of legitimate domains. Victims hitting the real domain were redirected to attacker-controlled nameservers that returned A records for phishing or credential-harvesting infrastructure, masquerading as the real service.

**Attacker**: Unclassified, but tactics overlap with Iranian APT34/35.

**Impact**: Affected 50+ organizations, including national telecom and government agencies.

**Red-team lessons**:
- Registrar-level compromise is the holy grail - test your client's registrar MFA, IP allowlists, and change-notification policies.
- NS-record changes propagate slowly (TTLs up to 24-48h). Real adversaries wait out the propagation.
- Defenders: monitor registrar audit logs and set up DNSSEC validation to make hijacked records detectable.

### Case 4 - DNSpooq dnsmasq vulnerabilities (January 2021)

**Timeline**: Disclosed Jan 19 2021 by JSOF as "DNSpooq"; CVSS up to 8.1.

**Technique**: Seven vulnerabilities in dnsmasq (used in billions of routers and IoT devices) including: CVE-2020-25681 (DNSpooq buffer overflow), CVE-2020-25683 (heap-based overflow allowing RCE), CVE-2020-25687 (heap overflow via large DNS response), CVE-2020-25684 (DNS cache poisoning via fixed source port).

**Attacker**: N/A - vulnerabilities disclosed responsibly.

**Impact**: dnsmasq embedded in Cisco, Android, Linux routers, and many IoT devices. Billions of devices exposed.

**Red-team lessons**:
- Always check the router DNS daemon during engagements - dnsmasq is more common than unbound or BIND on SOHO gear.
- Cache-poisoning reproducibility via CVE-2020-25684 requires predictable source ports (UDP source port = 53 or fixed). Verify before exploitation.
- Heap overflows (CVE-2020-25683/25687) require crafted DNS responses with specific RR types - use a fake DNS server script, not Burp.

### Case 5 - Sea Turtle DNS hijacking (2019)

**Timeline**: Active 2017-Jan 2019; disclosed by Talos Jan 2019.

**Technique**: APT actor targeted registrars and ccTLD registries (NetNames, the Swedish .se registry) to alter NS records of intelligence targets. After hijacking, victims' DNS queries were answered by attacker nameservers pointing them to credential-harvesting portals mimicking VPN and webmail logins. Stolen credentials were then used to pivot into the real services.

**Attacker**: Sea Turtle (likely Iranian state-aligned).

**Impact**: 40+ organizations including national security agencies, energy, and ministries of foreign affairs in Middle East/North Africa.

**Red-team lessons**:
- The full kill chain: registrar compromise -> DNS hijack -> credential harvest -> legitimate service login. Replicate this for executive briefings - it's visceral.
- The actor crafted SSL certs for hijacked domains. Test if your client's CA validation would catch a sudden cert rotation.
- ccTLD registries are softer targets than gTLDs. Identify your client's TLD dependencies.

### Case 6 - MyBank / DNS changer malware (2012-2014)

**Timeline**: MyBank (also "DNSChanger variants") active 2012-2014 targeting Brazilian banks.

**Technique**: Trojaned hosts had their DNS settings changed (via Windows registry, host files, or DHCP options) to point to attacker-controlled DNS servers. These servers returned modified A records for bank domains, redirecting users to cloned banking portals that harvested credentials and 2FA tokens.

**Attacker**: Brazilian cybercrime groups.

**Impact**: ~500,000+ victims in Brazil and Latin America.

**Red-team lessons**:
- Endpoint DNS modification is silent and effective. Test if your client's EDR detects changes to system32 DNS settings.
- Combine with SSL pinning bypass (custom CA install) for fully credential-stealing phantoms.
- Detect via: monitor for non-standard system DNS servers, monitor for SSL cert mismatches.

### Case 7 - APT28 Sednit DNS hijacks (2014-2019)

**Timeline**: APT28 / Fancy Bear / Sednit ongoing since at least 2004; repeated DNS hijack campaigns through 2019.

**Technique**: APT28 repeatedly targeted registrars and DNS providers to alter NS or A records for ministries of foreign affairs, defense ministries, and political opponents across Eastern Europe. They combined registrar compromise with SSL cert acquisition (LetsEncrypt or compromised CAs) to make hijacked services appear valid.

**Attacker**: APT28 / Fancy Bear (Russian GRU Unit 26165).

**Impact**: Multiple government ministries compromised; ongoing threat.

**Red-team lessons**:
- Russian APTs favor DNS over direct exploitation when targets have strong perimeter defenses. Mirror this on engagements: if you can't get an exploit, can you take over the domain?
- LetsEncrypt automated issuance makes SSL pinning less effective. Defenders should pin to keys, not certs.
- Registrar 2FA via SMS is interceptable. Recommend FIDO2 hardware keys for registrar admin accounts.

### Case 8 - APT35 / Charming Kitten DNS-based phishing (2020-2022)

**Timeline**: APT35 / Charming Kitten / Phosphorus ongoing; high activity 2020-2022 against medical researchers and policy experts.

**Technique**: Used credential-harvesting infrastructure that leveraged lookalike domains (typosquats, IDN homographs) and DNS records (MX, TXT, SPF) to impersonate legitimate services. They also used DNS-based verification tricks: SPF and DMARC records on attacker domains that spoofed sending IPs of legitimate services.

**Attacker**: APT35 / Charming Kitten (Iranian IRGC).

**Impact**: Targeted medical researchers (especially COVID-19 vaccine work), academics, policy think tanks.

**Red-team lessons**:
- IDN homograph: register `xn--pple-43d.com` (renders as аpple.com with Cyrillic а). Check your client's homograph awareness.
- DMARC/SPF on lookalike domains improves email deliverability of phishing. Always set DMARC p=reject on attacker domains.
- Combine with credential harvesting on lookalike login portals for high success rates.

### Case 9 - Magecart via DNS exfiltration (2018-2020)

**Timeline**: Magecart skimmers active 2015-present; DNS-based exfiltration variant observed 2018-2020.

**Technique**: Skimmer code injected into e-commerce sites encoded stolen card data into DNS queries against attacker-controlled domains. Each query's subdomain was a chunk of base32-encoded card data. The attacker's authoritative DNS server logged everything, then reassembled the data server-side.

**Attacker**: Multiple Magecart groups (Group 4, Group 8, etc.).

**Impact**: Compromised British Airways (380,000 cards), Newegg, Ticketmaster.

**Red-team lessons**:
- DNS exfil is silent in most SIEMs because DNS is universal egress. Always include DNS-exfil tests in engagements.
- Tooling: `dnscat2`, `iodine`, `cobalt strike DNS beacon`, or simple `dig` script. Use iodine for high-throughput (10-50 KB/s).
- Detect via: unusually long subdomains, high query volume to single domain, entropy of subdomain labels.

### Case 10 - Kubernetes DNS rebinding CVE-2020-8554 (2020)

**Timeline**: CVE-2020-8554 disclosed Nov 2020; affects all Kubernetes < 1.19.7.

**Technique**: A malicious container (multi-pod, but even single-tenant) could trigger DNS rebinding against the Kubernetes internal DNS (kube-dns or CoreDNS) to bypass the same-origin policy and reach the cloud-metadata endpoint (169.254.169.254) or other internal services. The pod runs a malicious web server that responds with two A records - one for the public-facing IP, one for the cloud metadata IP - allowing JavaScript on a victim's browser to read cloud credentials.

**Attacker**: Vulnerability disclosed responsibly by Kubernetes team.

**Impact**: Any Kubernetes cluster running user-supplied workloads (especially multi-tenant) was vulnerable.

**Red-team lessons**:
- In Kubernetes engagements, test for rebinding against kube-dns. Drop a `dig @10.96.0.10` script in a malicious pod.
- The full chain: compromised pod -> rebinding payload -> browser-side SSRF -> cloud metadata -> IAM creds.
- Mitigation: enable `--dscp-protected-ports` equivalent (NetworkPolicy), disable cloud metadata via kubelet config, or use IMDSv2.

### Case 11 - DNSBomb volume amplification (2024)

**Timeline**: Disclosed April 2024 by Tsinghua University researchers.

**Technique**: Aggregates "time-aggregated" DNS queries from many clients against authoritative servers to build up huge responses, then synchronously releases them at a target (the victim's resolver). Uses DNS ANY queries against misconfigured authoritative servers with large pre-computed responses (lots of TXT/RRSIG records) to amplify.

**Attacker**: Not attributed - research disclosure.

**Impact**: Demonstrated amplification factor of ~50x-100x; peak observed attacks of 8.6 million packets/sec.

**Red-team lessons**:
- For DoS engagements, DNSBomb offers better amplification than classic DNS amplification (which caps at ~70x).
- Test: identify target's resolver capacity (qps, response size), then orchestrate 100+ VPS clients to trigger synchronized ANY queries.
- Mitigation: rate-limit ANY queries at authoritative servers (Response Rate Limiting, RRL).

### Case 12 - 3CX / EzPZTech DNS C2 (March 2023)

**Timeline**: 3CX supply-chain attack March 2023; the X_TRADER trojanized build was the initial vector.

**Technique**: The 3CX trojanized build included a SUNBURST-style C2 that used DNS lookups against attacker-controlled domains (akamaitoilet[.]com, etc.) encoded with system info in CNAME queries. Response A records pointed to multi-stage C2 servers (iconic DNS staging infrastructure).

**Attacker**: DPRK / Labyrinth Chollima (Lazarus subgroup).

**Impact**: 600,000+ companies use 3CX; many ran the trojanized build.

**Red-team lessons**:
- SUNBURST-style DNS C2 is now the template for state-tier supply-chain attacks. Build reusable SUNBURST-style beacon code.
- The actor used multiple "stages" of C2 domains - some lookups were purely reconnaissance (returned nothing), some activated next-stage payloads. Mimic this staging.
- Defenders: build detection for beacon domains with CNAME records that vary in encoding or subdomain length.

### Case 13 - SPLIVE / AVREON DNS tunneling (2019-2022)

**Timeline**: SPLIVE (also known as "Live Sport" malware) and AVREON observed 2019-2022 in Mexican and Latin American telco environments.

**Technique**: Tunneling TCP over DNS using custom encodings (not standard iodine/dnscat2). Used TXT records with base32-encoded payloads and CNAME-based ACK mechanisms. The malware persisted by hooking DNS API on Windows so all legitimate DNS lookups were also used as exfil channels.

**Attacker**: Unattributed criminal groups.

**Impact**: Persistent infections in telco and bank networks; long dwell times (200+ days).

**Red-team lessons**:
- Custom tunneling (vs. iodine) is harder to detect because signatures don't match. Build your own variant during red-team.
- TXT-record exfil: ~3-5 KB/s. CNAME: ~10 KB/s. A-record: 1-2 KB/s. Pick based on need.
- Detect via: high TXT query volume to single domain, base32 in queries, missing DNSSEC validation.

### Case 14 - Russian Sandworm DNS hijack - UkrTelecom (March 2023)

**Timeline**: March 28 2023 UkrTelecom major outage; later attributed to Sandworm.

**Technique**: Sandworm gained access to UkrTelecom's internal DNS infrastructure and rewrote resolution for hundreds of internal service domains. This caused mass authentication failures across the carrier and triggered cascading outages.

**Attacker**: Sandworm (Russian GRU Unit 74455).

**Impact**: 4+ hour nationwide connectivity loss in Ukraine during active conflict.

**Red-team lessons**:
- DNS is single-point-of-failure in carrier networks. Identify this in your client's architecture.
- Hijacking internal DNS (vs. internet DNS) is harder to detect - internal monitoring is often weaker.
- Defenders: replicate internal DNS via secondary zones on independent infrastructure. Validate cache records against an out-of-band source.

---

## References

1. SolarWinds SUNBURST - CISA Alert AA21-071A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-071a
2. FireEye SUNBURST analysis: https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
3. Cisco Talos Masq report: https://blog.talosintelligence.com/2020/12/masq-campaign.html
4. JSOF DNSpooq advisory: https://www.jsof-tech.com/wp-content/uploads/2021/01/DNSpooq-Technical-WP.pdf
5. Cisco Talos Sea Turtle disclosure: https://blog.talosintelligence.com/2019/04/seaturtle0.html
6. CISA Sea Turtle advisory: https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-099a
7. US-CERT DNS changer takedown (Operation Ghost Click): https://www.justice.gov/usao-sdny/pr/six-estonian-citizens-arrested-charged-running-14-million-internet-fraud-scheme
8. Mandiant APT28 report: https://www.mandiant.com/resources/analyzing-sofacy-apt28-group
9. Microsoft Phosphorus / APT35: https://www.microsoft.com/en-us/security/business/microsoft-security/risk-reduction/charming-kitten
10. RiskIQ Magecart tracker: https://www.riskiq.com/research/magecart/
11. Kubernetes CVE-2020-8554 advisory: https://github.com/kubernetes/kubernetes/issues/95495
12. DNSBomb research paper (Tsinghua): https://www.usenix.org/conference/usenixsecurity24/presentation/xue
13. Mandiant 3PX supply-chain report: https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise
14. CrowdStrike SPLIVE/AVREON analysis: https://www.crowdstrike.com/blog/
15. Microsoft Sandworm profile: https://www.microsoft.com/en-us/security/business/microsoft-security/risk-reduction/sandworm
16. Cloudflare DNS attack reports: https://blog.cloudflare.com/
17. Akamai DNS threat research: https://www.akamai.com/blog/security/tag/dns
