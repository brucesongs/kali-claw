# CI/CD Supply Chain — Real-World Incident Case Studies

> Deep-dive companion to `skills/ci-cd-supply-chain-attack/SKILL.md`.
>
> Audience: pentesters and red teamers who need to ground their CI/CD supply chain tradecraft in concrete historical incidents. Each case is mapped to the supply chain link that was compromised, the attacker technique, the downstream impact, and the red-team lessons that translate directly into engagement findings.

---

## Overview

The software supply chain is the largest single attack surface in modern infrastructure because a single compromise propagates downstream to every consumer. The 2020 SolarWinds SUNBURST incident — a backdoored update pushed to roughly 18,000 organizations including US federal agencies — was the wake-up call. Four years later the XZ Utils backdoor (CVE-2024-3094) demonstrated that the same class of attack works against the open-source commons, where a single patient maintainer can backdoor a library that ships in every major Linux distribution.

This guide walks twelve canonical incidents. Each one is a different link in the supply chain — the build process, the upstream source, the package repository, the CI secret, the maintainer account, the CD platform, or the developer endpoint. Read them in order; the progression mirrors how real adversaries have professionalized this attack class from 2020 to 2024.

For each case study, look for the structural pattern: **what was the trust boundary the attacker violated?** SolarWinds violated the build process. Codecov violated the upload script. XZ violated maintainer trust. PHP violated upstream source. Once you can name the trust boundary, you can write a finding that recommends the durable fix (provenance, isolation, signing) instead of a band-aid.

---

## Case 1 — SolarWinds SUNBURST (December 2020, APT29 / Cozy Bear)

**Timeline.** September 2019 — initial access to SolarWinds network. Spring 2020 — attackers planted SUNBURST (a trojanized DLL, `SolarWinds.Orion.Core.BusinessLayer.dll`) into the Orion build pipeline. March–May 2020 — SolarWinds shipped the backdoored versions 2019.4 through 2020.2.1 HF1 to roughly 33,000 customers, of which ~18,000 installed it. December 13, 2020 — FireEye publicly disclosed the breach after detecting their own Red Team tool theft.

**Supply chain link compromised.** The Orion build process itself. APT29 (also attributed as SVR 85 GTsSS / Cozy Bear) inserted malicious code into the legitimate `SolarWinds.BusinessLayerHost.exe` build, signed with SolarWinds' valid code-signing certificate.

**Attacker technique.** SUNBURST was a two-week-dormant beacon that fingerprinted the host, then contacted a C2 domain (`avsvmcloud[.]com` and others) using a DGA constructed from the victim's domain. The C2 selected high-value targets for next-stage implants (TEARDROP, RAINDROP) that deployed Cobalt Strike. The malware specifically avoided sandbox and analysis VMs.

**Downstream impact.** Nine US federal agencies breached (Treasury, Commerce, Justice, Energy, Homeland Security, State, NIH, NOAA, CISA itself) plus ~100 private companies (FireEye, Microsoft, Intel, Cisco, Deloitte). Estimated remediation cost: $100M+ at SolarWinds alone. Mandiant attributed the FireEye breach to UNC2452 (later unified with APT29).

**Red team lessons.** (1) The signed-and-trusted binary is the highest-leverage implant in any environment. (2) Build-system telemetry must detect "the build produced a different binary than the source says it should" — SolarWinds had no such control. (3) DGA-based C2 over long dwell times defeats signature-based AV. Test your blue team's ability to catch a two-week-quiet beacon. (4) Every artifact your SI ingests (in this case Orion telemetry) is a potential implant; vendor risk equals insider risk.

---

## Case 2 — 3CX Desktop App Double Supply Chain (March 2023, Lazarus / AppleJeus Stage 2)

**Timeline.** The 3CX 3CXDesktopApp (Electron) was trojanized in update 22.6.7.501 (Windows) and 22.6.7.502 (macOS). March 22, 2023 — CrowdStrike and SentinelOne published advisories. March 29, 2023 — 3CX confirmed the breach. By then the malware had been distributed for weeks.

**Supply chain link compromised.** Two-stage supply chain. Stage 1: the 3CX build pipeline itself (developer workstation compromise → malicious Electron bundle). Stage 2 — the more interesting one — the 3CX attackers were themselves the downstream victim of a prior supply chain attack. Mandiant attributed the 3CX intrusion to UNC4736 (Lazarus / AppleJeus sub-cluster), and the initial access vector was a trojanized X_TRADER (trading software from Trading Technologies) that 3CX employees installed. The X_TRADER malware (named AppleJeus by Kaspersky in 2018) was itself a Lazarus product. Lazarus attacked Trading Technologies, the malicious X_TRADER installer was signed with a stolen Trading Technologies certificate, and a 3CX developer ran it.

**Attacker technique.** The malicious Electron app loaded aframe-`frame`-`poc`-style logic, contacted GitHub-hosted C2 (`iconicicons` repo) and then deployed second-stage payloads: **SmoothOperator** (the initial stage) and **ColdCat** / **Goptra** (later stages). The C2 traffic masqueraded as Google Analytics / Slack traffic.

**Downstream impact.** 3CX had 600,000+ companies and 12M+ daily users. Mandiant's analysis showed the second-stage payload was a keylogger / info stealer targeting financial firms — likely a broad financial-intelligence operation consistent with DPRK's posture.

**Red team lessons.** (1) Supply chain attacks chain — your vendors' vendors are your attack surface. (2) Electron apps are a soft target: the entire JavaScript payload is mutable, attackers don't need to recompile native code. (3) Code-signing is necessary but not sufficient; the 3CX binaries were signed. (4) Test your ability to detect a malicious update to an internal auto-updater — most orgs have no control over Electron-app updates.

---

## Case 3 — Codecov Bash Uploader Breach (January – April 2021)

**Timeline.** January 31, 2021 — attackers gained write access to Codecov's `bash uploader` script (`bash <(curl -s https://codecov.io/bash)`) by exploiting a Docker image misconfiguration that leaked an upload-script-editing credential. The script was modified to exfiltrate environment variables from CI builds. April 1, 2021 — a Codecov customer noticed the script's hash differed from the repo. Codecov investigated, removed the malicious modification, and disclosed publicly on April 15, 2021.

**Supply chain link compromised.** A `curl | bash` install script. Codecov's uploader was used by tens of thousands of CI runs daily. The script ran with the CI's full environment — including secrets.

**Attacker technique.** The malicious modification added code that, after the normal coverage upload, base64-encoded the CI environment variables and exfiltrated them to a Codecov-owned B2 cloud bucket URL (using `curl`/`wget` with a specific user agent). The attackers then used the harvested cloud credentials to pivot into downstream customer environments. Many of these credentials were AWS/GCP deploy keys.

**Downstream impact.** Twilio, Rapid7, HashiCorp, Monzo, and many others disclosed downstream compromise. HashiCorp rotated Vault/Consul/Terraform release-signing keys. Rapid7 disclosed that some source-code repos were accessed.

**Red team lessons.** (1) `curl | bash` is an unattested supply chain — there is no signature, no version pin, no integrity check. (2) CI environment variables are the highest-density secret store in most orgs — every workflow that runs the uploader leaks everything. (3) The "we trusted our install script" model is broken; SLSA-style provenance on installers is the durable fix. (4) As a red-team technique, target the install scripts — npm `postinstall`, pip `setup.py`, Homebrew formulas — they run with full CI/CD context.

---

## Case 4 — PHP Self-Backdoor in Upstream (March 2021)

**Timeline.** March 25, 2021 — attackers pushed two malicious commits to the `php-src` repository on `git.php.net` claiming RCE performance optimizations. The commits added a backdoor masquerading as a performance improvement: `if (Z_TYPE_P(passed) == IS_STRING && Z_STRLEN_P(passed) == 0)` → triggers `eval()` of the argument. March 28, 2021 — Nikita Popov noticed the malicious commits during review. PHP migrated to GitHub (`github.com/php/php-src`) and shut down `git.php.net`.

**Supply chain link compromised.** Direct upstream source — the canonical `php-src` repo. The attackers compromised a php maintainer account on `git.php.net` (which used self-hosted gitolite), bypassing the normal review process.

**Attacker technique.** The backdoor was subtle — an early return that turned `assert()` / `0` payloads into RCE. The commit messages claimed it was a performance optimization for assertions.

**Downstream impact.** The malicious commits were never released — caught within 48 hours of push. But if a release had been cut, every PHP 8 deployment would have shipped a remote code execution vulnerability in the runtime itself.

**Red team lessons.** (1) Maintainer-account compromise is the simplest supply chain attack — phishing or credential reuse gives you push access to the source of truth. (2) Two-person review (the GitHub model) catches this; gitolite without enforced review does not. (3) The xz-utils case (Case 5) shows the same technique evolved — instead of compromising a maintainer account, the attackers became the maintainer.

---

## Case 5 — XZ Utils Backdoor CVE-2024-3094 (February – March 2024, "Jia Tan")

**Timeline.** Late 2021 — account `Jia Tan` appeared, contributing low-pressure fixes to xz-utils. 2022 — Jia Tan became a co-maintainer. Early 2024 — Jia Tan pushed malicious `bad-3-corrupt_lzma2.xz` and `good-large_compressed.lzma` test files to the upstream `tukaani-project/xz` repo, and shipped a build system that conditionally injected those test files into `liblzma` during Debian/Ubuntu package builds. March 29, 2024 — Microsoft engineer Andres Freund noticed SSH logins taking 500ms longer than usual on Debian sid; traced the latency to the backdoor in liblzma, which is linked into `sshd` via `libsystemd`.

**Supply chain link compromised.** Maintainer trust plus build-system obfuscation. Jia Tan was a real (if pseudonymous) maintainer; their commits were reviewed by the original maintainer Lasse Collin. The malicious code lived in test fixtures and was conditionally activated only during the actual Debian/Ubuntu build (detected via `config.sub` string matching) — invisible to local repo clones.

**Attacker technique.** The backdoor hooked `RSA_public_decrypt` in liblzma-loaded `sshd`, allowing the attacker to send a specific ed448-signed payload in the SSH certificate that bypassed normal authentication and executed arbitrary commands as root. The exploit was sophisticated — RSA key extraction, certificate forgery, ed448 verification against a hardcoded key (`/dev/null`).

**Downstream impact.** Caught before stable release. Debian sid, Fedora Rawhide, and openSUSE Tumbleweed shipped the backdoor for ~3 weeks. If a stable release had gone out, every Linux SSH server that ran `sshd` linked against `libsystemd` (which linked `liblzma`) would have been compromised. NVD assigned CVE-2024-3094 with CVSS 10.0.

**Red team lessons.** (1) Patient maintainer-account grooming is the new social engineering. (2) Build-system obfuscation (test files, conditional injection) defeats source review. The malicious code never appeared in source form — it was binary in a test fixture, and the build script patched it in. (3) Reproducible builds are the only durable defense — they would have surfaced the divergence. (4) The detection that caught it (500ms latency in SSH) was serendipitous. SIEM rules for build-output delta are the durable control.

---

## Case 6 — JetBrains TeamCity Auth Bypass CVE-2023-42793 (September 2023)

**Timeline.** September 19, 2023 — JetBrains disclosed CVE-2023-42793, an authentication bypass in TeamCity < 2023.05.4. CVSS 9.8. October 2023 — CISA added to KEV catalog after active exploitation. November–December 2023 — ransomware crews (COATHANGER, Citrine Sleet DPRK) used it for initial access.

**Supply chain link compromised.** The CI server itself — TeamCity was the build pipeline for thousands of orgs. The auth bypass gave unauthenticated RCE on the build server.

**Attacker technique.** A path traversal in the `/app/rest/server` API endpoint allowed an attacker to create an admin user with a single crafted request, without authentication. The request was a simple `POST /hax?jsp=/app/rest/server` with an XML body.

**Downstream impact.** TeamCity runs the builds. Compromise of TeamCity = compromise of every artifact it produces. JetBrains's advisory named dozens of CVEs subsequently exploited; CISA KEV-listed within 30 days.

**Red team lessons.** (1) The CI server is a production system holding deploy secrets — must be patched at the same SLA as production. (2) Auth bypasses on CI servers are unfettered RCE; the build context is a one-stop shop for secret theft. (3) Test for the simple `POST /hax?jsp=` style payloads — they work, and most orgs have no WAF in front of TeamCity.

---

## Case 7 — Atlassian Bamboo RCE (CVE–2024–21687 and prior)

**Timeline.** Atlassian Bamboo < 9.6.4 was vulnerable to a remote code execution flaw via a deserialization gadget chain. Atlassian published advisories in 2024 urging immediate upgrade. Bamboo is widely used as a CD/CI server for Atlassian-shop orgs.

**Supply chain link compromised.** The build server (same class as TeamCity). Bamboo runs plans that contain shell scripts and credentials.

**Attacker technique.** Deserialization of untrusted data in Bamboo's internal API led to code execution via Java gadget chains (CommonsCollections). Payloads like `ysoserial CommonsCollections5` were effective.

**Downstream impact.** Orgs with internet-exposed Bamboo lost build-server control, which translates to deploy key theft and supply-chain-compromise-class impact across all Bamboo-built artifacts.

**Red team lessons.** (1) Java deserialization is forever — every Java-based CI server (Bamboo, Jenkins, GoCD) needs gadget-chain testing. (2) Authenticated RCE on a CI server is the highest-impact finding in this skill — escalate to client.

---

## Case 8 — GitLab CVE-2021-22205 (ExifTool, April 2021)

**Timeline.** April 14, 2021 — GitLab disclosed CVE-2021-22205, a crafted-DjVu-file RCE in ExifTool that GitLab used for image processing on uploads. CVSS 10.0. April 2023 — still actively exploited at scale (CISA KEV).

**Supply chain link compromised.** The repo manager / CI system itself — GitLab holds source, runners, and CD config. Unauthenticated RCE on GitLab = total compromise of the dev platform.

**Attacker technique.** An attacker uploads a malicious DjVu image as an avatar or attachment; ExifTool parses it, triggers the DjVu Perl eval gadget, and runs arbitrary code as the GitLab Workhorse user. From there the attacker pivots to the GitLab API and exfiltrates project source / CI secrets / SSH deploy keys.

**Downstream impact.** Hundreds of breaches attributed to this CVE in 2021–2022. Mirai botnets weaponized it.

**Red team lessons.** (1) Image-parsing libraries on internet-facing apps are an evergreen RCE vector (ImageMagick, ExifTool, Ghostscript). (2) Repo managers (GitLab, Gitea, Bitbucket Server) hold the same crown jewels as a CI server — scope them into every engagement. (3) The durable fix is parser sandboxing (gVisor, nsjail); allow-listing extensions is insufficient.

---

## Case 9 — CircleCI Orb Tampering (January 2023)

**Timeline.** January 4, 2023 — CircleCI disclosed that an unauthorized party had accessed a CircleCI engineer's laptop and exfiltrated an OAuth token that allowed them to potentially tamper with orbs (reusable CircleCI config packages). CircleCI forced rotation of all customer project tokens.

**Supply chain link compromised.** A CI provider's internal systems — analogous to a GitHub Actions or GitLab Runner compromise. The OAuth token gave the attacker the ability to mint project-level OAuth tokens for any CircleCI project.

**Attacker technique.** The compromised engineer's laptop had a session token for CircleCI's internal systems. The attacker used the token to access a system that could mint project OAuth tokens. There is no evidence orbs were modified, but the blast radius — every CircleCI project's secrets — forced fleet-wide rotation.

**Downstream impact.** Every CircleCI customer had to rotate all project secrets. Some downstream breaches attributed to this incident.

**Red team lessons.** (1) CI-provider-side compromise is asymmetric — one provider breach means every customer rotates everything. (2) OIDC federation is the durable fix; short-lived, scoped, federated tokens don't need fleet rotation. (3) Engagements should always test "what happens if the CI provider is compromised" — assume-breach exercises.

---

## Case 10 — npm/PyPI Typosquatting Campaigns (2023–2024)

**Timeline.** Continuous since 2017. Notable: `luminati` (a real npm package by Luminati Networks) was typosquatted as `luminati-io` in 2017 to deploy cryptominers. `colors` and `faker` (Marak Squires, January 2022) — a maintainer intentionally sabotaged his own packages, breaking thousands of pipelines. `node-ipc` (March 2022, RIAEvangelist) — maintainer pushed a "protestware" payload that wiped files on machines with Russian/Belarusian IPs. 2023–2024 — Python typosquatting campaigns (e.g. `pyutf8` mimicking `pyutf-8`, `reqeusts` mimicking `requests`) shipped infostealers.

**Supply chain link compromised.** The public package repository — npm, PyPI — which has no enforced namespace, allows anyone to publish anything.

**Attacker technique.** Two patterns: (a) typosquatting (`reqeusts` vs `requests`) for initial install confusion; (b) "protestware" / maintainer sabotage where the legitimate maintainer pushes malicious code. The second pattern is far more dangerous — there is no defensive checksum that distinguishes "legitimate maintainer with malicious intent" from "legitimate maintainer".

**Downstream impact.** Each major campaign breaks thousands of builds. The 2022 `colors`/`faker`/`node-ipc` incidents forced every major org to implement `npm install --ignore-scripts` and package-allow-listing.

**Red team lessons.** (1) Public package registries are untrusted by design. (2) Test your client's package-allow-list — most orgs have none. (3) "Protestware" is a legitimate threat — your clients cannot trust even their long-trusted maintainers without provenance.

---

## Case 11 — PyTorch Nightly Trojan (December 2023)

**Timeline.** December 25–30, 2023 — PyTorch disclosed that the `torchtriton` dependency of the nightly `pytorch-triton` package had been compromised. Attackers had registered a malicious `torchtriton` package on PyPI with the same name as the internal dependency, which the PyTorch build then pulled. The malicious package ran a malicious `setup.py` that exfiltrated `/etc/passwd`, `~/.ssh`, environment variables, and AWS/Gcloud credentials.

**Supply chain link compromised.** Dependency confusion — `torchtriton` was an internal package name (PyTorch's internal triton fork), but PyTorch's nightly install path pulled it from public PyPI, where the attacker had registered it.

**Attacker technique.** Classic dependency confusion: register an internal-sounding name on a public registry, the build pulls it because the public registry is preferred over the private. The malicious `setup.py` ran a stealer.

**Downstream impact.** PyTorch nightly users (researchers, ML engineers) had their SSH keys and cloud creds exfiltrated for ~3 days.

**Red team lessons.** (1) Dependency confusion is evergreen — every org that mixes internal + public registries needs namespace isolation. (2) The 2021 Alex Birsan research (case in dependency-confusion-deep guide) made this technique famous; it remains the highest-ROI finding in many engagements. (3) `setup.py` runs with full CI context — install-time malware is build-time malware.

---

## Case 12 — HashiCorp Vagrant Boxes and Image Trust (2024)

**Timeline.** Throughout 2023–2024, the Vagrant Cloud / Atlas box registry saw multiple malicious boxes published under typosquatted publisher names (`ubnutu` for `ubuntu`, `cenots` for `centos`). Developers pulling these boxes via `vagrant up` ran compromised VMs with developer-credentials exfiltration payloads.

**Supply chain link compromised.** The VM image registry — analogous to Docker Hub malicious images. The boxes run with developer context (SSH keys, cloud creds on dev laptops).

**Attacker technique.** Typosquatted publisher names on Vagrant Cloud; the boxes were built with `cloud-init` that ran a stealer on first boot.

**Downstream impact.** Developer-machine compromise — which in 2024 means source-code access, deploy key access, and a beachhead into the corporate network.

**Red team lessons.** (1) Developer-local VM and container images are an undersupervised attack surface — Vagrant boxes, Docker images, UTM/OVA appliances. (2) Image provenance (signed boxes, signed images) is the durable fix. (3) Test developer workstations for image-trust posture — most orgs have no policy.

---

## Hands-on: Mapping Incidents to Engagement Findings

When you write up an engagement finding, name the supply chain link and reference the canonical incident. Clients respond to "this is the SolarWinds-class risk in your build" better than to abstract CVSS scores.

### Step-by-step: Build an Incident-to-Finding Crosswalk

Create a `findings-crosswalk.yaml` in your engagement workspace:

```yaml
findings:
  - id: F-001
    title: "Self-hosted GitHub Actions runner has prod AWS creds in GITHUB_ENV"
    supply_chain_link: "build-runner"
    canonical_incident: "Codecov bash uploader (2021)"
    technique: "environment-variable exfiltration via build context"
    blast_radius: "production AWS account takeover"
    cvss_qualitative: "Critical"
    slsa_level_gap: "currently SLSA 1; target SLSA 3 (provenance + isolated build)"
    recommended_fix: "OIDC federation + ephemeral runners + cosign-signed artifacts"

  - id: F-002
    title: "Internal npm package 'myorg-utils' pullable from public npm"
    supply_chain_link: "dependency-resolution"
    canonical_incident: "PyTorch nightly torchtriton (2023)"
    technique: "dependency confusion"
    blast_radius: "build-time RCE on every consuming project"
    cvss_qualitative: "Critical"
    recommended_fix: ".npmrc scoped-registry isolation + npmrc provenance verification"
```

### Step-by-step: Test for Each Incident Class

```bash
# Dependency confusion: enumerate internal-sounding packages and check public registries
for pkg in myorg-utils mycompany-internal myteam-shared; do
  echo "checking $pkg on public npm..."
  curl -s "https://registry.npmjs.org/$pkg" | jq '.name, ."time" | keys'
done

# Maintainer-account risk: find packages with a single maintainer in client's package.json
jq -r '.dependencies | keys[]' package.json | while read pkg; do
  curl -s "https://registry.npmjs.org/$pkg" | jq '.maintainers | length'
done | sort | uniq -c | sort -rn

# Self-hosted runner GITHUB_TOKEN exposure: check workflow files for actions/checkout with persist-credentials
grep -rn "actions/checkout" .github/workflows/ | grep -v "persist-credentials: false"

# Provenance verification: check if artifacts are signed
cosign verify --key cosign.pub myregistry.com/app:v1.0.0 || echo "UNSIGNED ARTIFACT"
```

### Step-by-step: Build Detection Rules

For each canonical incident, write a SIEM rule that would catch the corresponding red-team technique. Examples:

```yaml
# Codecov-class: exfiltration of CI environment variables
detection:
  selection:
    Image|endswith:
      - "/curl"
      - "/wget"
    CommandLine|contains:
      - "http"
    ParentImage|contains:
      - "/bash"
      - "/sh"
      - "/usr/bin/python"
  filter_legitimate:
    CommandLine|contains:
      - "codecov.io/bash"   # legacy
      - ".well-known"
  condition: selection and not filter_legitimate
```

---

## References

1. CISA Alert AA21-076A — Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments (SolarWinds) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-076a
2. CISA Joint Statement on SolarWinds compromise — https://www.cisa.gov/news-events/news/joint-statement-federal-bureau-investigation-fbi-cybersecurity-and-infrastructure-security
3. Mandiant SUNBURST Analysis (UNC2452) — https://www.mandiant.com/resources/blog/sunburst-additional-technical-details
4. SentinelOne — 3CX Desktop App Supply Chain Compromise — https://www.sentinelone.com/labs/3cx-dual-supply-chain-attack/
5. CrowdStrike — 3CX Intrusion Analysis (UNC4736) — https://www.crowdstrike.com/blog/3cx-supply-chain-compromise-leads-to-triple-threat/
6. Codecov — Bash Uploader Incident Report — https://about.codecov.io/security-update/
7. PHP — Backdoor in upstream git server (March 2021) — https://news-web.php.net/php.internals/113838
8. NIST NVD — CVE-2024-3094 (XZ Utils backdoor) — https://nvd.nist.gov/vuln/detail/CVE-2024-3094
9. Andres Freund — Discovery of the XZ backdoor — https://www.openwall.com/lists/oss-security/2024/03/29/4
10. GitHub Security Lab — XZ Utils backdoor analysis — https://github.blog/news-insights/product-news/maintainer-of-xz-utils-backdoor/
11. JetBrains — TeamCity CVE-2023-42793 advisory — https://www.jetbrains.com/privacy-security/issues-fixed/
12. CISA KEV Catalog — Known Exploited Vulnerabilities — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
13. GitLab — CVE-2021-22205 ExifTool RCE advisory — https://about.gitlab.com/releases/2021/04/14/security-release-gitlab-13-10-3-released/
14. CircleCI — Security Alert January 2023 — https://circleci.com/blog/january-4-2023-security-alert/
15. Socket.dev — Typosquatting and supply chain research — https://socket.dev/blog
16. PyTorch Security Advisory — torchtriton confusion December 2023 — https://pytorch.org/blog/compromised-nightly-dependency/
17. SLSA Framework — Supply Chain Levels for Software Artifacts — https://slsa.dev/
18. OpenSSF Scorecard — supply chain security scoring — https://github.com/ossf/scorecard
19. Google SRE — Chapter on Build Provenance — https://sre.google/sre-book/
20. CISA — Software Supply Chain Security Guide (ESF) — https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain
