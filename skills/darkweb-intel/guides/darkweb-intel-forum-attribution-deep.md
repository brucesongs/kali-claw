# Darkweb Forum Attribution Deep Dive

## Introduction

Attribution is the holy grail of darkweb intelligence. When a threat actor uses OPSEC correctly, attributing a forum identity to a real-world person is extraordinarily hard — but almost nobody maintains perfect OPSEC forever. This guide covers the forensic pipeline used by law enforcement (Europol, FBI, NCA, BKA, Dutch NHC) and threat-intel teams (Flashpoint, Recorded Future, TRM Labs, Elliptic) to correlate a forum handle to a human.

The pipeline has six pillars:

1. **Username correlation** — pivot the handle across 400+ clearnet platforms (Sherlock, Maigret, WhatsMyName)
2. **Stylometry** — fingerprint writing style with JGAAP, Stylo R package, or GrobID-LfD
3. **Timezone inference** — model post-timestamp distributions to deduce actor's sleep window
4. **Avatar reverse image search** — Yandex, PimEyes, Bing Visual, PimEyes biometric match
5. **PGP key cross-referencing** — keys.openpgp.org, keyserver.ubuntu.com, MIT keyserver email leak
6. **Cryptocurrency cashout tracing** — Chainalysis Reactor, TRM Forensics, OXT Research

Every real case below (Ulbricht, Cazes, Hewitt, Dutchripperz, Bidencash) was solved by combining at least three of these pillars. The takeaway: OPSEC failure is not a single mistake — it is a chain of small leaks that, when stitched together, form a unique fingerprint.

## Attribution Methodology

### Pillar 1 — Username Correlation

A handle like `dutchripperz` is rare. Pivot it across the clearnet first.

```bash
# Sherlock — multithreaded username pivoting
pipx install sherlock-project
sherlock dutchripperz --timeout 15 --print-found

# Maigret — Sherlock fork with 2500+ sites and PDF report output
pipx install maigret
maigret dutchripperz --html output.html --timeout 20

# WhatsMyName — the canonical JSON list of 600+ sites
git clone https://github.com/webbreacher/whatsmyname
cd whatsmyname
python3 whatsmyname.py -u dutchripperz

# Blackbird OSINT — GUI-driven, covers 600+ sites
# https://github.com/1ndianlaptop/blackbird-osint
```

Look for **handle reuse on clearnet platforms with registration metadata**: GitHub (commit email, commit times), Reddit (creation date, karma curve), Twitter/X (account age, bio), Keybase (PGP, BTC address), Pastebin. A GitHub commit reveals two things: a likely real email, and a commit-time histogram that builds Pillar 3.

**Keybase is the gift that keeps giving**: it can store PGP public keys, BTC/Sia/Zcash addresses, and social proofs — all tied to one identity. If a darkweb market admin links their Keybase on their profile page (it happens), you have a free trip from Tor to clearnet.

### Pillar 2 — Stylometry (Writing Style Fingerprinting)

People are creatures of habit. The way someone uses commas, capitalizes "I", misspells "definitely" as "defiantly", or overuses ellipses is a fingerprint that survives translation.

**JGAAP (Java Graphical Authorship Attribution Program)** — Duquesne University, free, used in academic literary attribution. Bundle a corpus of suspect posts vs. a known-author corpus (e.g., a blog written by the suspect) and let the nearest-neighbor classifier score attribution.

**Stylo R package** — the de facto standard for computational stylometry. Operates on n-gram word frequencies with cross-validation.

```r
# Install stylo
install.packages("stylo")

# Corpus layout: two folders
#   corpus/suspect_dpr/   (DPR forum posts)
#   corpus/ulbricht/      (Ross's LinkedIn, GitHub, YouTube comments)
library(stylo)
stylo(
  corpus.dir = "corpus",
  analyzed.features = "w",
  ngram.size = 1,
  classification.method = "delta",
  cross.validation = "leave.one.out"
)
```

Features worth extracting manually:

- Average sentence length (mean and std)
- Comma-per-sentence ratio
- Vocabulary richness (Yule's K, hapax legomena)
- Specific typo patterns ("teh", "defiantly", "loose" for "lose")
- Punctuation tics (" -- ", "....", "smh", "lol")
- Capitalization patterns (title case in casual chat, lowercase always)
- Signature emojis or kaomoji `¯\_(ツ)_/¯`

**Best practices**: collect ≥2,000 words per author for any statistical claim. Below that threshold, stylometry is suggestive but not court-grade.

### Pillar 3 — Timezone Inference

Forum post timestamps are usually UTC. A user's posting histogram reveals their local sleep window.

```python
import pandas as pd
from collections import Counter

# Assume posts have 'ts_utc' ISO timestamps
posts = pd.read_json("dpr_posts.json")
posts['ts_utc'] = pd.to_datetime(posts['ts_utc'])
posts['hour_utc'] = posts['ts_utc'].dt.hour

hist = Counter(posts['hour_utc'])
# Output: hour -> post count

# Sleep window = min-activity 6-hour rolling window
def find_sleep_window(hist):
    best, best_score = None, float('inf')
    for start in range(24):
        window = sum(hist[(start + i) % 24] for i in range(6))
        if window < best_score:
            best_score, best = window, start
    return best  # UTC hour when sleep likely begins
```

If a user's sleep window is 06:00–12:00 UTC, their local time when sleeping starts around 23:00–01:00. That places them in UTC−6 to UTC−7 (US Mountain / Pacific) — or UTC+5 to UTC+7 (South/SE Asia) depending on direction. Cross-reference with language and currency clues to disambiguate.

This is **exactly** what the FBI used against Ross Ulbricht: his DPR posting histogram aligned with his San Francisco wake cycle.

### Pillar 4 — Avatar Reverse Image Search

Default avatars, memes, and stock photos are useless. But when a threat actor uses a **selfie, a personal photo, or a cropped photo of their workspace**, you have a lead.

- **Yandex Image Search** — best-in-class for faces and Cyrillic-web coverage
- **PimEyes** — biometric face search across the open web, paid tier identifies matches
- **Bing Visual Search** — strong for objects and screenshots
- **TinEye** — best for finding exact crops and edited versions
- **FaceCheck.ID** — face-only reverse search

Workflow: extract every avatar from the actor's forum, market, Telegram, and chat app profiles. Run all through Yandex first (free, broadest). If a face match surfaces on Instagram, LinkedIn, or a conference photo site (eventyay, lanyrd), you have a name.

### Pillar 5 — PGP Key Cross-Referencing

Many market vendors and forum admins publish PGP keys for encrypted comms. PGP keys contain metadata:

- **User ID (UID)**: often `Real Name <email@domain>` — sometimes the actor's real email
- **Creation timestamp**: can match a known profile creation date
- **Key server sync**: keys uploaded to keyservers propagate forever — there is no delete

```bash
# Search keys.openpgp.org (privacy-respecting, hides email by default)
gpg --auto-key-locate nodefault,wkd,keyserver --locate-key drib@example.org

# Search keyservers that do NOT scrub emails
gpg --keyserver hkps://keyserver.ubuntu.com --search-key <fingerprint>

# Search MIT keyserver (legacy, still indexed)
curl "https://pgp.mit.edu/pks/lookup?search=<fingerprint>&op=vindex"
```

**Real-world use**: When AlphaBay admin Alexandre Cazes (Alpha02) was being investigated, his PGP key helped confirm continuity between his darkweb admin identity and a personal email used for travel bookings.

### Pillar 6 — Crypto Cashout Tracing

Chainalysis Reactor, TRM Forensics, and OXT Research trace Bitcoin from a forum donation address to a KYC'd exchange. Monero (XMR) breaks this trail but cashout to fiat still requires an XMR→BTC or XMR→fiat swap (FixedFloat, ChangeNOW, SideShift), and many swap services log IP under subpoena.

## Real Cases

### Ross Ulbricht / Dread Pirate Roberts (Silk Road)

The DPR attribution combined every pillar above:

1. **Stack Overflow leak** — Ulbricht asked a question about Tor hidden services using his real name, then changed to "alt account" 60 seconds later — but the edit was scraped.
2. **GitHub** — `rostlib` account with commit timestamps matching San Francisco time.
3. **Forum posts** — DPR's writing style on bitcointalk matched Ulbricht's posts on his LinkedIn-published "Freedom Tower" essays.
4. **Server SSH** — Silk Road server was first administered from Ulbricht's home IP before Tor-only OPSEC was added.
5. **Catch in flagrante** — arrested at the Glen Park library in SF while logged into the admin panel.

### Alexandre Cazes / Alpha02 (AlphaBay)

Cazes was attributed through catastrophic OPSEC failures:

- **Welcome email** on AlphaBay used `Pimp_Alex_91@hotmail.com` — his real name (Alexandre) and birth year (1991)
- **PGP key** with the same email published openly
- **Cashout address** linked to a personal wallet funding his Thai real estate purchases
- **Post timestamps** matching Bangkok time
- Arrested in Bangkok, 2017. Died in custody.

### Allison Hewitt / Takeno

UK-based vendor on multiple markets, attributed via:

- Username reuse on clearnet forums going back to 2009
- Writing style match against a personal blog
- Cashout address that funded a Coinbase account in her real name
- Convicted 2018, sentenced to 7 years.

### Dutchripperz

Dutch vendor specializing in Xanax, attributed after:

- Handle reused on a clearnet gaming forum with his real photo
- Avatar matched to Instagram account via PimEyes
- Arrested 2020; Netherlands police found lab in his home.

### Bidencash / Trump's Dumps

Carding marketplace that, in 2022, dumped 1.2M credit cards for free as a "PR stunt". Attribution attempts pivoted the handle `Bidencash` against clearnet hacking forum history; Russian-named admins `Kvaqthe` and `Smoke.load` were correlated to a Volgograd cybercrew via stylometry (lowercase always, specific emoji set, paranoid quoting patterns). Attribution incomplete but sufficient for sanctions designation.

## Hands-on: Full Attribution Pipeline

```python
#!/usr/bin/env python3
"""Minimum viable attribution pipeline. Assumes you already
have a target handle and have exported the forum's post JSON.
"""
import json
import subprocess
from collections import Counter
from datetime import datetime, timedelta

HANDLE = "dutchripperz"
FORUM_POSTS = "export.json"  # [{"ts_utc": "...", "body": "..."}, ...]

# Step 1 — Username pivot (calls maigret)
subprocess.run(["maigret", HANDLE, "--html", f"{HANDLE}.html",
                "--timeout", "20"], check=True)

# Step 2 — Load posts and compute timezone histogram
posts = json.load(open(FORUM_POSTS))
hours = Counter()
word_freq = Counter()
for p in posts:
    h = datetime.fromisoformat(p["ts_utc"].replace("Z", "+00:00")).hour
    hours[h] += 1
    for w in p["body"].lower().split():
        word_freq[w] += 1

sleep_start = min(range(24), key=lambda s: sum(hours[(s+i) % 24] for i in range(6)))
print(f"[+] Sleep window (UTC): {sleep_start:02d}:00 – {(sleep_start+6)%24:02d}:00")
print(f"[+] Top 20 lexical tokens: {word_freq.most_common(20)}")

# Step 3 — Export stylometry corpus
corpus_dir = f"corpus/{HANDLE}"
import os; os.makedirs(corpus_dir, exist_ok=True)
open(f"{corpus_dir}/all_posts.txt", "w").write(
    "\n\n".join(p["body"] for p in posts)
)
print(f"[+] Corpus saved to {corpus_dir}/ — run stylo against your known-author folder")

# Step 4 — Avatar extraction (assume already scraped to avatars/)
print("[+] Now run: yandex + pimeyes on every file in avatars/")

# Step 5 — PGP lookup on any key fingerprint found in profile
# gpg --keyserver hkps://keys.openpgp.org --search-key <fp>
```

## OPSEC Failures to Avoid (Attacker's View)

For red-team operators and researchers running attribution-resistant identities:

- Never reuse a handle. Generate fresh per-forum handles.
- Build a "writing persona" and never let your real-world style bleed in.
- Rotate timezone by delaying posts with a queue, never posting in real time.
- Use AI-generated faces for avatars (thispersondoesnotexist.com), never memes or photos you also post elsewhere.
- Use a fresh PGP key per identity; never upload to a keyserver with a real email UID.
- Cash out through a chain of swaps and never reuse an address across identities.

## OPSEC Failures by Category

A threat-intel analyst's mental model should group OPSEC failures into five categories, each of which maps to one or more of the six pillars above:

1. **Identity reuse** — same handle, email, or PGP fingerprint on clearnet and darkweb (Cazes / Alpha02). Pivot via Sherlock/Maigret; verify via keyservers.
2. **Temporal leakage** — post timestamps that reveal a sleep window consistent with a specific timezone, then cross-correlated with a suspect's known wake cycle (Ulbricht / DPR). Counter: queue all posts for randomized release.
3. **Linguistic fingerprint** — writing style survives translation and machine paraphrasing. JGAAP and Stylo can match even after the actor changes handles (Hewitt / Takeno). Counter: maintain a "writing persona" with deliberate, consistent stylistic deviations from your real style.
4. **Visual reuse** — avatar, profile banner, or in-photo objects (coffee cup, watch, wallpaper) that match a clearnet photo (Dutchripperz). Counter: AI-generated faces, no original images.
5. **Financial leakage** — donation or cashout address reused across identities, or funding path that ends at a KYC'd exchange (Cazes, Hewitt). Counter: rotate addresses per transaction, swap through XMR, never cashout to a personal exchange account.

Categories 1 and 5 are the most common point of failure because they require active maintenance (generating new keys, addresses, handles) rather than passive OPSEC. Categories 2 and 3 require sustained discipline over years — most actors tire. Category 4 is a one-shot failure mode: a single reused image is game over.

## Hands-on: Cross-Pillar Correlation Worksheet

When you have outputs from multiple pillars, build a single correlation matrix:

| Evidence Type | Source | Finding | Confidence (1-5) |
|---|---|---|---|
| Username pivot | Maigret | Handle on GitHub with commit email `x@y.com` | 4 |
| Stylometry | Stylo Delta | 0.81 distance to suspect blog corpus | 3 |
| Timezone | Post histogram | Sleep window 06:00–12:00 UTC | 4 |
| Avatar | PimEyes | Face match to LinkedIn photo, 92% | 4 |
| PGP UID | keyserver.ubuntu.com | Email in UID matches pivot | 5 |
| BTC trace | Chainalysis Reactor | Donation addr funds KYC'd Coinbase | 5 |

Three or more "5" confidence findings are typically required to support an arrest warrant. Intel teams should treat each row as independently verifiable — a single failed row does not invalidate the matrix, but two failed rows demands re-examination of methodology.

## References

- https://www.justice.gov/usao-ndca/united-states-v-ross-william-ulbricht
- https://www.justice.gov/opa/pr/alpha bay-founder-alexandre-cazes-commits-suicide
- https://www.europol.europa.eu/media-press/newsroom/news/alphabay-and-hansa-takedown
- https://github.com/sherlock-project/sherlock
- https://github.com/Josue87/Maigret
- https://github.com/webbreacher/whatsmyname
- https://stylo.r-forge.r-project.org/
- https://evllabs.com/JGAAP/home/
- https://keys.openpgp.org/
- https://keyserver.ubuntu.com/
- https://pimeyes.com/en
- https://yandex.com/images
- https://facecheck.id/
- https://blog.chainalysis.com/reports/alphabay-bitcoin/
- https://www.trmlabs.com/solutions/forensics/
- https://oxt.me/
- https://www.ncsc.gov.uk/news/dark-web-vendor-jailed
- https://www.flashpoint-intel.com/blog/darkweb-attribution/
