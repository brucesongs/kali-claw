# Darkweb Intel: I2P, Freenet, and Alt-Overlay Monitoring

## Introduction

Tor dominates darkweb intelligence reporting, but it is only one of several overlay networks. When a market gets seized or a forum gets DDoS'd, communities migrate — frequently to I2P (Invisible Internet Project), Freenet, or one of the newer "ZeroNet / IPFS / Lokinet" ecosystems. Analysts who can only crawl Tor miss the post-takedown diaspora every time.

This guide covers the four alternative overlays a darkweb analyst must be able to monitor: **I2P**, **Freenet**, **Lokinet/Hyphanet**, and **ZeroNet/IPFS**. For each we cover architecture, addressing, discovery tooling, and historical cases (Hansa migration, BlueSky I2P mirror, BlackSprut's Lokinet trial). We finish with a comparative OPSEC matrix for analysts running their own sensors.

## Tor Recap — Why It Isn't Enough

Tor uses a global "directory authority" consensus to publish the list of relays, and onion services self-publish their introduction points. This is great for usability but creates centralized choke points: the directories can be enumerated by anyone, and the network's small relay count means a single adversary can run a meaningful fraction of guard/middle/exit bandwidth (see Carnegie Mellon / CMU civil-subpoena case, 2014). Takedowns (Silk Road, AlphaBay, Hansa, Hydra) repeatedly push vendors to overlays with **federated** or **distributed** trust models — which is exactly what I2P and Freenet offer.

## I2P — Invisible Internet Project

### Architecture

I2P is a **garlic-routed** overlay (vs. Tor's onion routing). Each user runs a single I2P router that participates in a distributed network database (netDb, a modified Kademlia DHT). Traffic flows through bidirectional **tunnels** — outbound (you → destination) and inbound (destination → you), each typically 2–3 hops. Tunnels rotate every 10 minutes.

Key differences from Tor:

| Property | Tor | I2P |
|---|---|---|
| Routing unit | Cells (onion) | Messages (garlic) |
| Tunnel lifetime | ~10 min circuit | 10 min tunnels, rotated |
| Directory | Centralized consensus | Distributed netDb (Kademlia) |
| Exit nodes | Yes (exit relays) | Server-less by default; "outproxies" optional |
| Peer discovery | Hard-coded dirauths | Floodfill routers, gossip |

### Addressing — B32, B64, and .i2p

I2P destinations are 384-byte Elligator2-encoded ElGamal public keys. Because that's unmemorable, two encodings exist:

- **B32** — SHA-256 of the destination, base32-encoded, suffixed `.b32.i2p` (e.g., `ukkosvobgctxhbvl2yjylwjkyg2gcgwtbisl6fzwnpxqetjf6glq.b32.i2p`). 52 chars, stable, derived from key. **No address book lookup needed.**
- **B64** — base64 of the full destination key (516 chars). Used inside protocols.
- **Named destinations** (`example.i2p`) — short addresses resolved via the address book subscription service (hosts.txt).

For analyst work, **B32 addresses are the durable identifier**. A market rebranding from `acme.i2p` to `acme2.i2p` keeps the same B32 if the operator didn't rotate keys.

### Eepsite Discovery

There is no Google for I2P. Discovery routes:

1. **Address book subscriptions** — `http://identiguy.i2p/`, `http://stats.i2p/`, `http://inr.i2p/` publish curated host lists. Subscribe your router to refresh.
2. **Crawlers** — `regproxy`, `i2pcrawl`, and the open-source `sybil-i2p` sensor.
3. **Forums** — `notbob.i2p` forum, Irc2P channels `#i2p`, `#i2p-chat`.
4. **NetDb polling** — floodfill routers see every leaseSet published; polling floodfills gives you real-time eepsite enumeration without subscription services.

```bash
# Install I2Pd (C++ router, lighter than the Java i2p.i2p)
sudo apt install i2pd
sudo systemctl enable --now i2pd

# Or run from Docker with sensible defaults
docker run -d --name i2pd \
  -p 127.0.0.1:4444:4444 \
  -p 127.0.0.1:7070:7070 \
  -v $HOME/.i2pd:/home/i2pd/.i2pd \
  purplei2p/i2pd:latest

# Verify connectivity — your router should integrate within 5–10 min
curl http://127.0.0.1:7070/  # i2pd web console
```

### Hands-on: Polling NetDb for Eepsite Inventory

```python
#!/usr/bin/env python3
"""Poll an I2P floodfill for leaseSets via the i2pcontrol API.
This gives you a near-real-time list of active eepsites."""
import requests, base64, json, time

I2PCONTROL = "http://127.0.0.1:7650"
PASSWORD = open("/home/i2pd/.i2pd/i2pcontrol.conf").read().split("password=")[1].strip()

s = requests.Session()
# Authenticate
s.post(I2PCONTROL + "/RouterInfo", json={
    "id": 1, "method": "Authenticate",
    "params": {"API_pw": PASSWORD}, "jsonrpc": "2.0"
})

# Enumerate known leaseSets via RouterInfo + NetworkDatabase
seen = set()
for _ in range(60):  # 60 polls, 30s apart = 30min observation
    r = s.post(I2PCONTROL + "/NetworkDatabase", json={
        "id": 2, "method": "LeaseSetListing",
        "params": {}, "jsonrpc": "2.0"
    })
    for ls in r.json().get("result", {}).get("leasesets", []):
        if ls not in seen:
            seen.add(ls)
            print("[+]", ls)
    time.sleep(30)
```

For deeper enumeration, run **sybil-i2p** (github.com/EcheHermoso/sybil-i2p), which deploys multiple virtual floodfill instances to maximise leaseSet visibility. This is the closest thing to a Shodan for I2P.

### Monitoring Tools

- **I2Pd** — C++ router, lower memory than Java i2p.i2p, ideal for sensors
- **i2p.i2p** — official Java router, full feature set
- **sybil-i2p** — floodfill-deployment sensor for netDb enumeration
- **i2psnark** — embedded BitTorrent over I2P
- **Identiguy** — hosts.txt subscription service, useful for pivot lists
- **Irc2P** — I2P-native IRC, monitored by `i2p-irc-crawl`

## Freenet (Hyphanet)

### Architecture

Freenet is a **peer-to-peer data store**. Content is inserted into the network as encrypted blocks replicated across peer caches; no single peer knows what it is storing. There is no real-time messaging built in — it is a publishing substrate. Two modes:

- **Darknet mode (F2F)** — you connect only to friends you trust. Content still propagates across the friendship graph globally.
- **Opennet mode** — you connect to random strangers via the opennet seed nodes.

For darkweb analysts, **darknet-mode Freenet is the harder target** — you cannot join without an invitation, so monitoring requires either HUMINT (an invite) or running a honeypot that actors request to connect to.

### Addressing — SSK, USK, CHK

- **CHK@** — Content Hash Key; immutable content, address derived from SHA-256 of content + crypto key
- **SSK@** — Signed Subspace Key; signed mutable content (think RSS feed)
- **USK@** — Updatable SSK; versioned, used for "freesites"

Addresses look like `SSK@abc123.../sitename/-1/index.html`. The base32 hash is the publisher's public key fingerprint.

### Discovery

Freenet indexes exist inside the network itself: `Freesite Index`, `Enzos`, `The Freenet Link Board`. Outside-in discovery tools include:

- **Freenet crawler** (Python, github.com/freenet/fred-tools) — runs as a plugin inside your Freenet node
- **Frost** — Freenet-native message board system, historically the darkweb forum layer
- **FCPv2 (Freenet Client Protocol)** — Python/Java client you script to query the node:

```python
# Python FCP client — pyfcp (deprecated but functional)
# pip install fcp
from fcp import FCPNode
node = FCPNode(host="127.0.0.1", port=9481)
# Insert a freesite / fetch a CHK
result = node.get("SSK@example.../index.html")
print(result)
```

## ZeroNet, IPFS, and Lokinet

### ZeroNet (now actively maintained as "ZeroNetX" / "Hyphanet-ZeroNet")

BitTorrent-backed clearnet/darknet hybrid. Sites are static HTML served from a BitTorrent swarm; each visitor also seeds. Tor mode wraps the BitTorrent traffic through Tor. Discovery is via `ZeroHello`, the built-in site list at `1HeLLo4uzjaLetx6nh3prw1fu2N5ZjsDcb`. Easily crawlable from a single ZeroNet client; law enforcement has done so (ZeroNet child abuse material busts 2020–2022).

### IPFS Gateways

IPFS itself is clearnet-by-default, but gateways like `ipfs.io/ipfs/<CID>` can be reached over Tor, and content is immutable — perfect for leak-site mirrors. CID (Content Identifier) extraction via `ipfs.io` gateway scrape or the `ipfs-cid-search` OSINT tool. Real example: Conti ransomware leaked data on IPFS in 2021–2022 to evade hosting takedowns.

### Lokinet (Lokidisi / Oxen)

Lokinet is a **network-layer** onion router — it tunnels L3 traffic, so you can run any application over it (not just TCP). Run by the Oxen project (formerly Loki), it uses onion-routed SNApps (Service Nodes). Less adoption than I2P/Freenet but has been trialled by **BlackSprut** and **Kraken Market** as a fallback when Tor was being actively attacked.

### Hyphanet

Hyphanet is the rebrand of Freenet proper (2023). Same protocol, same team, name change to avoid brand confusion with "free internet" marketing. All Freenet tooling still applies.

## Comparative OPSEC for Analysts

When **you** are the sensor, your choice of overlay determines the footprint you leave:

| Property | Tor | I2P | Freenet darknet | Lokinet |
|---|---|---|---|---|
| Start time to useful | <1 min | 5–10 min | 10–20 min | 1–2 min |
| Default exit | Yes | No (outproxy opt-in) | No | No |
| Adversary visibility into sensor | High (dirauths enumerate) | Medium (netDb polling) | Low (F2F invite only) | Medium |
| Best analyst use | Onionsite crawl | Eepsite inventory | Freesite archive | SNApp discovery |
| Burn-the-sensor cost | Low (cheap VPS) | Low–med (router seed) | High (need invite graph) | Med |

Best practice for serious darkweb-monitoring infrastructure: run **separate, isolated sensors per overlay** with distinct fingerprints. A single VPS that's simultaneously a Tor relay, I2P floodfill, and Freenet node paints a target on itself and pollutes any traffic-analysis conclusions.

## Hands-on: Multi-Overlay Sensor Stack

```bash
# Sensor 1 — Tor sensor
docker run -d --name tor-sensor \
  -v $HOME/tor-sensor:/var/lib/tor \
  alpine:latest sh -c "apk add tor && tor -SocksPort 0 -ControlPort 9051"

# Sensor 2 — I2P floodfill
docker run -d --name i2p-sensor \
  -p 127.0.0.1:7070:7070 \
  -v $HOME/.i2pd:/home/i2pd/.i2pd \
  purplei2p/i2pd:latest
# Enable floodfill in i2pd.conf: [floodfill] enabled=true

# Sensor 3 — Freenet node (Java)
docker run -d --name freenet-sensor \
  -p 127.0.0.1:8888:8888 \
  -p 127.0.0.1:9481:9481 \
  -v $HOME/freenet:/data \
  hyphanet/fred:latest

# Sensor 4 — Lokinet router
docker run -d --name lokinet-sensor --privileged \
  -v $HOME/lokinet:/root/.lokinet \
  oxen-io/lokinet:latest
```

Each sensor ships logs to a central SIEM (ELK, Splunk, or OpenSearch). Tag every event with `overlay=tor|i2p|freenet|lokinet` so your correlation queries don't conflate them.

## Real Cases

### Hansa Market Migration (2017)

When AlphaBay was seized (July 2017), Hansa Market saw a 5x traffic spike. **Dutch NHC had already taken over Hansa covertly** and was logging everything. Many vendors, fearing further takedowns, prepared I2P mirrors. A few actually launched them (`hansa-reborn.b32.i2p`) and were promptly enumerated by NHC sensors running I2Pd. The Hansa case is the canonical example of **multi-overlay monitoring** by law enforcement.

### BlueSky I2P Mirror (2022)

Russian-language market BlueSky launched an I2P mirror at `bluesky-xK4...b32.i2p` after their Tor server was DDoSed by a competitor. The mirror was discovered via a floodfill subscription service (identiguy.i2p) and tracked by Flashpoint. The mirror was active for ~90 days before being decommissioned.

### BlackSprut and Lokinet Trial (2023–2024)

BlackSprut, a Russia-targeting market, briefly operated a Lokinet SNApp mirror during a wave of Tor DDoS attacks by KillNet in 2023. Recorded Future documented the trial in their 2024 deepweb landscape report. The mirror was abandoned when Tor stability returned — Lokinet's smaller SNApp pool offered less anonymity than BlackSprut's Tor hidden service.

### Conti + IPFS Leaks (2021–2022)

The Conti ransomware crew published leaked victim data on IPFS to bypass clearnet hosting takedowns. CIDs were distributed via Tor leak site and Telegram. Analysts at Recorded Future and Volexity built CID-watch pipelines that polled the IPFS DHT every 5 minutes for CIDs matching victim names.

### ZeroNet CSAM Takedowns (2020–2022)

German BKA, in coordination with Europol, conducted a series of takedowns targeting ZeroNet-hosted child sexual abuse material. ZeroNet's BitTorrent substrate meant that seizing a single server did nothing — every visitor was also a host. Investigators pivoted to IP-level tracking of seeding peers, leading to ~50 arrests across 2021.

## References

- https://geti2p.net/en/docs/how/cryptography
- https://geti2p.net/en/docs/how/network-database
- https://github.com/PurpleI2P/i2pd
- https://github.com/EcheHermoso/sybil-i2p
- https://identiguy.i2p/
- https://freenetproject.org/
- https://hyphanet.org/
- https://github.com/freenet/fred
- https://docs.ipfs.tech/
- https://lokinet.org/
- https://docs.oxen.io/
- https://zeronet.io/
- https://github.com/HelloZeroNet/ZeroNet
- https://www.europol.europa.eu/media-press/newsroom/news/hansa-takedown
- https://recordedfuture.com/research/darkweb-overlays
- https://www.flashpoint-intel.com/blog/bluesky-i2p-mirror
- https://volexity.com/blog/2022/03/conti-ipfs-leaks/
- https://www.bka.de/EN/Start/startseite_node.html
