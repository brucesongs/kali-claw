# Dark Web Intelligence: Real-World Incident Case Studies

## Overview

This guide catalogs twelve landmark cyber incidents between 2021 and 2024 where dark web intelligence played a decisive role in attribution, response, or disruption. Each case study examines the timeline, the threat actor group behind the attack, the dark web platforms used for negotiation and data publication, the categories of leaked data, and the intelligence takeaways that defenders can fold back into their programs.

The cases span ransomware affiliates (DarkSide, REvil, Conti, LockBit, BlackCat/ALPHV, Clop, BlackSuit), underground marketplace takedowns (Hydra, BreachForums, RaidForums), and doxxing / data-broker incidents (Yanluo Pan, Celsius). Together they form a representative picture of the modern dark web threat economy: access brokers, RaaS operators, initial access brokers, dual-extortion leak sites, and law enforcement counter-operations.

The goal is not to glorify operators but to give analysts a reference frame: when a victim appears on a leak site, which playbook is being run, what the operator's negotiation history looks like, and where to look for corroborating telemetry (bitcoin flows, forum posts, Telegram channels, paste mirrors). All dates and actor names are drawn from public indictments, CISA advisories, BKA / DOJ press releases, and Mandiant / Chainalysis reports cited in the References section.

## Hands-on

The following workflow is how a dark web intelligence analyst works a new incident in 2024, using the case studies below as reference material. Treat every command as OPSEC-sensitive: run from a dedicated analyst workstation, ideally a Whonix or Tails VM with no link to your corporate identity.

### Step 1: Detect and Triage the Leak

```bash
# Poll the three major ransomware leak sites that are still live via a Tor proxy
# Example: curl through torsocks to fetch the latest victim list
torsocks curl -s -A "Mozilla/5.0 (analyst)" \
  http://lockbitcaptcha6cmvrzgzdr7lprt5fvlhdj5t7krvnda6oy4d3lh3qggid.onion/api/posts \
  | jq '.posts[] | {id, title, posted_at}'

# Cross-reference with Recorded Future / Intel 471 / Flashpoint APIs
# (commercial feeds — replace API_KEY with your org's)
curl -H "X-RFToken: $RF_API_KEY" \
  "https://api.recordedfuture.com/v2/ransomware/victims?limit=100" \
  | jq '.data[] | select(.group == "lockbit")'
```

### Step 2: Identify the Threat Actor Group

For each victim, classify which playbook is in use by mapping observed TTPs to known crews:

| Indicator | Likely Crew | Reference Case |
|-----------|-------------|----------------|
| US fuel/pipeline victim, May 2021 | DarkSide | Colonial Pipeline |
| MSP supply chain, July 2021 | REvil | Kaseya |
| Russian-language forum ads for access | LockBit | LockBit 2024 |
| ALPHV-themed Tor site, Rust binary | BlackCat | Change Healthcare |
| Zero-day in managed file transfer | Clop | MOVEit (CVE-2023-34362) |

### Step 3: Trace the Bitcoin / Monero Flows

```bash
# Use Chainalysis Reactor (subscription) or open-source OSINT
# Wget a known ransom wallet address from a leak site
ADDR="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"

# Query the public mempool.space API for transaction history
curl -s "https://mempool.space/api/address/$ADDR/txs" \
  | jq '[.[] | {txid, total: .status.total, time}] | .[0:10]'
```

### Step 4: Document Findings in the Intel Report

Maintain a per-incident markdown dossier including: leak-site screenshots, wallet addresses, transaction graph exports, attacker Telegram handles, and a CVE mapping. This is the artifact you will hand to legal, to insurance, and (if asked) to law enforcement.

## Step-by-step Case Studies

### 1. Colonial Pipeline — DarkSide (May 2021)

On 7 May 2021 Colonial Pipeline, the largest fuel pipeline in the United States, shut down all 5,500 miles of pipeline after DarkSide affiliates encrypted its billing and operational support networks. The outage caused fuel shortages across the East Coast and triggered a major federal response. DarkSide, a Russian-speaking RaaS operation, used a compromised VPN password to gain initial access. The group published a victim entry on its Tor leak site and demanded roughly 75 BTC. Colonial paid approximately 75 BTC (~$4.4M at the time). On 7 June 2021 the US Department of Justice announced that the FBI's Rapid Action Team had seized 63.7 BTC from the DarkSide affiliate wallet, the first major public demonstration of ransom recovery. DarkSide announced its dissolution days later under pressure from Russian-speaking peers who feared US retaliation. Intel takeaways: assume VPN credentials are the entry vector; deploy FIDO2 MFA on all remote access; treat the affiliate's wallet, not the operator's, as the primary attribution signal.

### 2. Kaseya — REvil (July 2021)

On 2 July 2021 the REvil ransomware crew exploited zero-day vulnerabilities (CVE-2021-30116, CVE-2021-30117) in Kaseya VSA, a remote management platform widely used by MSPs, to push ransomware to roughly 1,500 downstream organizations. REvil demanded $70M for a universal decryptor. The attack bypassed VSA monitoring and gave the attackers the ability to push an unsigned agent to every endpoint the MSP managed. On 13 July 2021 Kaseya obtained a universal decryptor through an undisclosed channel, widely reported to be a law-enforcement-brokered deal with an REvil insider. In October 2021 REvil's infrastructure was taken offline through a multi-country law enforcement operation, and key operator Yaroslav Vasinskyi was arrested in Poland and later extradited to the United States. Intel takeaways: supply chain attacks via MSP tooling are a tier-one risk; inventory all remote management appliances and patch on a 24-hour SLA for critical CVEs.

### 3. Hydra Marketplace Takedown (April 2022)

On 5 April 2022 the German Bundeskriminalamt (BKA) and the US Department of Justice coordinated the takedown of Hydra Market, the longest-running and largest Russian-language dark web marketplace. Hydra had operated since 2015 and, at its peak, accounted for roughly 80% of dark web drug trafficking in the German-speaking world. German authorities seized Hydra's server infrastructure in Germany and confiscated approximately $25M worth of bitcoin. The DOJ indicted Dmitry Pavlov, a Russian national, for conspiracy to distribute narcotics and conspiracy to commit money laundering, alleging he operated the infrastructure Hydra used to communicate with its buyers and sellers. The takedown also disrupted Hydra's elaborate cash-out network of "treasure men" who converted cryptocurrency to rubles via dead drops. Intel takeaways: marketplace takedowns have a measurable chilling effect but are typically followed within 60-90 days by successor markets; monitor Russian-language forums for the migration of Hydra vendors.

### 4. LockBit — Operation Cronos (February 2024)

On 19 February 2024 the UK National Crime Agency, FBI, Europol, and partners announced Operation Cronos, the seizure of LockBit's primary and affiliate infrastructure. LockBit was at the time the most prolific ransomware crew in the world, responsible for thousands of attacks since 2019. Law enforcement took control of the leak site, replaced it with a seizure banner, and seized over 1,000 decryption keys that were made available to victims. The NCA also published internal LockBit chat logs, affiliate panels, and build configurations, exposing the group's negotiation tactics, victim prioritization, and even the identity of the administrator known as "LockBitSupp." A subsequent May 2024 update revealed that law enforcement had gained persistent access to LockBit's infrastructure and continued to monitor affiliate activity even after the public takedown. Intel takeaways: ransomware crews are not immune to insider compromise; the published LockBit panels are a goldmine for understanding affiliate psychology and should be ingested into threat intel platforms.

### 5. BreachForums and RaidForums Takedowns (2022-2023)

RaidForums, founded in 2015, was one of the largest English-language cybercrime forums for buying and selling stolen databases. On 12 April 2022 the FBI seized RaidForums and arrested its administrator, Diogo Santos Coelho, in the United Kingdom. Coelho was later extradited to the United States and pleaded guilty in 2024. BreachForums emerged in mid-2022 as the spiritual successor, quickly becoming the go-to venue for selling data stolen from companies like Twitter (5.4M records in January 2022), AT&T, and Optus. On 15 March 2023 the FBI seized the first iteration of BreachForums and indicted its administrator Conor Brian Fitzpatrick ("pompompurin"), who pleaded guilty in June 2023. BreachForums was reconstituted at least twice more and remains a recurring threat. Intel takeaways: forum seizures are temporary but disruptive; track the migration of sellers across reincarnations and archive listings rapidly because seized domains are volatile.

### 6. BlackCat / ALPHV Shutdown (March 2024)

BlackCat, also known as ALPHV or Noberus, was a Rust-based RaaS operation that emerged in November 2021 and became the second-most-active crew by 2023. On 5 December 2023 a coordinated FBI takedown seized BlackCat's Tor sites and offered decryptors to over 500 victims. The crew responded by hijacking its own infrastructure back from law enforcement and continued operating. The saga culminated in March 2024 with the Change Healthcare incident: ALPHV affiliates allegedly extorted a $22M payment from UnitedHealth Group, then conducted an "exit scam" against their own affiliate, who was left without their cut. The affiliate then partnered with RansomHub to re-extort the victim. Intel takeaways: trust between operators and affiliates is brittle; intra-criminal disputes are a powerful intelligence source and can be observed via affiliate complaints on Russian-language forums.

### 7. Conti Playbook Leak (February 2022)

In late February 2022 a Ukrainian security researcher using the handle "contaminantleaks" began publishing the Conti ransomware group's internal chat logs, source code, and operational playbooks in response to Conti's public support of Russia's invasion of Ukraine. Over 170,000 internal messages between Conti leaders and affiliates were released across multiple dumps through September 2022. The Conti Leaks revolutionized the industry's understanding of how a major ransomware crew operates: salaries, shift schedules, on-call rotations, performance reviews, and explicit negotiation scripts. They revealed that Conti operated as a corporate entity with HR, brand management, and an internal knowledge base. The leaks also exposed the human side of operators — names, cryptocurrency addresses, and personal disputes. Intel takeaways: treat operator infrastructure as a targetable asset; the Conti Leaks remain the single best source of ground-truth on RaaS internals and should be required reading for any ransomware analyst.

### 8. Yanluo Pan Social Media Doxx (Ongoing)

Yanluo Pan is a Chinese national indicted in the US in September 2024 for her alleged role in a multi-year harassment and doxxing campaign targeting US military personnel, government officials, and dissidents. Operating at least since 2021 under the alias "Plump," Pan allegedly worked on behalf of Iran's Islamic Revolutionary Guard Corps (IRGC) to surveil and intimidate targets via social media platforms, messaging apps, and dark web paste sites. While not a ransomware incident, the case illustrates the convergence of state-aligned influence operations and dark web doxxing infrastructure. Intel takeaways: monitor state-aligned actors who blend social media OSINT with paste-site publication; doxxing campaigns are frequently a precursor to physical surveillance or swatting.

### 9. Celsius Network Data Leak (2022)

Celsius Network, a cryptocurrency lending platform that filed for bankruptcy in July 2022, suffered a series of data exposure incidents tied to its bankruptcy proceedings. In addition to regulatory disclosures, attacker groups exploited the public visibility of Celsius court filings to target customers with phishing and impersonation scams. Some Celsius customer data was offered for sale on dark web markets, and the case became a textbook example of "dual extortion" extending into the bankruptcy context, where attackers leverage publicly mandated disclosures to lend credibility to their extortion claims. Intel takeaways: in any regulated disclosure scenario, prepare customer-facing fraud monitoring; fraud teams should treat court filings as a fresh OSINT source for attackers.

### 10. MOVEit — Clop Ransomware (May 2023)

In late May 2023 the Clop ransomware crew, also known as Cl0p, began exploiting a zero-day SQL injection vulnerability (CVE-2023-34362) in Progress Software's MOVEit Transfer file-transfer product. The campaign ultimately affected more than 2,500 organizations and over 93 million individuals, making it one of the largest mass-exploitation events in history. Clop used the vulnerability to steal data rather than encrypt it, then extorted victims via their dedicated leak site, posting names of organizations that refused to pay. Notable victims included the US Department of Energy, Shell, the BBC, British Airways, and numerous state and local governments. Clop did not deploy ransomware in this campaign; the crew had refined their "data theft only" extortion model in prior zero-day campaigns against Accellion FTA (2021) and GoAnywhere MFT (early 2023). Intel takeaways: managed file transfer appliances are a high-value target; monitor vendor advisories continuously and isolate these appliances in dedicated network segments with egress filtering.

### 11. Change Healthcare — BlackCat (February 2024)

In late February 2024 BlackCat / ALPHV affiliates breached Change Healthcare, a UnitedHealth Group subsidiary that processes roughly one-third of US patient records. The attack caused weeks of disruption to pharmacies, hospitals, and billing systems across the United States. UnitedHealth Group confirmed paying a $22M ransom in bitcoin in March 2024. As noted above, ALPHV then exit-scammed its affiliate, who re-extorted via RansomHub, resulting in additional payments reportedly around $22M. The incident exposed the systemic risk of concentrated healthcare infrastructure and the brittle trust model of RaaS affiliate relationships. Intel takeaways: map third-party critical infrastructure dependencies; assume any single-vendor dependency is a single point of failure; watch for re-extortion when an operator exit-scams.

### 12. CDK Global — BlackSuit (June 2024)

In June 2024 the BlackSuit ransomware crew attacked CDK Global, a software provider serving roughly 15,000 car dealerships in North America. The attack caused multi-week outages across the US auto retail sector, with dealers reverting to paper-based processes. CDK reportedly paid two separate ransoms totaling tens of millions of dollars. BlackSuit is closely linked to the Royal ransomware crew and inherited much of Royal's code and affiliate base. The case demonstrated that even mid-tier crews can cause systemic disruption when their victim is a critical vertical SaaS provider. Intel takeaways: vertical SaaS concentration is the new MSP problem; perform tabletop exercises with operational continuity in mind, not just data recovery.

## Cross-Case Intelligence Patterns

Across these twelve cases several patterns emerge that should inform any dark web intelligence program. First, ransomware crews cycle through RaaS brands, and an apparent shutdown often precedes a rebrand (Conti → Black Basta / BlackCat; REvil → RansomHub; DarkSide → BlackMatter). Track operators, not brand names. Second, the affiliate model means that the same access broker may sell to multiple operators; access broker activity on Russian-language forums is a leading indicator of imminent intrusions. Third, leak sites have a predictable lifecycle: announcement, posted-victim listing, countdown timer, data release, deletion. Knowing where in the lifecycle a victim is determines the response window. Fourth, cryptocurrency tracing remains the strongest attribution signal, and Monero adoption by crews like LockBit is forcing analysts to develop new tracing techniques (covered in a companion guide).

## Defensive Recommendations

Operationalize the lessons from these case studies: deploy FIDO2 multi-factor authentication on all remote access (Colonial Pipeline, BlackCat), inventory and segment managed file transfer appliances (MOVEit, GoAnywhere, Accellion), monitor Russian-language forums for your organization's name and domain (Conti Leaks, BreachForums), maintain an internal threat intel dossier per ransomware crew with current wallet addresses and affiliate handles, and tabletop both data recovery and operational continuity scenarios (CDK Global, Change Healthcare). Engage with a reputable ransomware negotiation firm in advance, and pre-establish a relationship with FBI cyber field offices and InfraGard.

## References

1. FBI Press Release: Department of Justice Seizes $2.3M in Cryptocurrency Paid to the Ransomware Extortionists DarkSide — https://www.justice.gov/opa/pr/department-justice-seizes-23-million-cryptocurrency-paid-ransomware-extortionists-darkside
2. CISA / FBI / NSA Joint Cybersecurity Advisory: DarkSide Ransomware (AA21-131A) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a
3. DOJ Press Release: Kaseya Ransomware Indictment, Yaroslav Vasinskyi — https://www.justice.gov/opa/pr/ukrainian-national-arrested-charged-conducting-ransomware-attacks-against-kaseya
4. BKA / Bundeskriminalamt: Hydra Takedown Press Release (German/English) — https://www.bka.de/DE/Presse/Listenseite_Pressemitteilungen/2022/Pressemitteilung_05_04_2022_Hydra.html
5. NCA: Operation Cronos — LockBit Takedown — https://www.nationalcrimeagency.gov.uk/news/operation-cronos
6. DOJ: BreachForums Administrator Conor Fitzpatrick Indictment — https://www.justice.gov/usao-sdny/pr/brooklyn-man-charged-operating-breachforums-computer-hacking-forum
7. Mandiant: Noberus (BlackCat / ALPHV) Technical Analysis — https://www.mandiant.com/resources/analysis/noberus-blackcat-ransomware
8. Chainalysis: 2024 Crypto Crime Report (Ransomware Section) — https://www.chainalysis.com/blog/2024-crypto-crime-report/
9. Conti Leaks Archive (Verified Translation) — https://github.com/Nuzmy54/conti-leaks-translated
10. CISA: MOVEit Transfer Vulnerability CVE-2023-34362 Advisory — https://www.cisa.gov/news-events/alerts/2023/06/05/cisa-and-partners-investigating-compromise-moveit
11. Mandiant: Zero-Day Extortion Campaigns by UNC2589 / Clop — https://www.mandiant.com/resources/clop-zero-day-campaigns
12. UnitedHealth Group 8-K Filing on Change Healthcare Cyber Incident — https://www.unitedhealthgroup.com/newsroom/2024/2024-03-18-uhg-provides-update-on-cyberattack.html
13. FBI Most Wanted: Dmitry Olegovich Pavlov (Hydra) — https://www.fbi.gov/wanted/cyber/dmitry-olegovich-pavlov
14. DOJ: Yanluo Pan / Plump IRGC Doxxing Indictment — https://www.justice.gov/opa/pr/three-iranians-charged-cyber-campaign-targeting-us-government-and-critical-infrastructure
15. Ransomware Tracker (abuse.ch) — https://ransomware.tehillimShield.com/ — and RansomLook — https://www.ransomlook.io/
