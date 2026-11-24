# Tool Drift Rotation — 2026-11-25

## Scope and Method

- **Cadence slot**: Tuesday tool drift, Top 10 rotation.
- **Baseline**: `KALI_TOOLS_BASELINE_2026_09.md`.
- **Comparison channel**: authoritative upstream release pages/APIs.
- **Selection**: Top 10 distinct tools. Wireshark covers both Wireshark and tshark because they share one source package; Nuclei replaces the duplicate source row.
- **Reason for upstream comparison**: several baseline values track upstream releases. Kali package lag is useful operational data, but it is not the same axis and must not be reported as product drift.

## Results

| Rank | Tool | 2026-09 baseline | Upstream current | Relationship | Action |
|-----:|------|------------------|------------------|--------------|-------|
| 1 | strings / GNU binutils | 2.42 rolling | 2.46.1 (2026-06-08) | Same major | Defer to quarterly baseline |
| 2 | nmap | 7.99 | 7.993 (2026-10-23) | Same major | Defer to quarterly baseline |
| 3 | docker / Docker Engine | 29.8.1 | 29.10.1 (2026-11-24) | Same major | Defer; include current security-fix context |
| 4 | openssl | 4.0.2 / 3.5.8 LTS | 4.1.0 / 3.5.9 LTS (2026-10-23) | 4.0 → 4.1 series change | Queue D2 compatibility review |
| 5 | burp | 2026.9.1 | 2026.11.2 (2026-11-18) | Same product year | Defer to quarterly baseline |
| 6 | tcpdump | 4.99.4 | 4.99.7 (2026-09-21) | Same major | Defer to quarterly baseline |
| 7 | wireshark / tshark | 4.6.9 | 4.6.10 | Same major | Defer to quarterly baseline |
| 8 | sqlmap | 1.10 | 1.10.11 (2026-10-30) | Same major | Defer to quarterly baseline |
| 9 | ffuf | 2.1.0 | 2.2.1 (2026-07-13) | Same major | Defer to quarterly baseline |
| 10 | nuclei | 3.16.1+ | 3.11.1 (2026-08-08) | Baseline contradiction | Correct during D1 |

**Decision**: no first-token MAJOR jump occurred, so no skill was changed for tool compatibility. Nine tools moved forward; one baseline value is contradicted by upstream. Record findings and preserve the quarterly 2026-12-14..18 remediation window.

## Findings

### F-2026-11-25-01 — P1: Nuclei baseline value is unsupported

The September file says **3.16.1+**, but GitHub's latest stable release is **v3.11.1**, published 2026-08-08. Keep the burden of proof on the baseline: unless a stronger upstream source for 3.16.1 is found, replace it with 3.11.1 on D1.

### F-2026-11-25-02 — P2: source dimension is implicit

Observed splits:

| Tool | Upstream | Kali tracker |
|------|----------|--------------|
| Burp | 2026.11.2 | 2026.7 |
| Wireshark | 4.6.10 | 4.6.9 |
| Docker Engine | 29.10.1 | docker.io 27.5.1 |

The December baseline should label each row as `upstream-stable` or `kali-rolling`. This prevents distribution lag from being misclassified as product drift.

### F-2026-11-25-03 — P2: checker lacks a source-aware rotation mode

`check-tool-versions.py` is still valuable for a local Kali host, but it parses all Top-N rows and probes apt/binary state. It cannot reproduce this evidence from a stored source map. Add `--tools` and source-manifest mode as backlog; do not weaken the existing local probe.

## Source Manifest

- GNU binutils: https://ftp.gnu.org/gnu/binutils/
- Nmap: https://nmap.org/dist/?C=M&O=D
- Docker Engine: https://docs.docker.com/engine/release-notes/29/
- OpenSSL: https://www.openssl.org/source/
- Burp Suite: https://portswigger.net/burp/releases/professional-community-2026-11-2
- tcpdump: https://www.tcpdump.org/
- Wireshark: https://www.wireshark.org/download.html
- sqlmap: https://github.com/sqlmapproject/sqlmap/releases/tag/1.10.11
- ffuf: https://github.com/ffuf/ffuf/releases/tag/v2.2.1
- Nuclei: https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1
