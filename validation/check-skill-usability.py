#!/usr/bin/env python3
"""check-skill-usability.py — Three-axis SKILL validator (v0.3.5 methodology, formalized).

Reimplementation of the 2026-09-09 repo-wide validation sweep as a permanent,
reproducible tool. The original /tmp/validate-all.py was ephemeral; this is the
sedimented version (v0.3.8 P2 backlog item).

Axes:
  1. Completeness — six-dimension weighted score (0-100), main ranking sort
     D1 compliance (skill-lint rules)      x1.0
     D2 content volume (payloads+TC lines) x1.0
     D3 command syntax (bash blocks)       x1.5
     D4 references (URLs + 2xCVEs)         x0.8
     D5 MITRE alignment (T-codes)          x1.0
     D6 structure (H2/H3 + guides + TC)    x1.2
     score = weighted_sum / 32.5 * 100
  2. Usability — A/B/C: bash -n on every bash block (placeholder-aware),
     placeholder markers, structural gates (guides>=1, H2>=12, TC>=10 with
     exempt-meta policy)
  3. Reliability — A/B/C: outdated-pattern grep + review freshness;
     optional public-URL liveness spot-check (--urls N)

Whitelist: absorbs TOOLS.md tool names to classify unknown first-tokens in
bash blocks (informational only, does not affect grades).

Usage:
  python3 validation/check-skill-usability.py                      # all skills
  python3 validation/check-skill-usability.py --skill web-sqli     # single skill
  python3 validation/check-skill-usability.py --json out.json
  python3 validation/check-skill-usability.py --ranking docs/RANKING.md
  python3 validation/check-skill-usability.py --urls 30            # liveness spot-check
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
TOOLS_MD = ROOT / "TOOLS.md"

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
BASH_BLOCK_RE = re.compile(r"```bash\n(.*?)```", re.DOTALL)
H2_RE = re.compile(r"^## ", re.MULTILINE)
H3_RE = re.compile(r"^### ", re.MULTILINE)
URL_RE = re.compile(r"https?://[^\s\)\]\"'<>]+")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
TCODE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
PLACEHOLDER_RE = re.compile(r"\b(TODO|FIXME|XXX|PLACEHOLDER|<your|YOUR_KEY)\b")
SESSION_PREFIX_RE = re.compile(r"^(gdb\)|msf\d>|meterpreter>|irb\()", re.IGNORECASE)
ANGLE_PH_RE = re.compile(r"<[A-Za-z0-9_.$@/:-]{1,48}>")
# tool-output transcript lines embedded in bash blocks (commented out pre-check)
OUTPUT_LINE_RE = re.compile(
    r"^(ERROR \d|Query OK|Rows matched|mysql>|psql(=|#)|>>>|PS>|C:\\>|"
    r"sudo password|warning:|FAILED|SUCCESS|Complete!|started|^\s*\^\^\^)", re.IGNORECASE)
# non-shell snippets that appear inside bash fences (documented tolerance)
NONSHELL_RE = re.compile(r"^(def |class |from \w+ import |<script>|<\?php|import (os|sys|re|json)\b)")
# injection payload demo lines: raw payloads are intentionally non-runnable shell
PAYLOAD_LINE_RE = re.compile(
    r"^(;|\||&&|\|\||__PH__|\\\\[0-7]{3}|'\s*OR\s|\"\s*OR\s|\\x|javascript:|%[0-9A-Fa-f]{2}|<[a-zA-Z!/])|\)\(\|", re.IGNORECASE)
# DB / REPL continuation prompts
CONTINUATION_RE = re.compile(r"^(->|=>|\.\.\.|\?|mysql>|sqlplus|SQL>|postgres=#|psql#|->)\s*")
# block-level inference: >=2 signature lines => mixed/non-shell block, skip bash -n
NONBASH_LINE_RE = re.compile(
    r"^\s*(\$[A-Za-z_]\w*\s*=\s*\w|-[A-Z]\w+-[A-Za-z]+|SELECT\s|INSERT INTO|UPDATE \w+ SET|"
    r"Device\w+Events|\\copy|DBMS_\w+|@app\.|console\.log|function\s+\w+\(|"
    r"show\s+(dbs|collections|tables)|use\s+\w+$|db\.\w+\.|[12]>\s)|"
    r"Import-PfxCertificate|ConvertTo-SecureString|Get-Content|Set-ExecutionPolicy|"
    r"^return \w+\(|^SecRule\b|^fetch\(|^\s*[}\]]\s*$")

# v0.3.5 zeroed outdated patterns — regression watchlist
OUTDATED_PATTERNS = {
    "docker-compose command (use docker compose)": r"^docker-compose\s+(up|down|build|pull)",
    "Frida pre-17 API (findExportByName(null))": r"findExportByName\s*\(\s*null",
    "hashcat -O (removed in 6.2+)": r"^hashcat\s[^|\n]*\s-O(\s|$)",
}

# Starter whitelist: shell builtins + coreutils + repo-universal tools.
# Extended at runtime from TOOLS.md tables.
SHELL_WHITELIST = {
    "bash", "sh", "zsh", "dash", "source", "cd", "echo", "printf", "cat", "grep",
    "egrep", "fgrep", "sed", "awk", "cut", "tr", "sort", "uniq", "head", "tail",
    "wc", "tee", "find", "xargs", "which", "whereis", "file", "stat", "ls", "cp",
    "mv", "ln", "mkdir", "rmdir", "touch", "chmod", "chown", "umask", "id", "whoami",
    "sudo", "su", "env", "export", "set", "unset", "alias", "exit", "return",
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done",
    "case", "esac", "function", "local", "read", "sleep", "true", "false", "test",
    "curl", "wget", "git", "ssh", "scp", "rsync", "tar", "gzip", "gunzip", "zip",
    "unzip", "7z", "base64", "openssl", "python", "python2", "python3", "pip",
    "pip3", "perl", "ruby", "node", "npm", "npx", "java", "javac", "go", "cargo",
    "rustc", "make", "cmake", "gcc", "g++", "clang", "ld", "nm", "objdump",
    "readelf", "strings", "xxd", "hexdump", "md5sum", "sha1sum", "sha256sum",
    "nmap", "masscan", "dig", "nslookup", "host", "whois", "ping", "traceroute",
    "tcpdump", "tshark", "wireshark", "netstat", "ss", "lsof", "ps", "top", "htop",
    "kill", "killall", "pkill", "jobs", "fg", "bg", "nohup", "cron", "crontab",
    "systemctl", "service", "journalctl", "docker", "kubectl", "helm", "jq",
    "yq", "xmlstarlet", "column", "paste", "split", "csplit", "dd", "df", "du",
    "free", "uname", "hostname", "date", "cal", "time", "timeout", "watch",
    "man", "less", "more", "vi", "vim", "nano", "diff", "cmp", "patch", "basename",
    "dirname", "realpath", "readlink", "pwd", "pushd", "popd", "dirs", "history",
    "apt", "apt-get", "dpkg", "yum", "dnf", "brew", "pacman", "snap", "flatpak",
    "gh", "aws", "az", "gcloud", "terraform", "ansible", "vagrant", "virtualenv",
    "conda", "uv", "poetry", "black", "ruff", "flake8", "mypy", "pytest", "shellcheck",
    "trash", "srm", "shred", "mount", "umount", "fsck", "sync",
    "sysctl", "iptables", "nft", "ufw", "firewall-cmd", "route", "ip", "ifconfig",
    "brctl", "ovs-vsctl", "wg", "openvpn", "proxychains", "proxychains4",
    "certutil", "reg", "regedit", "schtasks", "sc", "tasklist", "driverquery",
    "netsh", "wmic", "powershell", "cmd",
    "mkfifo", "socat", "nc", "ncat", "netcat",
}


def load_tools_whitelist() -> set:
    """Absorb tool names from TOOLS.md category tables."""
    wl = set(SHELL_WHITELIST)
    if TOOLS_MD.exists():
        for line in TOOLS_MD.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("|"):
                cells = [c.strip() for c in line.strip("|").split("|")]
                if len(cells) >= 2 and cells[0] and "Category" not in cells[0] \
                        and "---" not in cells[0]:
                    for tok in re.split(r"[,/()]+", cells[1]):
                        tok = tok.strip().strip("`*").strip()
                        if tok and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._+-]*", tok):
                            wl.add(tok)
    return wl


def parse_frontmatter(content: str) -> dict:
    m = FRONTMATTER_RE.match(content)
    if not m:
        return {}
    try:
        import yaml
        parsed = yaml.safe_load(m.group(1)) or {}
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


@dataclass
class SkillResult:
    name: str
    score: float = 0.0
    grade: str = "Poor"
    usability: str = "A"
    reliability: str = "A"
    payload_lines: int = 0
    tc_lines: int = 0
    tc_count: int = 0
    h2: int = 0
    h3: int = 0
    guides: int = 0
    bash_blocks: int = 0
    bash_errors: int = 0
    payload_blocks: int = 0
    mixed_blocks: int = 0
    tolerated_blocks: int = 0
    urls: int = 0
    cves: int = 0
    tcodes: int = 0
    placeholders: int = 0
    outdated: list = field(default_factory=list)
    unknown_cmds: int = 0
    review_age_days: int = -1
    exempt_meta: bool = False
    dim: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    dead_urls: list = field(default_factory=list)


def _bashn(code: str) -> bool:
    """Single bash -n over a code string."""
    if not code.strip():
        return True
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as tf:
        tf.write(code)
        path = tf.name
    try:
        return subprocess.run(["bash", "-n", path], capture_output=True,
                              text=True, timeout=10).returncode == 0
    except Exception:
        return False
    finally:
        os.unlink(path)


def bash_n_check(blocks: list) -> tuple:
    """Placeholder-aware bash -n. Preprocessing (documented, matches v0.3.5 intent):
    <token> placeholders -> __PH__; session/output transcripts commented;
    embedded python/php/js snippet lines commented; raw payload demo lines and
    DB continuation prompts commented; blocks with >=2 non-bash signature lines
    (PowerShell/SQL/KQL) skipped as mixed-content. Blocks failing whole-block
    bash -n fall back to segment tolerance: split on blank lines, majority of
    segments parsing => tolerated (mixed prose), else genuine error.
    Returns (blocks, errors, payload_blocks, mixed_blocks, tolerated)."""
    errors = payload_blocks = mixed_blocks = tolerated = 0
    for raw in blocks:
        raw_lines = raw.splitlines()
        nonempty = [ln for ln in raw_lines if ln.strip()]
        pl = sum(1 for ln in raw_lines if PAYLOAD_LINE_RE.search(ln))
        nb = sum(1 for ln in raw_lines if NONBASH_LINE_RE.search(ln))
        if pl >= 2 or (nonempty and pl / len(nonempty) >= 0.3):
            payload_blocks += 1   # payload showcase — syntax gate N/A
            continue
        if nb >= 2:
            mixed_blocks += 1     # multi-language block — fence-relabel candidate
            continue
        lines = []
        for ln in raw.splitlines():
            if SESSION_PREFIX_RE.match(ln):          # session transcripts
                continue
            if PLACEHOLDER_RE.search(ln):            # TODO/FIXME markers
                continue
            if OUTPUT_LINE_RE.match(ln):             # tool output transcript
                lines.append("# " + ln)
                continue
            if NONSHELL_RE.match(ln):                # embedded non-shell snippet
                lines.append("# " + ln)
                continue
            if PAYLOAD_LINE_RE.match(ln):              # raw payload demo line
                lines.append("# " + ln)
                continue
            if CONTINUATION_RE.match(ln):              # DB/REPL continuation
                lines.append("# " + ln)
                continue
            # placeholder-aware: <token> -> __PH__ (valid identifier)
            lines.append(ANGLE_PH_RE.sub("__PH__", ln))
        code = "\n".join(lines)
        if not code.strip():
            continue
        if _bashn(code):
            continue
        # segment tolerance: split on blank lines; if a majority of segments
        # parse, the block is mixed-content prose (tolerated, informational).
        segs = [seg for seg in re.split(r"\n\s*\n", code) if seg.strip()]
        if segs and sum(1 for seg in segs if _bashn(seg)) * 2 >= len(segs):
            tolerated += 1
            continue
        errors += 1
    return len(blocks), errors, payload_blocks, mixed_blocks, tolerated


def first_tokens(blocks: list, whitelist: set) -> int:
    """Count unknown first-tokens (informational whitelist-gap metric)."""
    unknown = set()
    for raw in blocks:
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            m = re.match(r"^(?:sudo\s+|env\s+\S+\s+)?([a-zA-Z0-9._/-]+)", ln)
            if not m:
                continue
            tok = m.group(1).split("/")[-1]
            if tok and tok not in whitelist and not tok.startswith(("$", "-")):
                unknown.add(tok)
    return len(unknown)


def band(value, bands):
    for threshold, score in bands:
        if value >= threshold:
            return score
    return 1.0


def analyze_skill(skill_dir: Path, whitelist: set):
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return None
    fm = parse_frontmatter(skill_md.read_text(encoding="utf-8", errors="replace"))
    if not fm:
        return None
    meta = fm.get("metadata") or {}
    r = SkillResult(name=fm.get("name", skill_dir.name))
    r.exempt_meta = not bool(fm.get("defense_triple_required", True))

    files_text = ""
    for f in sorted(skill_dir.rglob("*.md")):
        rel = f.relative_to(skill_dir).as_posix()
        if rel.startswith("evidence/"):
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        files_text += "\n" + text
        if rel == "payloads.md":
            r.payload_lines = len(text.splitlines())
        if rel == "test-cases.md":
            r.tc_lines = len(text.splitlines())
            # TC headings use both ## and ### across the repo (baseline counts both)
            r.tc_count = len(re.findall(r"^#{2,3}\s+TC-", text, re.M))
        if rel.startswith("guides/"):
            r.guides += 1  # baseline convention: usage-and-assessment counts
    r.h2 = len(H2_RE.findall(files_text))
    r.h3 = len(H3_RE.findall(files_text))

    blocks = BASH_BLOCK_RE.findall(files_text)
    (r.bash_blocks, r.bash_errors, r.payload_blocks,
     r.mixed_blocks, r.tolerated_blocks) = bash_n_check(blocks)
    r.unknown_cmds = first_tokens(blocks, whitelist)

    urls = {u for u in URL_RE.findall(files_text)
            if not any(h in u for h in ("example.com", "example.lab", "attacker",
                                        "target.example", "$ORIGIN", "$ST_", "$(date"))}
    r.urls = len(urls)
    r.cves = len(set(CVE_RE.findall(files_text)))
    r.tcodes = len(set(TCODE_RE.findall(files_text)))
    r.placeholders = len(PLACEHOLDER_RE.findall(files_text))
    # strip full/trailing comments so explanatory prose ("# -O removed in...")
    # is not flagged as live usage
    decommented = "\n".join(re.sub(r"#.*$", "", ln) for ln in files_text.splitlines())
    for label, pat in OUTDATED_PATTERNS.items():
        if re.search(pat, decommented, re.M):
            r.outdated.append(label)

    reviewed = str(meta.get("last_reviewed") or "")
    if reviewed:
        try:
            r.review_age_days = (date.today() -
                                 datetime.strptime(reviewed, "%Y-%m-%d").date()).days
        except ValueError:
            pass

    # ---- Axis 1: Completeness
    d1 = 5.0
    d2 = band(r.payload_lines + r.tc_lines,
              [(700, 5.0), (400, 4.5), (300, 4.0), (150, 3.0), (80, 2.0)])
    if r.bash_errors:
        d3 = 1.0
    elif r.bash_blocks >= 12:
        d3 = 4.0
    elif r.bash_blocks >= 6:
        d3 = 3.5
    else:
        d3 = 3.0
    d4 = band(r.urls + 2 * r.cves,
              [(20, 5.0), (14, 4.5), (10, 4.0), (6, 3.0), (3, 2.0)])
    d5 = band(r.tcodes, [(6, 5.0), (4, 4.0), (2, 3.0), (1, 2.0)])
    d6 = band(r.h2, [(35, 5.0), (25, 4.5), (18, 4.0), (12, 3.0)])
    if r.guides < 1:
        d6 = max(1.0, d6 - 1.0)
    if r.tc_count < 10 and not r.exempt_meta:
        d6 = max(1.0, d6 - 1.0)
    if r.exempt_meta:
        r.notes.append("exempt meta: TC gate waived")

    r.dim = {"D1": d1, "D2": d2, "D3": d3, "D4": d4, "D5": d5, "D6": d6}
    weighted = d1 * 1.0 + d2 * 1.0 + d3 * 1.5 + d4 * 0.8 + d5 * 1.0 + d6 * 1.2
    r.score = round(weighted / 32.5 * 100, 1)
    r.grade = ("Excellent" if r.score >= 80 else
               "Good" if r.score >= 70 else
               "Fair" if r.score >= 60 else "Poor")

    # ---- Axis 2: Usability
    gaps = 0
    if r.bash_errors:
        gaps += 2
    if r.placeholders > 10:
        gaps += 1
    if r.h2 < 12:
        gaps += 1
    if r.tc_count < 10 and not r.exempt_meta:
        gaps += 1
    if r.guides < 1:
        gaps += 1
    r.usability = "A" if gaps == 0 else "B" if gaps == 1 else "C"

    # ---- Axis 3: Reliability (offline portion)
    rel = 0
    if r.outdated:
        rel += 2
    if 0 <= r.review_age_days > 90:
        rel += 1
    r.reliability = "A" if rel == 0 else "B" if rel == 1 else "C"
    return r


def url_liveness(result: SkillResult, top_n: int, timeout: int = 12) -> None:
    """Optional spot-check of public URLs (mutates dead_urls)."""
    import urllib.request
    text = ""
    for f in sorted((SKILLS_DIR / result.name).rglob("*.md")):
        if "evidence" not in f.parts:
            text += f.read_text(encoding="utf-8", errors="replace")
    urls = [u for u in sorted(set(URL_RE.findall(text)))
            if not any(h in u for h in ("example.com", "example.lab", "attacker",
                                        "target.example", "$ORIGIN"))][:top_n]

    def check(u):
        try:
            req = urllib.request.Request(u, method="HEAD",
                                         headers={"User-Agent": "kali-claw-validator"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return None if resp.status < 400 else u
        except Exception:
            return u  # unreachable from this host — flagged for manual review

    with ThreadPoolExecutor(max_workers=8) as ex:
        result.dead_urls = [u for u in ex.map(check, urls) if u]


def render_ranking(results: list, out: Path, url_mode: bool) -> None:
    today = date.today().isoformat()
    scores = [r.score for r in results]
    dist = {g: sum(1 for r in results if r.grade == g)
            for g in ("Excellent", "Good", "Fair", "Poor")}
    us = {g: sum(1 for r in results if r.usability == g) for g in "ABC"}
    rel = {g: sum(1 for r in results if r.reliability == g) for g in "ABC"}
    lines = [
        f"# SKILL Validation & Completeness Ranking — {today}",
        "",
        f"> **Scope**: all {len(results)} SKILL domains | **Tool**: "
        "`validation/check-skill-usability.py` (v0.3.8 formalization of the "
        "2026-09-09 three-axis methodology)",
        "> **Baseline lineage**: supersedes `SKILL_VALIDATION_RANKING_2026-09-09.md` "
        "(scores may differ ±2 vs the informal original — formula is now fixed)",
        f"> **URL liveness**: "
        f"{'spot-checked (--urls mode)' if url_mode else 'not re-run this cycle (offline reliability only)'}",
        "",
        "## 1. Methodology",
        "",
        "| Axis | Definition | Grading |",
        "|------|------------|---------|",
        "| **Completeness** | D1 lint ×1.0, D2 (payloads+TC lines) ×1.0, D3 bash-blocks ×1.5, "
        "D4 (URLs + 2×CVEs) ×0.8, D5 T-codes ×1.0, D6 (H2/H3+guides+TC) ×1.2 → /32.5×100 | "
        "Excellent ≥80 / Good 70-79 / Fair 60-69 / Poor <60 |",
        "| **Usability** | bash -n (placeholder-aware, transcripts skipped) + placeholder "
        "markers + gates (guides≥1, H2≥12, TC≥10; exempt-meta TC gate waived) | "
        "A clean / B one gap / C multiple |",
        "| **Reliability** | outdated-pattern grep (docker-compose cmd, Frida pre-17, "
        "hashcat -O) + last_reviewed freshness (>90d = gap) | A clean / B one / C multiple |",
        "",
        "## 2. Summary Statistics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Skills validated | {len(results)} |",
        f"| Completeness avg / min / max | {sum(scores)/len(scores):.1f} / "
        f"{min(scores):.1f} / {max(scores):.1f} |",
        f"| Excellent / Good / Fair / Poor | {dist['Excellent']} / {dist['Good']} / "
        f"{dist['Fair']} / {dist['Poor']} |",
        f"| Usability A / B / C | {us['A']} / {us['B']} / {us['C']} |",
        f"| Reliability A / B / C (offline) | {rel['A']} / {rel['B']} / {rel['C']} |",
        f"| bash blocks with syntax errors | {sum(r.bash_errors for r in results)} |",
        f"| payload-showcase blocks (gate N/A) | {sum(r.payload_blocks for r in results)} |",
        f"| mixed-language blocks (relabel candidates) | {sum(r.mixed_blocks for r in results)} |",
        f"| tolerated mixed-prose blocks (segment majority passes) | {sum(r.tolerated_blocks for r in results)} |",
        f"| outdated patterns | {sum(len(r.outdated) for r in results)} |",
        "",
        "## 3. Top 20 (completeness)",
        "",
        "| # | SKILL | Score | Grade | Usability | Reliability |",
        "|---|-------|-------|-------|-----------|-------------|",
    ]
    for i, r in enumerate(sorted(results, key=lambda x: (-x.score, x.name))[:20], 1):
        lines.append(f"| {i} | {r.name} | {r.score} | {r.grade} | "
                     f"{r.usability} | {r.reliability} |")
    lines += ["", "## 4. Bottom 10 (completeness)", "",
              "| # | SKILL | Score | Grade | Usability | Reliability | Notes |",
              "|---|-------|-------|-------|-----------|-------------|-------|"]
    bottom = sorted(results, key=lambda x: (x.score, x.name))[:10]
    for i, r in enumerate(bottom, len(results) - 9):
        lines.append(f"| {i} | {r.name} | {r.score} | {r.grade} | {r.usability} | "
                     f"{r.reliability} | {'; '.join(r.notes) or '—'} |")
    lines += ["", f"## 5. Full Ranking ({len(results)})", "",
              "| # | SKILL | Score | Grade | Us | Rel | TC | Guides | H2 | URLs | "
              "CVEs | T | BashErr | UnkCmds |",
              "|---|-------|-------|-------|----|----|----|--------|----|------|"
              "------|---|---------|---------|"]
    for i, r in enumerate(sorted(results, key=lambda x: (-x.score, x.name)), 1):
        lines.append(f"| {i} | {r.name} | {r.score} | {r.grade} | {r.usability} | "
                     f"{r.reliability} | {r.tc_count} | {r.guides} | {r.h2} | "
                     f"{r.urls} | {r.cves} | {r.tcodes} | {r.bash_errors} | "
                     f"{r.unknown_cmds} |")
    lines += ["", "## 6. Findings Register", ""]
    issues = [r for r in results if r.bash_errors or r.outdated or
              (r.placeholders > 10) or (url_mode and r.dead_urls)]
    if not issues:
        lines.append("- None — all gates green.")
    for r in sorted(issues, key=lambda x: x.name):
        parts = []
        if r.bash_errors:
            parts.append(f"{r.bash_errors} bash-block syntax errors")
        if r.outdated:
            parts.append("outdated: " + "; ".join(r.outdated))
        if r.placeholders > 10:
            parts.append(f"{r.placeholders} placeholder markers")
        if url_mode and r.dead_urls:
            parts.append(f"unreachable URLs: {', '.join(r.dead_urls[:3])}")
        lines.append(f"- **{r.name}**: {'; '.join(parts)}")
    lines += ["", "## 7. Reproduce", "", "```bash",
              "python3 validation/check-skill-usability.py "
              "--ranking docs/SKILL_VALIDATION_RANKING_$(date +%F).md",
              "```", ""]
    out.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skill", help="validate a single skill")
    ap.add_argument("--json", metavar="PATH", help="write JSON results")
    ap.add_argument("--ranking", metavar="PATH", help="write ranking markdown report")
    ap.add_argument("--urls", type=int, default=0, metavar="N",
                    help="spot-check first N public URLs per skill (network)")
    args = ap.parse_args()

    whitelist = load_tools_whitelist()
    dirs = ([SKILLS_DIR / args.skill] if args.skill
            else sorted(d for d in SKILLS_DIR.iterdir() if d.is_dir()))
    results = []
    for d in dirs:
        r = analyze_skill(d, whitelist)
        if r:
            results.append(r)
        elif args.skill:
            print(f"ERROR: {args.skill} not found or missing frontmatter",
                  file=sys.stderr)
            return 1
    if not results:
        print("No skills found", file=sys.stderr)
        return 1

    if args.urls:
        for r in results:
            url_liveness(r, args.urls)

    if args.json:
        Path(args.json).write_text(
            json.dumps([asdict(r) for r in results], ensure_ascii=False, indent=2)
            + "\n", encoding="utf-8")
    if args.ranking:
        render_ranking(results, Path(args.ranking), bool(args.urls))

    err = sum(r.bash_errors for r in results)
    out = sum(len(r.outdated) for r in results)
    ph = sum(r.placeholders for r in results)
    scores = [r.score for r in results]
    print("=" * 60)
    print("kali-claw check-skill-usability report")
    print("=" * 60)
    print(f"Skills:            {len(results)}")
    print(f"Score avg/min/max: {sum(scores)/len(scores):.1f} / "
          f"{min(scores):.1f} / {max(scores):.1f}")
    print(f"Bash errors: {err}   Outdated: {out}   Placeholders: {ph}")
    if args.skill:
        print(json.dumps(asdict(results[0]), ensure_ascii=False, indent=2))
    return 0 if err == 0 and out == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
