#!/usr/bin/env python3
"""gen-skill-handbook.py — Regenerate SKILL_INDEX.json + SKILL_HANDBOOK.md.

Ground truth is the live skills/ tree (frontmatter + files), never the stale
index. This keeps the two artifacts reproducible and enables a --check drift
gate for monthly reviews / CI.

Outputs:
  docs/SKILL_INDEX.json    — machine-readable index (schema-compatible with v0.3.0)
  docs/SKILL_HANDBOOK.md   — human-readable handbook, grouped by domain

Usage:
  python3 validation/gen-skill-handbook.py             # regenerate both
  python3 validation/gen-skill-handbook.py --check     # exit 1 on drift
  python3 validation/gen-skill-handbook.py --index-only
  python3 validation/gen-skill-handbook.py --handbook-only
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
INDEX_PATH = ROOT / "docs" / "SKILL_INDEX.json"
HANDBOOK_PATH = ROOT / "docs" / "SKILL_HANDBOOK.md"

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
DEFENSE_TRIPLE_STRICT = {
    "Defense Perspective": r"^### Defense Perspective\s*$",
    "Detection Methods": r"^## Detection Methods\s*$",
    "Defense Evasion Techniques": r"^## Defense Evasion Techniques\s*$",
}


def parse_frontmatter(content: str) -> dict:
    m = FRONTMATTER_RE.match(content)
    if not m:
        return {}
    try:
        parsed = yaml.safe_load(m.group(1)) or {}
        return parsed if isinstance(parsed, dict) else {}
    except yaml.YAMLError:
        return {}


def collect_skill_files(skill_dir: Path) -> list[str]:
    """Relative file inventory, excluding evidence/, .DS_Store, and zips."""
    files = []
    for p in sorted(skill_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(skill_dir).as_posix()
        if rel.startswith("evidence/") or rel == ".DS_Store" or rel.endswith(".zip"):
            continue
        files.append(rel)
    return files


def scan_skills() -> list[dict]:
    """Scan skills/ as ground truth. Fail hard on any skill without valid frontmatter."""
    skills = []
    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            print(f"ERROR: {skill_dir.name}/ has no SKILL.md — not a skill directory",
                  file=sys.stderr)
            sys.exit(1)
        content = skill_md.read_text(encoding="utf-8", errors="replace")
        fm = parse_frontmatter(content)
        if not fm:
            print(f"ERROR: {skill_dir.name}/SKILL.md has invalid/missing frontmatter",
                  file=sys.stderr)
            sys.exit(1)

        metadata = fm.get("metadata") or {}
        defense_required = bool(fm.get("defense_triple_required", True))
        triple = {
            "has_defense_perspective": defense_required and bool(
                re.search(DEFENSE_TRIPLE_STRICT["Defense Perspective"], content, re.M)),
            "has_detection": defense_required and bool(
                re.search(DEFENSE_TRIPLE_STRICT["Detection Methods"], content, re.M)),
            "has_evasion": defense_required and bool(
                re.search(DEFENSE_TRIPLE_STRICT["Defense Evasion Techniques"], content, re.M)),
        }

        skills.append({
            "name": fm.get("name", skill_dir.name),
            "description": (fm.get("description") or "").strip(),
            "version": str(fm.get("version", "")),
            "domain": metadata.get("domain") or "uncategorized",
            "category": metadata.get("category") or "general",
            "mitre": metadata.get("mitre") or "N/A",
            "owasp": fm.get("owasp") or metadata.get("owasp") or "",
            "last_reviewed": str(metadata.get("last_reviewed") or ""),
            "files": collect_skill_files(skill_dir),
            "defense_triple_required": defense_required,
            **triple,
        })
    return skills


def build_index(skills: list[dict]) -> dict:
    domains: dict[str, list[str]] = {}
    for s in sorted(skills, key=lambda x: x["name"]):
        domains.setdefault(s["domain"], []).append(s["name"])
    version = (ROOT / "VERSION").read_text().strip() if (ROOT / "VERSION").exists() else "dev"
    return {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "kali_claw_version": version,
            "total_skills": len(skills),
            "total_domains": len(domains),
            "skill_version": "0.2.0.2",
            "source": "regenerated from skills/ frontmatter by validation/gen-skill-handbook.py",
        },
        "domains": {k: sorted(v) for k, v in sorted(domains.items())},
        "skills": {s["name"]: s for s in sorted(skills, key=lambda x: x["name"])},
    }


def render_handbook(index: dict) -> str:
    meta = index["metadata"]
    skills = index["skills"]
    domains = index["domains"]
    lines = [
        "# kali-claw SKILL 使用手册",
        "",
        f"> **版本**: {meta['kali_claw_version']} | **生成日期**: {meta['generated_at'][:10]} | "
        f"**SKILL 总数**: {meta['total_skills']} / **域数**: {meta['total_domains']}",
        "> 本文件由 `validation/gen-skill-handbook.py` 自动生成（以 skills/ frontmatter 为权威源），请勿手工编辑。",
        "",
        "---",
        "",
        "## 目录",
        "",
    ]
    anchors = []
    for domain, names in domains.items():
        anchor = re.sub(r"[^a-z0-9-]+", "-", domain.lower()).strip("-")
        anchors.append((domain, anchor, len(names)))
    lines += [f"- [{d}](#{a}) ({n} 个 SKILL)" for d, a, n in anchors]
    lines += ["", "---", ""]

    for domain, anchor, _count in anchors:
        lines += [f"## {domain}", ""]
        for name in domains[domain]:
            s = skills[name]
            triple_parts = []
            if s["defense_triple_required"]:
                triple_parts = [
                    "Defense Perspective " + ("✓" if s["has_defense_perspective"] else "✗"),
                    "Detection Methods " + ("✓" if s["has_detection"] else "✗"),
                    "Defense Evasion " + ("✓" if s["has_evasion"] else "✗"),
                ]
            else:
                triple_parts = ["exempt (defense_triple_required: false)"]
            reviewed = f" | reviewed {s['last_reviewed']}" if s["last_reviewed"] else ""
            owasp = f" | **OWASP**: {s['owasp']}" if s["owasp"] else ""
            lines += [
                f"### {name}",
                "",
                f"**版本**: {s['version']} | **域**: {s['domain']} | "
                f"**MITRE**: {s['mitre']}{owasp}{reviewed}",
                "",
                f"> {s['description']}",
                "",
                f"**Defense Triple**: {' | '.join(triple_parts)}",
                "",
                f"**文件** ({len(s['files'])}): {', '.join(s['files'])}",
                "",
                "---",
                "",
            ]
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="compare generated output with on-disk files; exit 1 on drift")
    ap.add_argument("--index-only", action="store_true", help="only regenerate SKILL_INDEX.json")
    ap.add_argument("--handbook-only", action="store_true", help="only regenerate SKILL_HANDBOOK.md")
    args = ap.parse_args()

    skills = scan_skills()
    index = build_index(skills)
    drift = False

    if not args.handbook_only:
        rendered = json.dumps(index, ensure_ascii=False, indent=2) + "\n"
        if args.check:
            if INDEX_PATH.exists() and INDEX_PATH.read_text(encoding="utf-8") != rendered:
                print("DRIFT: docs/SKILL_INDEX.json is stale", file=sys.stderr)
                drift = True
            else:
                print("OK: docs/SKILL_INDEX.json is fresh")
        else:
            INDEX_PATH.write_text(rendered, encoding="utf-8")
            print(f"wrote {INDEX_PATH.relative_to(ROOT)} "
                  f"({index['metadata']['total_skills']} skills / "
                  f"{index['metadata']['total_domains']} domains)")

    if not args.index_only:
        handbook = render_handbook(index)
        if args.check:
            if HANDBOOK_PATH.exists() and HANDBOOK_PATH.read_text(encoding="utf-8") != handbook:
                print("DRIFT: docs/SKILL_HANDBOOK.md is stale", file=sys.stderr)
                drift = True
            else:
                print("OK: docs/SKILL_HANDBOOK.md is fresh")
        else:
            HANDBOOK_PATH.write_text(handbook, encoding="utf-8")
            print(f"wrote {HANDBOOK_PATH.relative_to(ROOT)} ({len(handbook.splitlines())} lines)")

    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
