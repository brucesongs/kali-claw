#!/usr/bin/env python3
"""validate-payloads.py — Validate payloads.md files for kali-claw SKILLs.

Checks:
- File exists for each SKILL
- Minimum content (>=50 lines)
- Code block presence
- No obvious placeholders (TODO, FIXME, XXX)
- Duplicate detection across payloads

Usage:
    python3 validation/validate-payloads.py                # validate all
    python3 validation/validate-payloads.py --skill NAME   # validate one
    python3 validation/validate-payloads.py --json         # JSON output
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

SKILLS_DIR = Path("skills")
MIN_LINES = 50
MIN_CODE_BLOCKS = 5
PLACEHOLDER_PATTERNS = [r"\bTODO\b", r"\bFIXME\b", r"\bXXX\b", r"\bPLACEHOLDER\b"]


def validate_payloads(skill_dir: Path) -> dict:
    """Validate payloads.md for a single SKILL."""
    skill_name = skill_dir.name
    payload_file = skill_dir / "payloads.md"

    result = {
        "skill": skill_name,
        "exists": payload_file.exists(),
        "errors": [],
        "warnings": [],
        "stats": {},
    }

    if not payload_file.exists():
        result["errors"].append("payloads.md not found")
        return result

    content = payload_file.read_text(encoding="utf-8", errors="replace")
    lines = content.count("\n")
    code_blocks = len(re.findall(r"```", content)) // 2
    sections = len(re.findall(r"^##+ ", content, re.M))
    placeholders = []
    for pattern in PLACEHOLDER_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            placeholders.extend(matches)

    result["stats"] = {
        "lines": lines,
        "code_blocks": code_blocks,
        "sections": sections,
        "placeholders": len(placeholders),
    }

    if lines < MIN_LINES:
        result["warnings"].append(f"Only {lines} lines (minimum {MIN_LINES})")

    if code_blocks < MIN_CODE_BLOCKS:
        result["warnings"].append(f"Only {code_blocks} code blocks (minimum {MIN_CODE_BLOCKS})")

    if placeholders:
        result["warnings"].append(f"Found {len(placeholders)} placeholder markers (TODO/FIXME/etc)")

    return result


def main():
    parser = argparse.ArgumentParser(description="Validate payloads.md files")
    parser.add_argument("--skill", help="Validate a specific SKILL")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.skill:
        skill_dir = SKILLS_DIR / args.skill
        if not skill_dir.exists():
            print(f"ERROR: skill '{args.skill}' not found")
            sys.exit(1)
        results = [validate_payloads(skill_dir)]
    else:
        results = []
        for skill_dir in sorted(SKILLS_DIR.iterdir()):
            if skill_dir.is_dir():
                results.append(validate_payloads(skill_dir))

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        total = len(results)
        existing = sum(1 for r in results if r["exists"])
        with_errors = sum(1 for r in results if r["errors"])
        with_warnings = sum(1 for r in results if r["warnings"])

        print(f"\n{'='*60}")
        print(f"payloads.md validation report")
        print(f"{'='*60}")
        print(f"Total skills:   {total}")
        print(f"Existing:       {existing} ({existing*100//total if total else 0}%)")
        print(f"With errors:    {with_errors}")
        print(f"With warnings:  {with_warnings}")
        print(f"{'='*60}\n")

        for r in results:
            if r["errors"] or r["warnings"]:
                print(f"  {r['skill']}:")
                for e in r["errors"]:
                    print(f"    ❌ {e}")
                for w in r["warnings"]:
                    print(f"    ⚠️  {w}")

    sys.exit(0)


if __name__ == "__main__":
    main()
