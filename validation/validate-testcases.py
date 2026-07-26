#!/usr/bin/env python3
"""validate-testcases.py — Validate test-cases.md files for kali-claw SKILLs.

Checks:
- File exists
- Minimum test case count (>=5)
- AAA pattern (Arrange, Act, Assert) presence
- Clear expected results
- No placeholders

Usage:
    python3 validation/validate-testcases.py                # validate all
    python3 validation/validate-testcases.py --skill NAME   # validate one
    python3 validation/validate-testcases.py --json         # JSON output
"""
import argparse
import json
import re
import sys
from pathlib import Path

SKILLS_DIR = Path("skills")
MIN_TEST_CASES = 5
AAA_PATTERNS = [
    r"\bArrange\b", r"\bAct\b", r"\bAssert\b",
    r"\bObjective\b", r"\bExpected\b", r"\bPrerequisites\b",
    r"\bStep\b", r"\bResult\b",
]


def validate_testcases(skill_dir: Path) -> dict:
    """Validate test-cases.md for a single SKILL."""
    skill_name = skill_dir.name
    tc_file = skill_dir / "test-cases.md"

    result = {
        "skill": skill_name,
        "exists": tc_file.exists(),
        "errors": [],
        "warnings": [],
        "stats": {},
    }

    if not tc_file.exists():
        result["errors"].append("test-cases.md not found")
        return result

    content = tc_file.read_text(encoding="utf-8", errors="replace")
    lines = content.count("\n")

    # Count test cases (## TC- patterns or ### TC- patterns)
    tc_count = len(re.findall(r"^##+\s*(TC-|Test Case|TC\d)", content, re.M))
    if tc_count == 0:
        # Alternative: count "## " sections that look like test cases
        tc_count = len(re.findall(r"^##+\s+\d+\.", content, re.M))

    # Check AAA pattern
    aaa_found = sum(1 for p in AAA_PATTERNS if re.search(p, content, re.IGNORECASE))

    # Check for placeholders
    placeholders = len(re.findall(r"\b(TODO|FIXME|PLACEHOLDER)\b", content, re.IGNORECASE))

    result["stats"] = {
        "lines": lines,
        "test_cases": tc_count,
        "aaa_keywords_found": aaa_found,
        "placeholders": placeholders,
    }

    if tc_count < MIN_TEST_CASES:
        result["warnings"].append(f"Only {tc_count} test cases (minimum {MIN_TEST_CASES})")

    if aaa_found < 3:
        result["warnings"].append(f"AAA pattern keywords found: {aaa_found}/8 (recommend ≥3)")

    if placeholders:
        result["warnings"].append(f"Found {placeholders} placeholder markers")

    return result


def main():
    parser = argparse.ArgumentParser(description="Validate test-cases.md files")
    parser.add_argument("--skill", help="Validate a specific SKILL")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.skill:
        skill_dir = SKILLS_DIR / args.skill
        if not skill_dir.exists():
            print(f"ERROR: skill '{args.skill}' not found")
            sys.exit(1)
        results = [validate_testcases(skill_dir)]
    else:
        results = []
        for skill_dir in sorted(SKILLS_DIR.iterdir()):
            if skill_dir.is_dir():
                results.append(validate_testcases(skill_dir))

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        total = len(results)
        existing = sum(1 for r in results if r["exists"])
        with_errors = sum(1 for r in results if r["errors"])
        with_warnings = sum(1 for r in results if r["warnings"])
        total_tcs = sum(r["stats"].get("test_cases", 0) for r in results)

        print(f"\n{'='*60}")
        print(f"test-cases.md validation report")
        print(f"{'='*60}")
        print(f"Total skills:   {total}")
        print(f"Existing:       {existing}")
        print(f"Total test cases: {total_tcs}")
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
