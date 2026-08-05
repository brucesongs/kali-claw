#!/usr/bin/env python3
"""skill-lint.py — SKILL.md quality linter for kali-claw.

Checks:
- YAML frontmatter presence and required fields
- Markdown structure (sections present)
- Defense Triple completeness (Defense Perspective + Detection Methods + Defense Evasion)
- Translation residue (mixed CN/EN)
- Version baseline (v0.2.0.2)
- last_reviewed metadata
- File structure (payloads.md, test-cases.md, guides/)

Usage:
    python3 validation/skill-lint.py                # lint all skills
    python3 validation/skill-lint.py --skill NAME   # lint specific skill
    python3 validation/skill-lint.py --fix          # attempt auto-fix
    python3 validation/skill-lint.py --json         # output JSON report
"""
import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


REQUIRED_YAML_FIELDS = ["name", "description", "version", "compatibility", "allowed-tools", "metadata"]
REQUIRED_METADATA_FIELDS = ["domain", "last_reviewed"]
REQUIRED_SECTIONS = ["## Summary", "## Core Tools", "## Methodology", "## Practical Steps"]
DEFENSE_TRIPLE_STRICT = {
    "Defense Perspective": r"^### Defense Perspective\s*$",
    "Detection Methods": r"^## Detection Methods\s*$",
    "Defense Evasion Techniques": r"^## Defense Evasion Techniques\s*$",
}
EXPECTED_VERSION = "0.2.0.2"
TRANSLATION_RESIDUE_PATTERN = re.compile(r"[a-z][一-鿿]|[一-鿿][a-z]")
SKILLS_DIR = Path("skills")
FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


@dataclass
class LintFinding:
    severity: str  # ERROR, WARN, INFO
    code: str
    message: str
    skill: str = ""
    fix: Optional[str] = None


@dataclass
class LintReport:
    skill: str
    findings: list[LintFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not any(f.severity == "ERROR" for f in self.findings)

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "ERROR")

    @property
    def warn_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "WARN")


def parse_frontmatter(content: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Return (parsed_yaml, raw_text) or (None, None) if missing/malformed."""
    fm_match = FRONTMATTER_RE.match(content)
    if not fm_match:
        return None, None
    fm_text = fm_match.group(1)
    try:
        parsed = yaml.safe_load(fm_text) or {}
        if not isinstance(parsed, dict):
            return None, fm_text
        return parsed, fm_text
    except yaml.YAMLError:
        return None, fm_text


def lint_skill(skill_dir: Path) -> LintReport:
    """Lint a single SKILL directory."""
    skill_name = skill_dir.name
    report = LintReport(skill=skill_name)
    skill_file = skill_dir / "SKILL.md"

    if not skill_file.exists():
        report.findings.append(LintFinding("ERROR", "MISSING_SKILL_MD",
                                            f"SKILL.md not found in {skill_name}"))
        return report

    content = skill_file.read_text(encoding="utf-8", errors="replace")

    # 1. YAML frontmatter (parse + field presence)
    fm, fm_text = parse_frontmatter(content)
    if fm is None:
        report.findings.append(LintFinding("ERROR", "MISSING_FRONTMATTER",
                                           "YAML frontmatter (--- block) is missing or malformed"))
    else:
        for field_name in REQUIRED_YAML_FIELDS:
            if field_name not in fm:
                report.findings.append(LintFinding("ERROR", "MISSING_FIELD",
                                                   f"Required YAML field missing: {field_name}"))
        metadata = fm.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}
        for meta_field in REQUIRED_METADATA_FIELDS:
            if meta_field not in metadata:
                report.findings.append(LintFinding("WARN", "MISSING_METADATA",
                                                   f"metadata.{meta_field} not found"))

    # 2. Version baseline
    version = fm.get("version") if fm else None
    if version is None:
        report.findings.append(LintFinding("ERROR", "VERSION_MISSING",
                                           "No version field found"))
    elif version != EXPECTED_VERSION:
        report.findings.append(LintFinding("WARN", "VERSION_MISMATCH",
                                           f"Version is {version}, expected {EXPECTED_VERSION}",
                                           skill_name))

    # 3. Required sections
    for section in REQUIRED_SECTIONS:
        if not re.search(rf'^{re.escape(section)}', content, re.M):
            report.findings.append(LintFinding("WARN", "MISSING_SECTION",
                                               f"Section not found: {section}"))

    # 4. Defense Triple (strict heading match; honor defense_triple_required: false)
    defense_required = bool(fm.get("defense_triple_required", True)) if fm else True
    if not defense_required:
        report.findings.append(LintFinding("INFO", "DEFENSE_TRIPLE_EXEMPT",
                                           "defense_triple_required: false — Defense Triple checks skipped",
                                           skill_name))
    else:
        # Detect heading-level regressions (H2 instead of H3) for Defense Perspective
        h2_dp = re.search(r"^## Defense Perspective\s*$", content, re.M)
        for name, pattern in DEFENSE_TRIPLE_STRICT.items():
            if not re.search(pattern, content, re.M):
                if name == "Defense Perspective" and h2_dp:
                    report.findings.append(LintFinding("ERROR", "DEFENSE_PERSPECTIVE_WRONG_LEVEL",
                                                       "Defense Perspective uses H2 (##) but should be H3 (###) under ## Defense Triple",
                                                       skill_name,
                                                       fix="sed -i '' 's/^## Defense Perspective$/### Defense Perspective/' SKILL.md"))
                else:
                    report.findings.append(LintFinding("WARN", "MISSING_DEFENSE_TRIPLE",
                                                       f"Defense Triple component missing: {name}"))

    # 5. Translation residue
    residue = len(TRANSLATION_RESIDUE_PATTERN.findall(content))
    if residue > 0:
        report.findings.append(LintFinding("WARN", "TRANSLATION_RESIDUE",
                                           f"{residue} instances of mixed CN/EN text"))

    # 6. File structure
    expected_files = ["SKILL.md", "payloads.md", "test-cases.md"]
    for fname in expected_files:
        if not (skill_dir / fname).exists():
            severity = "WARN" if fname != "SKILL.md" else "ERROR"
            report.findings.append(LintFinding(severity, "MISSING_FILE",
                                               f"Expected file missing: {fname}"))

    guides_dir = skill_dir / "guides"
    if not guides_dir.exists() or not any(guides_dir.iterdir()):
        report.findings.append(LintFinding("INFO", "NO_GUIDES",
                                           "No guides/ directory or empty",
                                           skill_name))

    return report


def main():
    parser = argparse.ArgumentParser(description="kali-claw SKILL quality linter")
    parser.add_argument("--skill", help="Lint a specific SKILL")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--fix", action="store_true", help="Attempt auto-fix (not implemented)")
    args = parser.parse_args()

    if args.skill:
        skill_dir = SKILLS_DIR / args.skill
        if not skill_dir.exists():
            print(f"ERROR: skill '{args.skill}' not found")
            sys.exit(1)
        reports = [lint_skill(skill_dir)]
    else:
        reports = []
        for skill_dir in sorted(SKILLS_DIR.iterdir()):
            if skill_dir.is_dir():
                reports.append(lint_skill(skill_dir))

    total_errors = sum(r.error_count for r in reports)
    total_warnings = sum(r.warn_count for r in reports)

    if args.json:
        output = {
            "total_skills": len(reports),
            "passed": sum(1 for r in reports if r.passed),
            "failed": sum(1 for r in reports if not r.passed),
            "total_errors": total_errors,
            "total_warnings": total_warnings,
            "reports": [
                {
                    "skill": r.skill,
                    "passed": r.passed,
                    "errors": r.error_count,
                    "warnings": r.warn_count,
                    "findings": [
                        {"severity": f.severity, "code": f.code, "message": f.message}
                        for f in r.findings
                    ],
                }
                for r in reports
            ],
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        total = len(reports)
        passed = sum(1 for r in reports if r.passed)

        print(f"\n{'='*60}")
        print(f"kali-claw skill-lint report")
        print(f"{'='*60}")
        print(f"Total skills:    {total}")
        print(f"Passed (no ERR): {passed} ({passed*100//total if total else 0}%)")
        print(f"Failed:          {total - passed}")
        print(f"Total errors:    {total_errors}")
        print(f"Total warnings:  {total_warnings}")
        print(f"{'='*60}\n")

        if total_errors > 0 or args.skill:
            for r in reports:
                if r.findings:
                    print(f"\n--- {r.skill} ---")
                    for f in r.findings:
                        icon = {"ERROR": "❌", "WARN": "⚠️ ", "INFO": "ℹ️ "}.get(f.severity, "  ")
                        print(f"  {icon} [{f.code}] {f.message}")

    sys.exit(1 if total_errors > 0 else 0)


if __name__ == "__main__":
    main()
