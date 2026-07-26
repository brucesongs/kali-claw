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
from typing import Optional


REQUIRED_YAML_FIELDS = ["name", "description", "version", "compatibility", "allowed-tools", "metadata"]
REQUIRED_METADATA_FIELDS = ["domain", "last_reviewed"]
REQUIRED_SECTIONS = ["## Summary", "## Core Tools", "## Methodology", "## Practical Steps"]
DEFENSE_TRIPLE_SECTIONS = {
    "Defense Perspective": r"Defense Perspective",
    "Detection Methods": r"^## Detection Methods",
    "Defense Evasion Techniques": r"^## Defense Evasion Techniques",
}
EXPECTED_VERSION = "0.2.0.2"
TRANSLATION_RESIDUE_PATTERN = re.compile(r"[a-z][一-鿿]|[一-鿿][a-z]")
SKILLS_DIR = Path("skills")


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

    # 1. YAML frontmatter
    fm_match = re.match(r'^---\s*\n(.*?)\n---', content, re.DOTALL)
    if not fm_match:
        report.findings.append(LintFinding("ERROR", "MISSING_FRONTMATTER",
                                           "YAML frontmatter (--- block) is missing"))
    else:
        fm_text = fm_match.group(1)
        for field_name in REQUIRED_YAML_FIELDS:
            if field_name not in fm_text:
                report.findings.append(LintFinding("ERROR", "MISSING_FIELD",
                                                   f"Required YAML field missing: {field_name}"))
        for meta_field in REQUIRED_METADATA_FIELDS:
            if meta_field not in fm_text:
                report.findings.append(LintFinding("WARN", "MISSING_METADATA",
                                                   f"metadata.{meta_field} not found"))

    # 2. Version baseline
    v_match = re.search(r'^version:\s*"([^"]+)"', content, re.M)
    if v_match:
        version = v_match.group(1)
        if version != EXPECTED_VERSION:
            report.findings.append(LintFinding("WARN", "VERSION_MISMATCH",
                                               f"Version is {version}, expected {EXPECTED_VERSION}",
                                               skill_name))
    else:
        report.findings.append(LintFinding("ERROR", "VERSION_MISSING",
                                           "No version field found"))

    # 3. Required sections
    for section in REQUIRED_SECTIONS:
        if not re.search(rf'^{re.escape(section)}', content, re.M):
            report.findings.append(LintFinding("WARN", "MISSING_SECTION",
                                               f"Section not found: {section}"))

    # 4. Defense Triple
    for name, pattern in DEFENSE_TRIPLE_SECTIONS.items():
        if not re.search(pattern, content, re.M):
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

    if args.json:
        output = {
            "total_skills": len(reports),
            "passed": sum(1 for r in reports if r.passed),
            "failed": sum(1 for r in reports if not r.passed),
            "total_errors": sum(r.error_count for r in reports),
            "total_warnings": sum(r.warn_count for r in reports),
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
        total_errors = sum(r.error_count for r in reports)
        total_warnings = sum(r.warn_count for r in reports)

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
