# Evidence Chain Management Guide

## Introduction

Evidence chain management ensures all penetration test findings are properly documented, timestamped, and verifiable. A strong evidence chain supports accurate reporting and enables independent verification of findings. Without proper evidence management, findings cannot be reproduced, reports lose credibility, and organizations cannot prioritize remediation effectively.

Evidence chain management is not just about collecting tool output — it is about creating a structured, auditable record that connects each finding to specific actions, timestamps, and artifacts. This record must be complete enough that an independent reviewer could reproduce the finding without any additional context.

## Evidence Directory Structure

Every engagement uses a standardized directory structure that organizes evidence by kill chain phase. This structure ensures predictable file locations and enables automated evidence processing during report generation.

```
engagement/
├── evidence/
│   ├── recon/
│   │   ├── evidence.md          # Phase evidence summary
│   │   ├── commands.md          # Tool commands used with timestamps
│   │   ├── subdomains.txt       # Raw tool output
│   │   └── techstack.txt        # Raw tool output
│   ├── scan/
│   │   ├── fullscan.nmap        # Nmap output (text)
│   │   ├── fullscan.xml         # Nmap output (XML)
│   │   └── nuclei_results.txt   # Nuclei findings
│   ├── enum/
│   ├── vuln/
│   ├── exploit/
│   └── postexp/
├── logs/
│   ├── recon.log
│   ├── scan.log
│   └── activity.log
├── state/
│   ├── metadata.txt
│   ├── checkpoint.json
│   └── evidence_checksums.txt
├── reports/
│   ├── final_report.md
│   └── findings_summary.csv
└── scope/
    ├── targets.json
    └── scope-rules.json
```

## Evidence Standards

### Per-Finding Documentation

Each finding must include all of the following fields to be considered complete. Incomplete findings reduce report quality and cannot be included in the final deliverable.

1. **Unique identifier**: Sequential format F-001, F-002, etc. — never reuse IDs within an engagement
2. **Timestamp**: When the finding was discovered using ISO 8601 UTC format (YYYY-MM-DDTHH:MM:SSZ)
3. **Severity**: One of Critical, High, Medium, Low, or Informational — based on CVSS score and business impact
4. **CVSS score**: Numeric score 0.0-10.0 with full CVSS vector string for standardized severity classification
5. **Affected asset**: Hostname, IP address, or URL where the vulnerability was discovered
6. **Proof of concept**: Complete, reproducible steps or commands that demonstrate the vulnerability
7. **Impact assessment**: Both business impact (data loss, reputation, compliance) and technical impact (system compromise, privilege escalation)
8. **Remediation**: Specific, actionable steps to fix the vulnerability — not generic advice
9. **Status**: Confirmed, Suspected, or False Positive — findings should be validated before including in report

### Timestamp Format

All timestamps must use ISO 8601 UTC format: `YYYY-MM-DDTHH:MM:SSZ`. This ensures consistent, unambiguous time representation across time zones and enables chronological sorting of evidence.

### File Naming Convention

Consistent file naming enables automated evidence processing and prevents confusion:

- Evidence files: `{phase}-{tool}-{timestamp}.txt` (e.g., `scan-nmap-20260610-143000.txt`)
- Finding documents: `F-{sequence}.md` (e.g., `F-001.md`, `F-002.md`)
- Screenshots: `{phase}-{finding_id}-{description}.png` (e.g., `exploit-F-003-sql_shell.png`)
- Logs: `{phase}.log` (e.g., `recon.log`, `scan.log`)
- Checkpoints: `checkpoint.json`

## Evidence Integrity

### Integrity Rules

Evidence integrity is non-negotiable. Modified evidence undermines the entire engagement and can have legal implications:

- Never modify raw evidence files after creation — if analysis is needed, create a separate processed file
- Keep original tool output alongside processed findings so reviewers can verify transformations
- Use SHA-256 checksums for all critical evidence files, generated immediately after evidence collection
- Store screenshots in their original format with no cropping, editing, or annotation of the original file
- Use version control concepts: if evidence must be supplemented, create addendum files rather than modifying originals

### Checksum Generation and Verification

Generate checksums immediately after each phase completes to establish a baseline:

```bash
# Generate checksums after evidence collection
cd engagement/evidence
find . -type f -exec sha256sum {} \; > ../state/evidence_checksums.txt

# Verify integrity at any point
cd engagement
sha256sum -c state/evidence_checksums.txt

# Add new evidence checksums without regenerating all
echo "SHA256 NEW_FILE" >> state/evidence_checksums.txt
```

### Checkpoint System

The orchestrator uses checkpoints to track progress and enable resume functionality. The checkpoint file must be updated after each phase completes:

```json
{
    "engagement_id": "ENG-20260610",
    "completed_phases": ["recon", "scan", "enum"],
    "current_phase": "vuln",
    "next_phase": 5,
    "last_update": "2026-06-10T14:30:00Z",
    "findings_count": 3,
    "critical_findings": 1
}
```

## Data Handoff Protocol

Data handoffs between phases ensure that each phase receives properly formatted input from the previous phase. Standardized formats prevent data parsing errors and enable automated tool chain execution.

| From Phase | To Phase | Data Format | File Type |
|------------|----------|-------------|-----------|
| recon | scan | One host per line | Text (.txt) |
| scan | enum | Nmap XML + service list | XML + Text |
| enum | vuln | URL list + parameter map | JSON + Text |
| vuln | exploit | Vulnerability JSON with exploit info | JSON |
| exploit | postexp | Credential file + shell access notes | Text |
| postexp | report | Finding summary + evidence paths | Markdown |

### Handoff Validation

After each phase, verify the handoff data is valid before starting the next phase:

```bash
# Verify recon to scan handoff
test -s engagement/evidence/recon/subdomains.txt && echo "OK: subdomains" || echo "MISSING: subdomains"

# Verify scan to enum handoff
test -s engagement/evidence/scan/fullscan.xml && echo "OK: scan XML" || echo "MISSING: scan XML"

# Verify handoff file format
head -5 engagement/evidence/recon/subdomains.txt | grep -E '^([a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,})$'
```

## Critical Evidence Handling

### Critical Finding Evidence

Critical findings require additional evidence handling to support the accelerated notification protocol:

1. Immediately create a finding document with all required fields
2. Generate checksums for all evidence related to the critical finding
3. Create a notification document separate from the main report
4. Log the discovery timestamp and notification timestamp
5. Maintain a separate critical findings register in the engagement state

### Evidence Preservation for Legal Context

If findings may have legal implications (data breach evidence, compliance violations):

- Create additional backup copies of all related evidence
- Document chain of custody for each evidence file
- Use cryptographic signing in addition to checksums
- Store evidence in multiple locations to prevent loss
- Record hash values of all files at the time of collection

## Hands-on Practice

Apply evidence chain management principles in a lab environment:

1. Create the standard engagement directory structure
2. Execute a 3-phase mini-engagement (recon, scan, enum) against a lab target
3. Collect evidence at each phase following the naming convention
4. Generate checksums after each phase and verify integrity
5. Create a finding document with all required fields
6. Practice the checkpoint resume flow by interrupting and resuming
7. Generate a mini-report from the collected evidence

## References

- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
- ISO 27037: Guidelines for identification, collection, acquisition, and preservation of digital evidence
- RFC 3227: Guidelines for Evidence Collection and Archiving
- PTES Reporting Standard: http://www.pentest-standard.org/index.php/Reporting
