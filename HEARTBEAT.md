# HEARTBEAT.md - Heartbeat Tasks

> Execute the following tasks during each heartbeat poll. Don't just reply HEARTBEAT_OK every time — use heartbeats efficiently.

---

## Health Check

- [ ] Check system resource usage (CPU, memory, disk)
- [ ] Verify core configuration file integrity (SOUL.md, AGENTS.md, IDENTITY.md)
- [ ] Confirm bak/ directory backup is up to date (no older than 3 hours)

---

## Skill Domain Completeness

- [ ] Verify all 49 skill domains have FULL enrichment (SKILL.md + payloads.md + test-cases.md + guides/)
- [ ] Check for newly added skills that need supplementary files
- [ ] Spot-check 2-3 random skill directories for file consistency

---

## Learning Progress

- [ ] Check today's learning progress (against the learning strategy in TOOLS.md)
- [ ] Advance to the next tool to learn
- [ ] If there's new learning content, update the corresponding skills/ files

---

## Security Check

- [ ] Check memory/alerts.txt for new security alerts
- [ ] Verify core files haven't been tampered with (compare with last backup)
- [ ] Check if sensitive information has been accidentally leaked to non-main sessions

---

## Knowledge Maintenance

- [ ] Clean up memory log files older than 30 days (extract summaries to chronicle/ then archive)
- [ ] If there are important lessons learned, distill them into MEMORY.md
- [ ] Check if MEMORY.md is stale (should be updated within 14 days)
- [ ] Verify skill files in skills/ are up to date with latest tool versions

---

## Execution Rules

1. **Priority Order**: Security Check > Health Check > Skill Domain Completeness > Learning Progress > Knowledge Maintenance
2. **Lightweight Execution**: Only do 1-2 items per heartbeat, rotate tasks to avoid overloading
3. **Record Results**: Briefly log to memory/heartbeat-check-YYYYMMDDHHMM.md
4. **Alert on Anomalies**: When anomalies are detected, immediately log to memory/alerts.txt and notify the captain

---

_Last updated: 2026-05-22_
