#!/bin/bash
# auto-backup.sh — Automated backup rotation for kali-claw workspace
# Creates timestamped tar.gz backups of skills, memory, and chronicle.
# Usage: bash validation/auto-backup.sh [--restore <file>] [--keep N]
#   --restore <file>  Restore from a specific backup file
#   --keep N          Keep last N backups (default: 10)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BAK_DIR="$ROOT_DIR/bak"

KEEP_COUNT=10
RESTORE_FILE=""
ACTION="backup"

for arg in "$@"; do
    case "$arg" in
        --restore) ACTION="restore" ;;
        --keep) shift; KEEP_COUNT="${1:-10}" ;;
        --help) echo "Usage: bash validation/auto-backup.sh [--restore <file>] [--keep N]"; exit 0 ;;
        *.tar.gz) [ "$ACTION" = "restore" ] && RESTORE_FILE="$arg" ;;
    esac
done

mkdir -p "$BAK_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")

# ── Restore mode ────────────────────────────────────────────────────────

if [ "$ACTION" = "restore" ]; then
    if [ -z "$RESTORE_FILE" ]; then
        echo "Error: --restore requires a backup file path"
        echo "Available backups:"
        ls -lt "$BAK_DIR"/*.tar.gz 2>/dev/null | head -10 || echo "  No backups found"
        exit 1
    fi

    if [ ! -f "$RESTORE_FILE" ]; then
        # Try relative to bak/
        RESTORE_FILE="$BAK_DIR/$(basename "$RESTORE_FILE")"
    fi

    if [ ! -f "$RESTORE_FILE" ]; then
        echo "Error: Backup file not found: $RESTORE_FILE"
        exit 1
    fi

    echo "Restoring from: $RESTORE_FILE"
    echo ""

    # Verify integrity
    if ! tar -tzf "$RESTORE_FILE" > /dev/null 2>&1; then
        echo "Error: Backup file is corrupted"
        exit 1
    fi
    echo "Integrity check: PASSED"

    # List contents
    FILE_COUNT=$(tar -tzf "$RESTORE_FILE" | wc -l | tr -d ' ')
    echo "Files in backup: $FILE_COUNT"
    echo ""

    read -p "Restore to $ROOT_DIR? This will overwrite existing files. [y/N] " -r confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        tar -xzf "$RESTORE_FILE" -C "$ROOT_DIR"
        echo "Restore complete."
    else
        echo "Restore cancelled."
    fi
    exit 0
fi

# ── Backup mode ─────────────────────────────────────────────────────────

echo "Creating backup..."

BACKUP_NAME="kali-claw-${TIMESTAMP}.tar.gz"
BACKUP_PATH="$BAK_DIR/$BACKUP_NAME"

# Create backup
tar -czf "$BACKUP_PATH" \
    -C "$ROOT_DIR" \
    skills/ \
    memory/ \
    chronicle/ \
    MEMORY.md \
    SOUL.md \
    AGENTS.md \
    IDENTITY.md \
    TOOLS.md \
    VERSION \
    2>/dev/null || {
    # Fallback: backup what exists
    EXISTING=()
    for d in skills memory chronicle; do
        [ -d "$ROOT_DIR/$d" ] && EXISTING+=("$d/")
    done
    for f in MEMORY.md SOUL.md AGENTS.md IDENTITY.md TOOLS.md VERSION; do
        [ -f "$ROOT_DIR/$f" ] && EXISTING+=("$f")
    done
    tar -czf "$BACKUP_PATH" -C "$ROOT_DIR" "${EXISTING[@]}" 2>/dev/null
}

BACKUP_SIZE=$(du -h "$BACKUP_PATH" | cut -f1)

# Verify integrity
if tar -tzf "$BACKUP_PATH" > /dev/null 2>&1; then
    INTEGRITY="PASSED"
else
    INTEGRITY="FAILED"
    echo "Warning: Integrity check failed for $BACKUP_PATH"
fi

FILE_COUNT=$(tar -tzf "$BACKUP_PATH" | wc -l | tr -d ' ')

echo "  Backup: $BACKUP_NAME"
echo "  Size:   $BACKUP_SIZE"
echo "  Files:  $FILE_COUNT"
echo "  Verify: $INTEGRITY"
echo ""

# ── Rotation: remove old backups ────────────────────────────────────────

EXISTING_BACKUPS=$(ls -1t "$BAK_DIR"/kali-claw-*.tar.gz 2>/dev/null || true)
BACKUP_COUNT=$(echo "$EXISTING_BACKUPS" | grep -c . || true)

if [ "$BACKUP_COUNT" -gt "$KEEP_COUNT" ]; then
    REMOVE_COUNT=$((BACKUP_COUNT - KEEP_COUNT))
    echo "Rotating: removing $REMOVE_COUNT old backup(s) (keeping $KEEP_COUNT)"
    echo "$EXISTING_BACKUPS" | tail -n "$REMOVE_COUNT" | while read -r old_backup; do
        echo "  Removing: $(basename "$old_backup")"
        rm -f "$old_backup"
    done
else
    echo "Rotation: $BACKUP_COUNT backup(s) on disk (limit: $KEEP_COUNT)"
fi

echo ""
echo "Backup complete: $BACKUP_PATH"
