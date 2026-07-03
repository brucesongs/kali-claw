#!/usr/bin/env python3
"""cybergym-download-tasks.py — Selective HuggingFace downloader for CyberGym arvo tasks.

Downloads only the specified arvo task directories from
https://huggingface.co/datasets/sunblaze-ucb/cybergym instead of the full 240GB dataset.

Each arvo task contains:
  - description.txt   (the vuln description)
  - error.txt         (compiler/sanitizer error output, level1+)
  - patch.diff        (the security fix, level2+)
  - repo-vul.tar.gz   (vulnerable source, ~10-200MB each)
  - repo-fix.tar.gz   (patched source)

Usage:
    python3 validation/cybergym-download-tasks.py \\
        --cybergym-root ~/code/cybergym \\
        --task-ids 509,759,781,919 \\
        --workers 4

Or read IDs from the v0.1.45 sampling JSON:
    python3 validation/cybergym-download-tasks.py \\
        --cybergym-root ~/code/cybergym \\
        --from-sampling docs/cybergym-sampling-v0.1.45.json \\
        --workers 4
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    from huggingface_hub import hf_hub_download
except ImportError:
    print("ERROR: huggingface_hub not installed. Install with `pip install huggingface_hub`", file=sys.stderr)
    sys.exit(2)


REPO_ID = "sunblaze-ucb/cybergym"
REPO_TYPE = "dataset"
TASK_FILES = ["description.txt", "error.txt", "patch.diff", "repo-vul.tar.gz", "repo-fix.tar.gz"]


def list_local_tasks(cybergym_root: Path) -> set[str]:
    """Return set of arvo IDs already downloaded locally."""
    arvo_dir = cybergym_root / "cybergym_data" / "data" / "arvo"
    if not arvo_dir.is_dir():
        return set()
    return {d.name for d in arvo_dir.iterdir() if d.is_dir() and d.name.isdigit()}


def download_one_task(task_id: str, cybergym_root: Path) -> tuple[str, str | None]:
    """Download a single arvo task. Returns (task_id, error_or_none)."""
    arvo_id = task_id.split(":", 1)[1] if ":" in task_id else task_id
    target_dir = cybergym_root / "cybergym_data" / "data" / "arvo" / arvo_id
    target_dir.mkdir(parents=True, exist_ok=True)
    for filename in TASK_FILES:
        remote_path = f"data/arvo/{arvo_id}/{filename}"
        local_path = target_dir / filename
        if local_path.exists() and local_path.stat().st_size > 0:
            continue
        try:
            downloaded = hf_hub_download(
                repo_id=REPO_ID,
                repo_type=REPO_TYPE,
                filename=remote_path,
                local_dir=str(cybergym_root),
            )
            # hf_hub_download with local_dir preserves the relative path; verify.
            actual = Path(downloaded)
            if actual != local_path and not local_path.exists():
                # In newer huggingface_hub versions, the file lands at the relative path.
                # Fall back: copy if mismatched.
                local_path.write_bytes(actual.read_bytes())
        except Exception as e:
            return task_id, f"failed on {filename}: {e}"
    return task_id, None


def parse_task_ids(args: argparse.Namespace) -> list[str]:
    if args.task_ids:
        ids = [t.strip() for t in args.task_ids.split(",") if t.strip()]
        return [t if ":" in t else f"arvo:{t}" for t in ids]
    if args.from_sampling:
        sampling = json.loads(Path(args.from_sampling).read_text())
        # Filter to instances whose cybergym_instance_id is set; otherwise pick from mask_map
        ids = []
        for inst in sampling.get("instances", []):
            cybergym_id = inst.get("cybergym_instance_id")
            if cybergym_id and cybergym_id.startswith("arvo:"):
                ids.append(cybergym_id)
        if not ids:
            # Fall back: pick the smallest 23 arvo IDs not yet local
            mask_map_path = Path(args.cybergym_root) / "mask_map.json"
            if mask_map_path.exists():
                mask = json.loads(mask_map_path.read_text())
                all_ids = list(mask.keys()) if isinstance(mask, dict) else mask
                arvo_ids = [i for i in all_ids if i.startswith("arvo:")]
                local = list_local_tasks(Path(args.cybergym_root))
                arvo_ids = [i for i in arvo_ids if i.split(":")[1] not in local]
                arvo_ids.sort(key=lambda x: int(x.split(":")[1]))
                ids = arvo_ids[:23]
        return ids
    return []


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cybergym-root", required=True, type=Path, help="Path to CyberGym repo root")
    p.add_argument("--task-ids", help="Comma-separated arvo IDs (e.g. 509,759,781 or arvo:509,arvo:759)")
    p.add_argument("--from-sampling", help="Sampling JSON file to read IDs from")
    p.add_argument("--workers", type=int, default=4, help="Parallel download workers (default: 4)")
    p.add_argument("--dry-run", action="store_true", help="Show what would be downloaded, no actual download")
    args = p.parse_args()

    if not args.cybergym_root.is_dir():
        print(f"ERROR: cybergym_root not found: {args.cybergym_root}", file=sys.stderr)
        return 2

    task_ids = parse_task_ids(args)
    if not task_ids:
        print("ERROR: no task IDs to download (provide --task-ids or valid --from-sampling)", file=sys.stderr)
        return 2

    local = list_local_tasks(args.cybergym_root)
    already = [t for t in task_ids if t.split(":")[1] in local]
    todo = [t for t in task_ids if t.split(":")[1] not in local]

    print(f"CyberGym root      : {args.cybergym_root}")
    print(f"Requested tasks    : {len(task_ids)}")
    print(f"Already local      : {len(already)} (skipped)")
    print(f"To download        : {len(todo)}")
    print(f"Workers            : {args.workers}")
    print(f"Per-task file count: {len(TASK_FILES)} (desc + error + patch + repo-vul + repo-fix)")
    print()

    if args.dry_run:
        print("[dry-run] Task IDs to download:")
        for tid in todo:
            print(f"  - {tid}")
        return 0

    if not todo:
        print("Nothing to download.")
        return 0

    succeeded: list[str] = []
    failed: list[tuple[str, str]] = []

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(download_one_task, tid, args.cybergym_root): tid for tid in todo}
        for i, future in enumerate(as_completed(futures), 1):
            tid = futures[future]
            try:
                returned_tid, err = future.result()
            except Exception as e:
                failed.append((tid, f"exception: {e}"))
                print(f"  [{i}/{len(todo)}] {tid}  FAIL  exception: {e}")
                continue
            if err is None:
                succeeded.append(returned_tid)
                print(f"  [{i}/{len(todo)}] {tid}  OK")
            else:
                failed.append((returned_tid, err))
                print(f"  [{i}/{len(todo)}] {tid}  FAIL  {err}")

    print()
    print(f"Summary: {len(succeeded)} succeeded, {len(failed)} failed")
    if failed:
        print("Failed tasks:")
        for tid, err in failed:
            print(f"  - {tid}: {err}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
