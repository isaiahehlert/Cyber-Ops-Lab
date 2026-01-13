#!/usr/bin/env python3
"""
sentinel.log_cleaner
Deletes any file inside LOG_DIRS older than LOG_RETENTION_DAYS.
Run manually or via cron/systemd timer.  Safe ✂️ only—no directories removed.
"""
import os, time, pathlib, shutil, sys, datetime

LOG_DIRS = ["logs", "sentinel_logs"]
RETENTION_DAYS = int(os.getenv("LOG_RETENTION_DAYS", 30))
CUTOFF = time.time() - RETENTION_DAYS * 86400

def purge(dir_path: pathlib.Path):
    for entry in dir_path.rglob("*"):
        if entry.is_file() and entry.stat().st_mtime < CUTOFF:
            try:
                entry.unlink()
                print(f"🗑️  Deleted {entry} "
                      f"({datetime.datetime.fromtimestamp(entry.stat().st_mtime)})")
            except Exception as e:
                print(f"⚠️  Could not delete {entry}: {e}", file=sys.stderr)

def main():
    for d in LOG_DIRS:
        path = pathlib.Path(d)
        if path.exists():
            purge(path)

if __name__ == "__main__":
    main()
