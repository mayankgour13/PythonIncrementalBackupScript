#!/usr/bin/env python3

import os
import tarfile
import csv
import hashlib
import time
from datetime import datetime
import argparse

CSV_LOG_FILE = "backup_log.csv"
DIRS_LOG_FILE = "backup_dirs.txt"

def get_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        # while chunk := f.read(8192):
        #     h.update(chunk)
        chunk = f.read(8192)
        while chunk:
            h.update(chunk)
            chunk = f.read(8192)
    return h.hexdigest()

def load_previous_log(log_path):
    prev_data = {}
    if os.path.exists(log_path):
        with open(log_path, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                prev_data[row['file_path']] = row
    return prev_data

def get_all_files(base_dir):
    file_infos = []
    for root, _, files in os.walk(base_dir):
        for name in sorted(files):
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, base_dir)
            if os.path.isfile(full_path):
                stat = os.stat(full_path)
                file_infos.append({
                    'file_path': rel_path,
                    'full_path': full_path,
                    'size': stat.st_size,
                    'mtime': stat.st_mtime
                })
    return file_infos

def get_all_dirs(base_dir):
    dirs = set()
    for root, dirnames, _ in os.walk(base_dir):
        rel_root = os.path.relpath(root, base_dir)
        if rel_root == ".":
            rel_root = ""  # Use "" for root directory
        dirs.add(rel_root)
    return dirs


def group_files(files, size_limit):
    groups = []
    current_group = []
    current_size = 0

    for f in files:
        if f['size'] >= size_limit:
            # Large file forms its own group
            groups.append([f])
            continue  # Skip rest and start next iteration

        # Accumulate small files
        current_group.append(f)
        current_size += f['size']

        # Flush current group when size limit reached or exceeded
        if current_size >= size_limit:
            groups.append(current_group)
            current_group = []
            current_size = 0

    # Append any leftover files as the last group (may be smaller than size_limit)
    if current_group:
        groups.append(current_group)

    return groups


def perform_backup(source_dir, dest_dir, archive_size_bytes=(500 * 1024 * 1024), loops=0):
    print("[*] Starting backup...")
    os.makedirs(dest_dir, exist_ok=True)
    log_path = os.path.join(dest_dir, CSV_LOG_FILE)
    dirs_path = os.path.join(dest_dir, DIRS_LOG_FILE)

    prev_log = load_previous_log(log_path)
    current_files = get_all_files(source_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    new_log_rows = []

    # Detect new or modified files compared to previous log
    print("[*] Scanning for changes...")
    new_or_changed_files = []
    for info in current_files:
        rel_path = info['file_path']
        mtime_str = str(info['mtime'])
        size = info['size']
        prev = prev_log.get(rel_path)
        if (not prev) or (prev['mtime'] != mtime_str) or (int(prev.get('size', 0)) != size):
            if prev and (prev['mtime'] != mtime_str) and (int(prev.get('size', 0)) == size):
                sha = get_sha256(info['full_path'])
                if sha == prev['sha256']:
                    prev['mtime'] = mtime_str
            new_or_changed_files.append(info)


    current_file_set = {f['file_path'] for f in current_files}
    deleted_files = [fp for fp in prev_log if fp not in current_file_set and prev_log[fp].get('deleted') != 'yes']

    # CASE 1: No new/changed files and no deletions: nothing to do
    if not new_or_changed_files and not deleted_files:
        print("[*] No changes or deletions detected. Backup not needed.")
        return

    archive_name = ''
    # CASE 2: No new/changed files but deletions exist → create empty tar archive + mark deletions
    if not new_or_changed_files and deleted_files:
        processed_groups = 1
        archive_name = f"backup_{timestamp}_001.tar.gz"
        archive_path = os.path.join(dest_dir, archive_name)

        print("[*] No new/changed files, but detected deletions.")
        print(f"[*] Creating empty archive to mark this backup at {archive_path}")
        with tarfile.open(archive_path, "w:gz"):
            pass  # create empty tar archive

        # Mark deleted files with this archive info
        all_records = prev_log.copy()
        for rel_path in deleted_files:
            rec = all_records.get(rel_path, {})
            rec['deleted'] = 'yes'
            rec['backup_archive'] = archive_name
            rec['backup_timestamp'] = datetime.now().isoformat()
            all_records[rel_path] = rec

        # Save updated CSV log
        with open(log_path, 'w', newline='') as csvfile:
            fieldnames = ['file_path', 'mtime', 'sha256', 'size', 'backup_archive', 'backup_timestamp', 'deleted']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for record in all_records.values():
                writer.writerow(record)

        # Save current dirs snapshot
        dirs = get_all_dirs(source_dir)
        with open(dirs_path, "w") as f:
            for d in sorted(dirs):
                f.write(d + "\n")

        print(f"[✓] Backup complete (empty archive for deletion). Archives saved to: {dest_dir}")
        return

    # CASE 3: New or changed files exist → normal backup flow

    # Group changed/new files into size-limited batches
    full_groups = group_files(new_or_changed_files, archive_size_bytes)
    processed_groups = len(full_groups)
    if loops > 0:
        processed_groups = min(loops, len(full_groups))

    print(f"[*] Creating {processed_groups} archive(s) of up to {archive_size_bytes} Bytes each...")

    for i in range(processed_groups):
        group = full_groups[i]
        archive_name = f"backup_{timestamp}_{i+1:03d}.tar.gz"
        archive_path = os.path.join(dest_dir, archive_name)
        with tarfile.open(archive_path, "w:gz") as tar:
            for f in group:
                tar.add(f['full_path'], arcname=f['file_path'])
                sha = get_sha256(f['full_path'])
                new_log_rows.append({
                    'file_path': f['file_path'],
                    'mtime': str(f['mtime']),
                    'sha256': sha,
                    'size': f['size'],
                    'backup_archive': archive_name,
                    'backup_timestamp': datetime.now().isoformat(),
                    'deleted': ''
                })

    # Merge previous log with new records and mark deleted files
    all_records = prev_log.copy()
    for rec in new_log_rows:
        all_records[rec['file_path']] = rec

    # Mark deleted files only if not already marked deleted
    for rel_path in prev_log:
        if rel_path not in current_file_set:
            rec = all_records.get(rel_path, {})
            if rec.get('deleted') != 'yes':
                rec['deleted'] = 'yes'
                rec['backup_timestamp'] = datetime.now().isoformat()
                # Set backup archive to last created archive (for consistent reference)
                rec['backup_archive'] = archive_name if processed_groups > 0 else ""
                all_records[rel_path] = rec

    # Write merged log back to CSV
    with open(log_path, 'w', newline='') as csvfile:
        fieldnames = ['file_path', 'mtime', 'sha256', 'size', 'backup_archive', 'backup_timestamp', 'deleted']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for record in all_records.values():
            writer.writerow(record)

    # Save current dirs snapshot as backup_dirs.txt
    dirs = get_all_dirs(source_dir)
    with open(dirs_path, "w") as f:
        for d in sorted(dirs):
            f.write(d + "\n")

    print(f"[✓] Backup complete. Archives saved to: {dest_dir}")


def load_backup_dirs(backup_dir):
    dirs_file = os.path.join(backup_dir, DIRS_LOG_FILE)
    if not os.path.exists(dirs_file):
        return set()
    with open(dirs_file, "r") as f:
        return set(line.strip() for line in f if line.strip())


def remove_deleted_dirs(restore_root, source_dirs):
    """
    Recursively remove directories from restore_root which do NOT exist in source_dirs
    but only if they are empty.
    """
    for dirpath, dirnames, filenames in os.walk(restore_root, topdown=False):
        rel_dir = os.path.relpath(dirpath, restore_root)
        if rel_dir == ".":
            rel_dir = ""  # root directory relative path
        if rel_dir not in source_dirs:
            # Only remove empty directories
            if not dirnames and not filenames:
                try:
                    os.rmdir(dirpath)
                    print(f"[-] Removed deleted directory: {rel_dir or '/'}")
                except Exception as e:
                    print(f"[!] Failed to remove directory {rel_dir}: {e}")


def restore_backup(backup_dir, restore_target, count: int):
    print("[*] Starting restore...")
    log_path = os.path.join(backup_dir, CSV_LOG_FILE)
    if not os.path.exists(log_path):
        print("[X] No backup log found!")
        return
    if not os.path.exists(restore_target):
        os.makedirs(restore_target, exist_ok=True)

    with open(log_path, 'r', newline='') as csvfile:
        reader = list(csv.DictReader(csvfile))

    active_files = {r['file_path']: r for r in reader if r.get('deleted') != 'yes'}
    deleted_files = {r['file_path'] for r in reader if r.get('deleted') == 'yes'}

    # Map archives → files to extract
    archives = {}
    for record in active_files.values():
        archives.setdefault(record['backup_archive'], []).append(record['file_path'])

    # Extract files from archives
    processed_archives: int = 0
    for archive, paths in archives.items():
        archive_path = os.path.join(backup_dir, archive)
        if not os.path.exists(archive_path):
            print(f"[!] Archive missing: {archive_path}")
            continue
        with tarfile.open(archive_path, 'r:gz') as tar:
            for path in paths:
                try:
                    member = tar.getmember(path)
                except KeyError:
                    print(f"[!] File {path} not found in archive {archive}")
                    continue
                target_path = os.path.join(restore_target, path)
                record = active_files[path]  # from CSV log
                backup_size = int(record['size'])
                backup_mtime = float(record['mtime'])
                backup_sha = record['sha256']

                if os.path.exists(target_path):
                    stat = os.stat(target_path)
                    if backup_size == stat.st_size:
                        if backup_mtime == stat.st_mtime:
                            # print(f"[=] Skipped: {path} (already up-to-date with size and mtime)")
                            continue
                        else:
                            local_sha = get_sha256(target_path)
                            if local_sha == backup_sha:
                                print(f"[=] Skipped: {path} (already up-to-date with sha)")
                                # Optionally: update target's mtime to match backup
                                os.utime(target_path, (stat.st_atime, backup_mtime))
                                continue
                    else:
                        print(f"[!] File size mismatch: {path}; {backup_size} != {stat.st_size}")
                        pass
                else:
                    # print(f"[!] File not found: {path}")
                    pass

                # Extract if not up-to-date or missing
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                tar.extract(member, path=restore_target)
                # print(f"[+] Restored: {path}")
        print(f"[+] Processed Archive: {archive_path}")
        processed_archives += 1
        if count > 0 and processed_archives >= count:
            break

    # Delete files flagged as deleted
    for file_path in deleted_files:
        target_path = os.path.join(restore_target, file_path)
        if os.path.exists(target_path):
            try:
                os.remove(target_path)
                print(f"[-] Deleted: {file_path}")
            except Exception as e:
                print(f"[!] Failed to delete {file_path}: {e}")

    # Remove directories deleted in source (only if empty)
    source_dirs = load_backup_dirs(backup_dir)
    remove_deleted_dirs(restore_target, source_dirs)

    print(f"[✓] Restore complete. Restored files to: {restore_target}")


def parse_size(size_str) -> int:
    """
    Parse a human-friendly size string like '500M', '2G', '100K', '1024'
    and return size in bytes as int.
    Supports: K/k (kilobytes), M/m (megabytes), G/g (gigabytes), no suffix = bytes.
    """
    if not size_str:
        return 500 * 1024 * 1024  # default 500MB
    size_str = size_str.strip().upper()
    if size_str.endswith('K'):
        return int(float(size_str[:-1]) * 1024)
    elif size_str.endswith('M'):
        return int(float(size_str[:-1]) * 1024 ** 2)
    elif size_str.endswith('G'):
        return int(float(size_str[:-1]) * 1024 ** 3)
    else:
        return int(size_str)


def main():
    parser = argparse.ArgumentParser(description="Incremental file-level tar backup utility")
    subparsers = parser.add_subparsers(dest="command")

    backup_parser = subparsers.add_parser("backup", help="Run backup")
    backup_parser.add_argument("--source", required=True, help="Directory to backup")
    backup_parser.add_argument("--dest", required=True, help="Backup folder (archives + log)")
    backup_parser.add_argument("--loops", type=int, default=1, help="Number of archive groups to create this run")
    backup_parser.add_argument("--max-size", required=True, help="Archive size limit per group, e.g., 500M or 1G or 1024000")

    restore_parser = subparsers.add_parser("restore", help="Run restore")
    restore_parser.add_argument("--backup", required=True, help="Backup folder (archives + log)")
    restore_parser.add_argument("--target", required=True, help="Directory to restore to")
    restore_parser.add_argument("--count", type=int, default=0, required=False, help="Number of archives to restore")

    args = parser.parse_args()

    if args.command == "backup":
        size_limit_bytes = parse_size(args.max_size)
        perform_backup(args.source, args.dest, archive_size_bytes=size_limit_bytes, loops=args.loops)
    elif args.command == "restore":
        restore_backup(args.backup, args.target, args.count)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()


# python3 backup_tool.py backup --source /your/folder/to/backup --dest /your/backup_dir/
# python3 backup_tool.py backup --source /your/folder/to/backup --dest /your/backup_dir/ --loops 2 --max-size 50
# python3 backup_tool.py restore --backup /your/backup_dir/ --target /destination/restore_path/
# python3 backup_tool.py restore --backup /your/backup_dir/ --target /destination/restore_path/ --count 1

