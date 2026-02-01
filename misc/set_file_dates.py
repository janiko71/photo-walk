import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from dateutil import parser

try:
    import piexif
except Exception:  # Optional dependency
    piexif = None


IMAGE_EXIF_EXTS = {".jpg", ".jpeg", ".tif", ".tiff"}
RAW_EXTS = {
    ".arw", ".cr2", ".cr3", ".crw", ".dcr", ".dcs", ".dng", ".drf", ".gpr",
    ".k25", ".kdc", ".mrw", ".nef", ".nrw", ".orf", ".pef", ".ptx", ".raf",
    ".raw", ".rw2", ".sr2", ".srf", ".srw", ".x3f"
}
VIDEO_EXTS = {
    ".mpg", ".mp2", ".mpeg", ".mpe", ".mpv", ".mov", ".ogv", ".mp4", ".m4p",
    ".m4v", ".avi", ".ts", ".webm", ".wm", ".wmv", ".avchd"
}


def parse_target_date(date_text):
    dt = parser.parse(date_text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return dt


def iter_files(root, recursive, extensions):
    if recursive:
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                if not extensions or os.path.splitext(name)[1].lower() in extensions:
                    yield path
    else:
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                if not extensions or os.path.splitext(name)[1].lower() in extensions:
                    yield path


def _dt_to_filetime(dt):
    dt_utc = dt.astimezone(timezone.utc)
    unix_seconds = dt_utc.timestamp()
    return int((unix_seconds + 11644473600) * 10_000_000)


def set_windows_file_times(path, dt):
    import ctypes
    from ctypes import wintypes

    FILE_WRITE_ATTRIBUTES = 0x0100
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

    handle = ctypes.windll.kernel32.CreateFileW(
        path,
        FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise OSError("CreateFileW failed")

    try:
        ft = _dt_to_filetime(dt)
        filetime = wintypes.FILETIME(ft & 0xFFFFFFFF, ft >> 32)
        res = ctypes.windll.kernel32.SetFileTime(
            handle,
            ctypes.byref(filetime),
            ctypes.byref(filetime),
            ctypes.byref(filetime),
        )
        if res == 0:
            raise OSError("SetFileTime failed")
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def set_fs_times(path, dt):
    if os.name == "nt":
        try:
            set_windows_file_times(path, dt)
            return
        except Exception:
            pass
    ts = dt.timestamp()
    os.utime(path, (ts, ts))


def set_exif_dates(path, dt):
    if piexif is None:
        raise RuntimeError("piexif is not installed")
    ext = os.path.splitext(path)[1].lower()
    if ext not in IMAGE_EXIF_EXTS:
        raise ValueError("EXIF write not supported for this file type")

    exif_dict = piexif.load(path)
    date_text = dt.strftime("%Y:%m:%d %H:%M:%S")
    exif_dict.setdefault("0th", {})
    exif_dict.setdefault("Exif", {})
    exif_dict["0th"][piexif.ImageIFD.DateTime] = date_text
    exif_dict["Exif"][piexif.ExifIFD.DateTimeOriginal] = date_text
    exif_dict["Exif"][piexif.ExifIFD.DateTimeDigitized] = date_text

    exif_bytes = piexif.dump(exif_dict)
    piexif.insert(exif_bytes, path)


def set_video_metadata(path, dt, keep_backup):
    iso = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    base_dir = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(prefix="ffmeta_", suffix=os.path.splitext(path)[1], dir=base_dir)
    os.close(fd)
    try:
        cmd = [
            "ffmpeg",
            "-y",
            "-i",
            path,
            "-map",
            "0",
            "-c",
            "copy",
            "-metadata",
            f"creation_time={iso}",
            "-metadata:s:v:0",
            f"creation_time={iso}",
            "-metadata:s:a:0",
            f"creation_time={iso}",
            tmp_path,
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            raise RuntimeError(res.stderr.strip() or "ffmpeg failed")

        if keep_backup:
            backup_path = path + ".bak"
            if not os.path.exists(backup_path):
                shutil.copy2(path, backup_path)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def main():
    parser_arg = argparse.ArgumentParser(
        description="Set file system dates and EXIF metadata for images/videos in a directory."
    )
    parser_arg.add_argument("directory", help="Target directory")
    parser_arg.add_argument("date", help="Target date (e.g. 2020-01-02 12:34:56)")
    parser_arg.add_argument("--no-recursive", action="store_true", help="Do not traverse subfolders")
    parser_arg.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    parser_arg.add_argument("--set-fs", action="store_true", help="Set filesystem times")
    parser_arg.add_argument("--set-exif", action="store_true", help="Set EXIF dates for JPEG/TIFF")
    parser_arg.add_argument("--set-video-metadata", action="store_true", help="Set creation_time for videos (ffmpeg)")
    parser_arg.add_argument("--keep-backup", action="store_true", help="Keep .bak backup when rewriting videos")
    parser_arg.add_argument("--extensions", nargs="*", help="Limit to extensions (e.g. .jpg .mp4)")

    args = parser_arg.parse_args()

    if not (args.set_fs or args.set_exif or args.set_video_metadata):
        print("Nothing to do: choose at least one of --set-fs, --set-exif, --set-video-metadata")
        return 2

    target_dir = args.directory
    if not os.path.isdir(target_dir):
        print(f"Directory not found: {target_dir}")
        return 2

    target_dt = parse_target_date(args.date)
    extensions = None
    if args.extensions:
        extensions = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in args.extensions}

    total = 0
    updated = 0
    skipped = 0
    errors = 0

    for path in iter_files(target_dir, not args.no_recursive, extensions):
        total += 1
        ext = os.path.splitext(path)[1].lower()
        try:
            if args.dry_run:
                print(f"[DRY] {path}")
                updated += 1
                continue

            if args.set_exif and ext in IMAGE_EXIF_EXTS:
                set_exif_dates(path, target_dt)

            if args.set_video_metadata and ext in VIDEO_EXTS:
                set_video_metadata(path, target_dt, args.keep_backup)

            if args.set_fs:
                set_fs_times(path, target_dt)

            updated += 1
        except ValueError as ve:
            print(f"Skip: {path} ({ve})")
            skipped += 1
        except Exception as e:
            print(f"Error: {path} ({e})")
            errors += 1

    print("")
    print(f"Files scanned: {total}")
    print(f"Updated: {updated}")
    print(f"Skipped: {skipped}")
    print(f"Errors: {errors}")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
