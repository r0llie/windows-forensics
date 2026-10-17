#!/usr/bin/env python3
"""Collect registry hives and registry-derived live state into a directory.

Saves hives with `reg save` (transaction logs applied -> clean offline copies)
and copies the Amcache.hve file. Writes a manifest with sizes and SHA-256.

Usage:
  python collect_reg.py --out DIR [--hives system,ntuser,...] [--no-manifest]
Exit codes: 0 = all requested artifacts collected, 1 = some failed, 2 = usage error.
"""

import argparse
import ctypes
import hashlib
import json
import shutil
import subprocess
import sys
import winreg
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "0.1.1"
SCHEMA_VERSION = 1

AMCACHE_DIR = Path(r"C:\Windows\AppCompat\Programs")

HIVES = {
    "system": {
        "kind": "reg-save",
        "source": r"HKLM\SYSTEM",
        "target": "SYSTEM",
        "requires_admin": True,
    },
    "software": {
        "kind": "reg-save",
        "source": r"HKLM\SOFTWARE",
        "target": "SOFTWARE",
        "requires_admin": True,
    },
    "sam": {
        "kind": "reg-save",
        "source": r"HKLM\SAM",
        "target": "SAM",
        "requires_admin": True,
    },
    "security": {
        "kind": "reg-save",
        "source": r"HKLM\SECURITY",
        "target": "SECURITY",
        "requires_admin": True,
    },
    "ntuser": {
        "kind": "reg-save",
        "source": "HKCU",
        "target": "NTUSER.DAT",
        "requires_admin": False,
    },
    "usrclass": {
        "kind": "reg-save",
        "source": r"HKCU\Software\Classes",
        "target": "UsrClass.dat",
        "requires_admin": False,
    },
    "amcache": {
        "kind": "file-copy",
        "source": str(AMCACHE_DIR / "Amcache.hve"),
        "target": "Amcache.hve",
        "requires_admin": False,
        "companions": ["Amcache.hve.LOG1", "Amcache.hve.LOG2"],
    },
}
DEFAULT_HIVES = ["system", "software", "sam", "security", "ntuser", "usrclass", "amcache"]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def file_info(path: Path, warnings=None):
    info = {
        "file": path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }
    if warnings:
        info["warnings"] = list(warnings)
    return info


def reg_save(source: str, target: Path, timeout=300):
    cmd = ["reg", "save", source, str(target), "/y"]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"reg save {source} failed (rc={proc.returncode}): {detail}")
    if not target.exists() or target.stat().st_size == 0:
        raise RuntimeError(f"reg save {source} produced no output file")


def read_active_control_set(warnings):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Select") as key:
            value, _ = winreg.QueryValueEx(key, "Current")
        return f"ControlSet{value:03d}"
    except OSError as exc:
        warnings.append(f"could not read HKLM\\SYSTEM\\Select\\Current: {exc}")
        return None


def read_pending_renames():
    """Snapshot the live PendingFileRenameOperations value (REG_MULTI_SZ)."""
    result = {"value": "PendingFileRenameOperations", "present": False}
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
        ) as key:
            data, vtype = winreg.QueryValueEx(key, "PendingFileRenameOperations")
        if vtype == winreg.REG_MULTI_SZ:
            result["present"] = True
            result["strings"] = list(data)
        else:
            result["error"] = f"unexpected value type {vtype}"
    except FileNotFoundError:
        result["error"] = "value not present (nothing pending at collection time)"
        result["present"] = False
    except OSError as exc:
        result["error"] = f"read failed: {exc}"
    return result


def collect(out_dir: Path, wanted, warnings):
    out_dir.mkdir(parents=True, exist_ok=True)
    admin = is_admin()
    collected = {}
    failed = {}

    for name in wanted:
        spec = HIVES[name]
        target = out_dir / spec["target"]
        try:
            if target.exists():
                raise RuntimeError("refusing to overwrite existing evidence file: %s" % target)
            if spec["kind"] == "reg-save":
                if spec["requires_admin"] and not admin:
                    raise RuntimeError("requires an elevated (admin) session")
                reg_save(spec["source"], target)
                collected[name] = {"source": spec["source"], **file_info(target)}
            else:
                src = Path(spec["source"])
                if not src.exists():
                    raise RuntimeError(f"source file not found: {src}")
                note = []
                try:
                    shutil.copy2(src, target)
                except PermissionError:
                    note.append("direct copy denied (file locked); tried with admin share")
                    raise
                companions = []
                for comp_name in spec.get("companions", []):
                    comp_src = src.parent / comp_name
                    if comp_src.exists():
                        comp_dst = out_dir / comp_name
                        try:
                            if comp_dst.exists():
                                raise FileExistsError("refusing to overwrite existing evidence file: %s" % comp_dst)
                            shutil.copy2(comp_src, comp_dst)
                            companions.append(file_info(comp_dst))
                        except PermissionError:
                            note.append(f"companion not copied (locked): {comp_name}")
                entry = {"source": str(src), **file_info(target)}
                if note:
                    entry["warnings"] = note
                if companions:
                    entry["companions"] = companions
                collected[name] = entry
        except Exception as exc:  # noqa: BLE001 - report every failure honestly
            failed[name] = str(exc)

    manifest = {
        "tool": "collect_reg.py",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "elevated": admin,
        "output_dir": str(out_dir),
        "requested": list(wanted),
        "collected": collected,
        "failed": failed,
        "active_control_set": read_active_control_set(warnings),
        "pending_file_rename_operations": read_pending_renames(),
        "warnings": list(warnings),
    }
    return manifest


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="collect_reg.py",
        description="Collect registry hives (reg save) + Amcache + live registry state.",
    )
    ap.add_argument("--out", required=True, help="output directory (created if missing)")
    ap.add_argument(
        "--hives",
        default=None,
        help=f"comma-separated subset of: {','.join(HIVES)} (default: all)",
    )
    ap.add_argument("--no-manifest", action="store_true", help="do not write collect_reg.json")
    ap.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    args = ap.parse_args(argv)

    wanted = DEFAULT_HIVES if args.hives is None else [h.strip().lower() for h in args.hives.split(",") if h.strip()]
    unknown = [h for h in wanted if h not in HIVES]
    if unknown or not wanted:
        ap.error(f"unknown --hives value(s): {unknown or '(empty)'}; valid: {','.join(HIVES)}")

    out_dir = Path(args.out).expanduser().resolve()
    warnings = []
    try:
        manifest = collect(out_dir, wanted, warnings)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.no_manifest:
        manifest_path = out_dir / "collect_reg.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    ok = len(manifest["collected"])
    bad = len(manifest["failed"])
    if not args.quiet:
        print(
            f"collect_reg: collected={ok}/{len(wanted)} failed={bad} elevated={manifest['elevated']} "
            f"out={out_dir}",
            file=sys.stderr,
        )
        for name, err in manifest["failed"].items():
            print(f"  failed {name}: {err}", file=sys.stderr)
        for w in warnings:
            print(f"  warning: {w}", file=sys.stderr)
    if bad and not ok:
        return 1
    if bad:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
