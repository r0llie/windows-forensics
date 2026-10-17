#!/usr/bin/env python3
"""One-command case collection for the windows-forensics skill (Phase 7).

Builds a self-contained case directory and a manifest.json that hashes and
attributes every collected file. Nothing here parses artifacts - it collects
raw evidence and delegates to the existing tools:

    <case>/
      manifest.json          every file + SHA256 + source + step + machine info
      machine_info.json      OS/build/CPU/timezone/volume facts (winreg + ctypes)
      registry/              delegated to tools/collect_reg.py (elevated only)
      prefetch/              copy of C:\\Windows\\Prefetch\\*.pf
      evtx/                  wevtutil qe XML exports (per channel; epl optional)
      mft/mft.bin            raw $MFT data stream (boot-sector -> runlist walk,
                             follows $ATTRIBUTE_LIST extension-record fragments)
      usn/usn_journal.bin    raw USN records as returned by FSCTL_READ_USN_JOURNAL

Elevation gates: $MFT, USN journal, registry `reg save` and the Security log
need an elevated prompt; without it those steps are recorded as skipped (with
the reason) and everything else still runs - the manifest never lies about
what was and was not collected.

Exit codes: 0 = tool ran (per-step errors inside the manifest), 1 = fatal
(case dir unusable / not Windows), 2 = usage error.
"""

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

import mft_parse as mft  # noqa: E402
import usn_parse as usn  # noqa: E402

TOOL_VERSION = "0.1.2"
SCHEMA_VERSION = 1

try:
    import winreg  # noqa: F401

    WINREG_OK = True
except ImportError:
    WINREG_OK = False

DEFAULT_CHANNELS = ("System", "Application", "Security")
DEFAULT_PREFETCH_DIR = r"C:\Windows\Prefetch"
READ_CHUNK = 1 << 23  # 8 MiB


class CollectError(RuntimeError):
    pass


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_elevated():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevation_gate(requested_skip, elevated):
    """Pure decision helper: (skip?, reason)."""
    if requested_skip:
        return True, "requested (--skip flag)"
    if not elevated:
        return True, "not elevated"
    return False, None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _reg_value(root, path, name):
    import winreg

    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            value, _kind = winreg.QueryValueEx(key, name)
        return value
    except OSError as exc:
        return "<error: %s>" % exc


def machine_info(volume):
    import winreg

    cv = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    info = {
        "collected_at": now_iso(),
        "computer_name": os.environ.get("COMPUTERNAME"),
        "user": os.environ.get("USERNAME"),
        "windows": {
            "product_name": _reg_value(winreg.HKEY_LOCAL_MACHINE, cv, "ProductName"),
            "display_version": _reg_value(winreg.HKEY_LOCAL_MACHINE, cv, "DisplayVersion"),
            "edition_id": _reg_value(winreg.HKEY_LOCAL_MACHINE, cv, "EditionID"),
            "build": _reg_value(winreg.HKEY_LOCAL_MACHINE, cv, "CurrentBuildNumber"),
            "ubr": _reg_value(winreg.HKEY_LOCAL_MACHINE, cv, "UBR"),
            "registered_owner": _reg_value(winreg.HKEY_LOCAL_MACHINE, cv, "RegisteredOwner"),
        },
        "cpu": {
            "processor": _reg_value(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString"
            ),
        },
        "timezone": {
            "key_name": _reg_value(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
                "TimeZoneKeyName",
            ),
        },
    }
    install_raw = _reg_value(winreg.HKEY_LOCAL_MACHINE, cv, "InstallDate")
    if isinstance(install_raw, int) and install_raw > 0:
        info["windows"]["install_date"] = datetime.fromtimestamp(install_raw, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        info["windows"]["install_date_unix"] = install_raw
    else:
        info["windows"]["install_date"] = None
        info["windows"]["install_date_unix"] = None
    info["volume"] = volume_info(volume)
    return info


def volume_info(volume):
    letter = volume.strip().rstrip(":\\")
    root = letter + ":\\"
    out = {"letter": letter + ":", "root": root}
    try:
        k32 = ctypes.windll.kernel32
        label = ctypes.create_unicode_buffer(261)
        fs_name = ctypes.create_unicode_buffer(261)
        serial = ctypes.c_uint32(0)
        max_component = ctypes.c_uint32(0)
        flags = ctypes.c_uint32(0)
        ok = k32.GetVolumeInformationW(
            root, label, 261, ctypes.byref(serial), ctypes.byref(max_component), ctypes.byref(flags), fs_name, 261
        )
        if ok:
            out["label"] = label.value
            out["file_system"] = fs_name.value
            out["serial"] = "%08X" % serial.value
        else:
            out["error"] = "GetVolumeInformationW failed"
        free = ctypes.c_ulonglong(0)
        total = ctypes.c_ulonglong(0)
        total_free = ctypes.c_ulonglong(0)
        ok2 = k32.GetDiskFreeSpaceExW(root, ctypes.byref(free), ctypes.byref(total), ctypes.byref(total_free))
        if ok2:
            out["total_bytes"] = total.value
            out["free_bytes"] = total_free.value
    except Exception as exc:  # pragma: no cover - defensive
        out["error"] = str(exc)
    return out


def read_exact(fh, offset, length, sector):
    """Read `length` bytes at sector-aligned `offset`; retries short reads."""
    if offset % sector:
        raise CollectError("unaligned read offset %d (sector %d)" % (offset, sector))
    want = ((length + sector - 1) // sector) * sector
    fh.seek(offset)
    chunks = []
    got = 0
    while got < want:
        chunk = fh.read(want - got)
        if not chunk:
            raise CollectError("short read at offset %d: got %d, wanted %d" % (offset, got, want))
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)[:length]


def parse_boot_sector(boot):
    if boot[3:11] != b"NTFS    ":
        raise CollectError("volume is not NTFS (boot sector signature missing)")
    bytes_per_sector = struct.unpack_from("<H", boot, 0x0B)[0]
    sectors_per_cluster = boot[0x0D]
    if bytes_per_sector not in (512, 1024, 2048, 4096):
        raise CollectError("implausible bytes-per-sector: %d" % bytes_per_sector)
    if sectors_per_cluster == 0 or sectors_per_cluster > 128:
        raise CollectError("implausible sectors-per-cluster: %d" % sectors_per_cluster)
    cluster_size = bytes_per_sector * sectors_per_cluster
    mft_lcn = struct.unpack_from("<Q", boot, 0x30)[0]
    rec_size_raw = struct.unpack_from("<b", boot, 0x40)[0]
    record_size = (1 << (-rec_size_raw)) if rec_size_raw < 0 else rec_size_raw * cluster_size
    if record_size not in (1024, 2048, 4096):
        raise CollectError("implausible MFT record size: %d" % record_size)
    return {
        "bytes_per_sector": bytes_per_sector,
        "sectors_per_cluster": sectors_per_cluster,
        "cluster_size": cluster_size,
        "mft_lcn": mft_lcn,
        "record_size": record_size,
    }


def _fix_record(record_bytes, record_size, warnings):
    fixed = mft.apply_fixup(record_bytes, 0, record_size, warnings)
    if fixed[:4] != b"FILE":
        raise CollectError("MFT record has no FILE magic")
    return fixed


def _walk_attributes(fixed, record_size):
    first_attr = struct.unpack_from("<H", fixed, 0x14)[0]
    used = struct.unpack_from("<I", fixed, 0x18)[0]
    found = []
    attr_off = first_attr
    attr_end = min(used, record_size)
    while attr_off + 16 <= attr_end:
        atype, alen, non_res, name_len = struct.unpack_from("<IIBB", fixed, attr_off)
        if atype == 0xFFFFFFFF:
            break
        if alen < 24 or alen % 8 or attr_off + alen > record_size:
            raise CollectError("attribute walk aborted at 0x%x" % attr_off)
        found.append((atype, attr_off, alen, bool(non_res), name_len))
        attr_off += alen
    return found


def _data_fragment(fixed, attr_off):
    """Unnamed non-resident $DATA fragment: (lowest_vcn, runs, allocated, real, warning)."""
    lowest_vcn = struct.unpack_from("<Q", fixed, attr_off + 16)[0]
    runs_offset = struct.unpack_from("<H", fixed, attr_off + 32)[0]
    allocated = struct.unpack_from("<Q", fixed, attr_off + 40)[0]
    real = struct.unpack_from("<Q", fixed, attr_off + 48)[0]
    runs, run_warning = mft.decode_runs(fixed, attr_off + runs_offset)
    if not runs:
        raise CollectError("$MFT $DATA fragment has an empty runlist")
    return lowest_vcn, runs, allocated, real, run_warning


def _read_runlist_bytes(fh, runs, cluster_size, sector, byte_count):
    out = bytearray()
    for run in runs:
        if len(out) >= byte_count:
            break
        if run["lcn"] is None:
            raise CollectError("sparse run while reading $MFT metadata - refusing to guess")
        run_bytes = run["clusters"] * cluster_size
        take = min(run_bytes, byte_count - len(out))
        out += read_exact(fh, run["lcn"] * cluster_size, take, sector)
    if len(out) < byte_count:
        raise CollectError("$MFT metadata runlist is shorter than its declared size")
    return bytes(out)


def _parse_attribute_list(content):
    entries = []
    pos = 0
    while pos + 26 <= len(content):
        atype, elen = struct.unpack_from("<IH", content, pos)
        if elen == 0 or pos + elen > len(content):
            break
        name_len = content[pos + 6]
        lowest_vcn = struct.unpack_from("<Q", content, pos + 8)[0]
        ref = struct.unpack_from("<Q", content, pos + 16)[0]
        entries.append(
            {
                "type": atype,
                "name_len": name_len,
                "lowest_vcn": lowest_vcn,
                "record_number": ref & 0xFFFFFFFFFFFF,
            }
        )
        pos += elen
    return entries


def _translate_stream_offset(stream_off, runs, cluster_size):
    vcn_off = 0
    for run in runs:
        run_bytes = run["clusters"] * cluster_size
        if stream_off < vcn_off + run_bytes:
            if run["lcn"] is None:
                raise CollectError("sparse run inside $MFT $DATA - refusing to guess")
            return run["lcn"] * cluster_size + (stream_off - vcn_off)
        vcn_off += run_bytes
    return None


def find_mft_data_runs(fh, boot_info):
    """Full $MFT $DATA runlist: base record plus $ATTRIBUTE_LIST fragments.

    A large or grown $MFT can split its unnamed $DATA runlist across extension
    records listed in a (possibly non-resident) $ATTRIBUTE_LIST. Extension
    records are read through already-known runs; fragments are ordered by
    lowest VCN and verified contiguous. Returns (runs, warnings, extras).
    """
    sector = boot_info["bytes_per_sector"]
    cluster_size = boot_info["cluster_size"]
    record_size = boot_info["record_size"]
    mft_start = boot_info["mft_lcn"] * cluster_size
    warnings = []
    rec0 = read_exact(fh, mft_start, record_size, sector)
    fixed = _fix_record(rec0, record_size, warnings)
    attrs = _walk_attributes(fixed, record_size)

    base = None
    attr_list = None
    for atype, attr_off, alen, non_res, name_len in attrs:
        if atype == 0x80 and non_res and name_len == 0 and base is None:
            base = _data_fragment(fixed, attr_off)
        elif atype == 0x20:
            attr_list = (attr_off, alen, non_res, name_len)
    if base is None:
        raise CollectError("$MFT record 0 has no non-resident unnamed $DATA")
    base_vcn, base_runs, allocated, real, base_warning = base
    if base_warning:
        warnings.append(base_warning)
    if base_vcn != 0:
        raise CollectError("$MFT $DATA base fragment does not start at VCN 0")
    fragments = [(base_vcn, base_runs)]

    extension_records = 0
    if attr_list is not None:
        attr_off, alen, non_res, name_len = attr_list
        if non_res:
            list_runs_off = struct.unpack_from("<H", fixed, attr_off + 32)[0]
            list_real = struct.unpack_from("<Q", fixed, attr_off + 48)[0]
            list_runs, list_warning = mft.decode_runs(fixed, attr_off + list_runs_off)
            if list_warning:
                warnings.append("attribute_list_" + list_warning)
            content = _read_runlist_bytes(fh, list_runs, cluster_size, sector, list_real)
        else:
            content_len = struct.unpack_from("<I", fixed, attr_off + 16)[0]
            content_off = struct.unpack_from("<H", fixed, attr_off + 20)[0]
            content = bytes(fixed[attr_off + content_off : attr_off + content_off + content_len])

        pending = []
        for entry in _parse_attribute_list(content):
            if entry["type"] != 0x80 or entry["name_len"] != 0:
                continue
            if entry["record_number"] == 0:
                continue  # base record itself - its fragment is already held
            pending.append(entry)

        progressed = True
        while pending and progressed:
            progressed = False
            still = []
            ordered = [run for _vcn, runs in sorted(fragments, key=lambda item: item[0]) for run in runs]
            for entry in pending:
                stream_off = entry["record_number"] * record_size
                physical = _translate_stream_offset(stream_off, ordered, cluster_size)
                if physical is None:
                    still.append(entry)
                    continue
                ext = _fix_record(read_exact(fh, physical, record_size, sector), record_size, warnings)
                fragment = None
                for a2type, a2_off, _a2len, a2_res, a2_name in _walk_attributes(ext, record_size):
                    if a2type == 0x80 and a2_res and a2_name == 0:
                        fragment = _data_fragment(ext, a2_off)
                        break
                if fragment is None:
                    raise CollectError("$ATTRIBUTE_LIST extension record %d has no unnamed $DATA" % entry["record_number"])
                lvcn, runs, _alloc, _real, frag_warning = fragment
                if frag_warning:
                    warnings.append(frag_warning)
                if lvcn != entry["lowest_vcn"]:
                    raise CollectError(
                        "$ATTRIBUTE_LIST lowest VCN %d disagrees with extension record fragment %d"
                        % (entry["lowest_vcn"], lvcn)
                    )
                fragments.append((lvcn, runs))
                extension_records += 1
                progressed = True
            pending = still
        if pending:
            raise CollectError(
                "%d $ATTRIBUTE_LIST extension record(s) lie outside the known $MFT runs (first: record %d)"
                % (len(pending), pending[0]["record_number"])
            )

    fragments.sort(key=lambda item: item[0])
    merged = []
    vcn = 0
    for lowest_vcn, runs in fragments:
        if lowest_vcn != vcn:
            raise CollectError("$MFT $DATA fragments are not contiguous (fragment VCN %d, expected %d)" % (lowest_vcn, vcn))
        for run in runs:
            if run["lcn"] is None:
                raise CollectError("sparse run inside $MFT $DATA - refusing to guess")
            merged.append(run)
            vcn += run["clusters"]

    merged_bytes = vcn * cluster_size
    if allocated and merged_bytes != allocated:
        warnings.append("run_total_bytes=%d != allocated_bytes=%d" % (merged_bytes, allocated))
    extras = {
        "mft_data_allocated_bytes": allocated,
        "mft_data_real_bytes": real,
        "mft_attribute_list": attr_list is not None,
        "mft_extension_records": extension_records,
        "mft_fragment_count": len(fragments),
    }
    return merged, warnings, extras


def extract_mft_stream(volume_path, out_path, max_bytes=None, progress=None):
    """Boot sector -> record 0 -> full $MFT $DATA runlist -> raw stream copy."""
    meta = {"volume_path": volume_path, "max_bytes": max_bytes}
    with open(volume_path, "rb", buffering=0) as fh:
        boot = read_exact(fh, 0, 512, 512)
        boot_info = parse_boot_sector(boot)
        meta.update(boot_info)
        sector = boot_info["bytes_per_sector"]
        cluster_size = boot_info["cluster_size"]
        runs, warnings, extras = find_mft_data_runs(fh, boot_info)
        total_clusters = sum(r["clusters"] for r in runs)
        total_bytes = total_clusters * cluster_size
        meta["mft_run_count"] = len(runs)
        meta["mft_total_bytes"] = total_bytes
        meta.update(extras)
        target = total_bytes if max_bytes is None else min(total_bytes, max_bytes)
        meta["mft_truncated"] = target < total_bytes
        written = 0
        with open(out_path, "wb") as out:
            for run in runs:
                if written >= target:
                    break
                if run["lcn"] is None:
                    raise CollectError("sparse run inside $MFT $DATA - refusing to guess")
                run_bytes = run["clusters"] * cluster_size
                run_off = run["lcn"] * cluster_size
                remaining = min(run_bytes, target - written)
                while remaining > 0:
                    step = min(remaining, READ_CHUNK)
                    out.write(read_exact(fh, run_off, step, sector))
                    run_off += step
                    remaining -= step
                    written += step
                    if progress:
                        progress(written, target)
        meta["mft_run_warnings"] = warnings
        meta["mft_bytes_written"] = written
    return meta


def capture_usn_journal(volume, out_path, open_fn=None, close_fn=None, io_fn=None, query_fn=None, progress_every=50):
    """Dump USN records exactly as FSCTL_READ_USN_JOURNAL returns them."""
    open_fn = open_fn or usn.open_volume
    close_fn = close_fn or usn.close_volume
    io_fn = io_fn or usn._device_io
    query_fn = query_fn or usn.query_journal
    handle = None
    meta = {"volume": volume}
    try:
        handle = open_fn(volume)
        journal = query_fn(handle)
        meta["journal"] = journal
        current = journal["first_usn"]
        iterations = 0
        written = 0
        last_usn = current
        with open(out_path, "wb") as out:
            while iterations < usn.MAX_IO_ITERATIONS:
                iterations += 1
                inb = struct.pack("<QIIQQQ", current, 0xFFFFFFFF, 0, 0, 0, journal["journal_id"])
                buf = io_fn(handle, usn.FSCTL_READ_USN_JOURNAL, inb, usn.IO_BUFFER_SIZE)
                if len(buf) < 8:
                    break
                next_usn = struct.unpack_from("<Q", buf, 0)[0]
                out.write(buf[8:])
                written += len(buf) - 8
                last_usn = next_usn
                if next_usn <= current or len(buf) <= 8:
                    break
                current = next_usn
        meta["iterations"] = iterations
        meta["records_bytes_written"] = written
        meta["last_usn"] = last_usn
        meta["note"] = (
            "records concatenated as returned by FSCTL_READ_USN_JOURNAL; each is a self-delimiting "
            "USN_RECORD - parse with tools/usn_parse.py (offline mode)"
        )
    finally:
        if handle is not None:
            close_fn(handle)
    return meta


def wevtutil_qe_command(channel):
    return ["wevtutil", "qe", channel, "/f:xml", "/rd:false"]


def wevtutil_epl_command(channel, out_path):
    return ["wevtutil", "epl", channel, out_path, "/ow:true"]


def safe_channel_name(channel):
    return channel.replace("\\", "_").replace("/", "_").replace(":", "")


class Case:
    def __init__(self, case_dir):
        self.dir = case_dir
        self.steps = []
        self.files = []  # (relative_path, source, step)
        self.errors = []
        self.warnings = []
        self.notes = []

    def rel(self, path):
        return os.path.relpath(path, self.dir).replace("\\", "/")

    def add_file(self, path, source, step):
        self.files.append((self.rel(path), source, step))

    def run_step(self, name, func, requested_skip=False, elevated=True):
        started_at = now_iso()
        skip, reason = elevation_gate(requested_skip, elevated)
        if skip:
            self.steps.append({
                "step": name, "status": "skipped", "reason": reason,
                "started_at": started_at, "finished_at": now_iso(), "notes": [], "outputs": [],
            })
            return
        errors_before = len(self.errors)
        record = {
            "step": name, "status": "ok",
            "started_at": started_at, "finished_at": None, "outputs": [], "notes": [],
        }
        try:
            outputs = func(record)
            if outputs:
                record["outputs"].extend(outputs)
            if len(self.errors) > errors_before and record["status"] == "ok":
                record["status"] = "partial"
        except Exception as exc:
            record["status"] = "failed"
            record["error"] = "%s: %s" % (type(exc).__name__, exc)
            self.errors.append({"step": name, "error": record["error"]})
        record["finished_at"] = now_iso()
        self.steps.append(record)


def _dir_for(case_dir, name):
    path = os.path.join(case_dir, name)
    os.makedirs(path, exist_ok=True)
    return path


def step_registry(case, elevated):
    def run(record):
        out_dir = _dir_for(case.dir, "registry")
        proc = subprocess.run(
            [sys.executable, os.path.join(TOOLS_DIR, "collect_reg.py"), "--out", out_dir, "--quiet"],
            capture_output=True,
        )
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        added = 0
        report_path = os.path.join(out_dir, "collect_reg.json")
        try:
            with open(report_path, encoding="utf-8") as fh:
                reg_manifest = json.load(fh)
            for hive, entry in reg_manifest.get("collected", {}).items():
                full = os.path.join(out_dir, entry["file"])
                if os.path.isfile(full):
                    case.add_file(full, entry.get("source", hive), "registry")
                    added += 1
                for companion in entry.get("companions", []):
                    comp_path = os.path.join(out_dir, companion["file"])
                    if os.path.isfile(comp_path):
                        case.add_file(comp_path, entry.get("source", hive), "registry")
                        added += 1
            if os.path.isfile(report_path):
                case.add_file(report_path, "collect_reg.py manifest", "registry")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            record["notes"].append("could not read collect_reg manifest: %s" % exc)
        if proc.returncode != 0:
            failed = ""
            if os.path.isfile(report_path):
                try:
                    with open(report_path, encoding="utf-8") as fh:
                        failed = ", ".join(sorted(json.load(fh).get("failed") or {}))
                except (OSError, ValueError):
                    failed = ""
            summary = "failed: " + failed if failed else (stderr.splitlines()[-1] if stderr else "no stderr")
            record["status"] = "partial" if added else "failed"
            record["error"] = "collect_reg.py rc=%d (%s)" % (proc.returncode, summary)
            case.errors.append({"step": "registry", "error": record["error"]})
        record["notes"].append("delegated to collect_reg.py (rc=%d, %d file(s))" % (proc.returncode, added))
        return [case.rel(out_dir)]

    case.run_step("registry", run, requested_skip=case.skip_registry, elevated=elevated)


def step_prefetch(case, prefetch_dir):
    def run(record):
        out_dir = _dir_for(case.dir, "prefetch")
        if not os.path.isdir(prefetch_dir):
            raise CollectError("prefetch dir not found: %s" % prefetch_dir)
        copied = 0
        failures = []
        for name in sorted(os.listdir(prefetch_dir)):
            if not name.lower().endswith(".pf"):
                continue
            src = os.path.join(prefetch_dir, name)
            if not os.path.isfile(src):
                continue
            dst = os.path.join(out_dir, name)
            try:
                shutil.copy2(src, dst)
                case.add_file(dst, src, "prefetch")
                copied += 1
            except OSError as exc:
                failures.append({"file": name, "error": str(exc)})
        record["notes"].append("copied %d .pf file(s)" % copied)
        if failures:
            record["notes"].append("failed to copy %d file(s)" % len(failures))
            case.errors.extend({"step": "prefetch", **f} for f in failures)
        return [case.rel(out_dir)]

    case.run_step("prefetch", run, requested_skip=case.skip_prefetch)


def step_evtx(case, channels, with_epl):
    def run(record):
        out_dir = _dir_for(case.dir, "evtx")
        for channel in channels:
            base = safe_channel_name(channel)
            xml_path = os.path.join(out_dir, base + ".xml")
            proc = subprocess.run(wevtutil_qe_command(channel), capture_output=True, timeout=1800)
            if proc.returncode == 0 and proc.stdout:
                with open(xml_path, "wb") as fh:
                    fh.write(proc.stdout)
                case.add_file(xml_path, "wevtutil qe %s" % channel, "evtx")
                record["notes"].append("%s: %d bytes XML" % (channel, len(proc.stdout)))
            else:
                stderr = proc.stderr.decode("utf-8", "replace").strip().splitlines()
                error = proc.returncode if proc.returncode else "empty output"
                record["notes"].append("%s: qe failed (%s) %s" % (channel, error, stderr[0] if stderr else ""))
                case.errors.append({"step": "evtx", "channel": channel, "error": "qe failed: %s" % error})
            if with_epl:
                evtx_path = os.path.join(out_dir, base + ".evtx")
                proc2 = subprocess.run(wevtutil_epl_command(channel, evtx_path), capture_output=True, timeout=1800)
                if proc2.returncode == 0 and os.path.isfile(evtx_path):
                    case.add_file(evtx_path, "wevtutil epl %s" % channel, "evtx")
                else:
                    stderr = proc2.stderr.decode("utf-8", "replace").strip().splitlines()
                    error = proc2.returncode if proc2.returncode else "no file produced"
                    record["notes"].append("%s: epl failed (%s) %s" % (channel, error, stderr[0] if stderr else ""))
                    case.errors.append({"step": "evtx", "channel": channel, "error": "epl failed: %s" % error})
        if any("failed" in n for n in record["notes"]):
            record["status"] = "partial"
        return [case.rel(out_dir)]

    case.run_step("evtx", run, requested_skip=case.skip_evtx)


def step_mft(case, volume, max_bytes):
    def run(record):
        out_dir = _dir_for(case.dir, "mft")
        volume_path = "\\\\.\\" + volume.strip().rstrip(":\\") + ":"
        out_path = os.path.join(out_dir, "mft.bin")
        meta = extract_mft_stream(volume_path, out_path, max_bytes=max_bytes)
        meta_path = os.path.join(out_dir, "mft_boot_info.json")
        with open(meta_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(meta, fh, indent=2)
            fh.write("\n")
        case.add_file(out_path, volume_path, "mft")
        case.add_file(meta_path, volume_path, "mft")
        record["notes"].append(
            "%d MiB of %d MiB $MFT stream (%d run(s))"
            % (meta["mft_bytes_written"] >> 20, meta["mft_total_bytes"] >> 20, meta["mft_run_count"])
        )
        if meta["mft_truncated"]:
            case.warnings.append("mft_truncated_by_max_bytes")
        return [case.rel(out_dir)]

    case.run_step("mft", run, requested_skip=case.skip_mft, elevated=case.elevated)


def step_usn(case, volume):
    def run(record):
        out_dir = _dir_for(case.dir, "usn")
        volume_path = "\\\\.\\" + volume.strip().rstrip(":\\") + ":"
        out_path = os.path.join(out_dir, "usn_journal.bin")
        meta = capture_usn_journal(volume, out_path)
        meta_path = os.path.join(out_dir, "usn_journal.json")
        with open(meta_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(meta, fh, indent=2)
            fh.write("\n")
        case.add_file(out_path, volume_path, "usn")
        case.add_file(meta_path, volume_path, "usn")
        record["notes"].append("%d USN byte(s) in %d read(s)" % (meta["records_bytes_written"], meta["iterations"]))
        return [case.rel(out_dir)]

    case.run_step("usn", run, requested_skip=case.skip_usn, elevated=case.elevated)


def build_manifest(case, args, started_at, finished_at, machine):
    files = []
    total_bytes = 0
    for rel, source, step in case.files:
        full = os.path.join(case.dir, rel.replace("/", os.sep))
        size = os.path.getsize(full) if os.path.isfile(full) else None
        digest = None
        if not args.no_hash and size is not None:
            digest = sha256_file(full)
        if size:
            total_bytes += size
        files.append({"path": rel, "size": size, "sha256": digest, "step": step, "source": source})
    by_step = {}
    for entry in files:
        by_step[entry["step"]] = by_step.get(entry["step"], 0) + 1
    warnings = sorted(set(case.warnings))
    if not case.elevated:
        warnings.append("not_elevated")
    if args.no_hash:
        warnings.append("hashes_skipped")
    return {
        "tool": "collect",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "case": os.path.basename(os.path.abspath(case.dir)),
        "volume": args.volume.strip().rstrip(":\\") + ":",
        "elevated": case.elevated,
        "started_at": started_at,
        "finished_at": finished_at,
        "machine": machine,
        "params": {
            "channels": list(args.channels),
            "with_epl": bool(args.evtx_epl),
            "mft_max_bytes": args.mft_max_bytes,
            "prefetch_dir": args.prefetch_dir,
            "no_hash": bool(args.no_hash),
            "skips": {
                "registry": bool(args.skip_registry),
                "prefetch": bool(args.skip_prefetch),
                "evtx": bool(args.skip_evtx),
                "mft": bool(args.skip_mft),
                "usn": bool(args.skip_usn),
            },
        },
        "steps": case.steps,
        "files": files,
        "counts": {"files": len(files), "bytes": total_bytes, "by_step": by_step},
        "notes": case.notes,
        "errors": case.errors,
        "warnings": warnings,
    }


def print_summary(manifest, quiet):
    if quiet:
        return
    steps = ", ".join("%s=%s" % (s["step"], s["status"]) for s in manifest["steps"])
    sys.stderr.write(
        "[collect] case=%s elevated=%s files=%d bytes=%d\n"
        % (manifest["case"], manifest["elevated"], manifest["counts"]["files"], manifest["counts"]["bytes"])
    )
    sys.stderr.write("[collect] steps: %s\n" % steps)
    for error in manifest["errors"][:5]:
        sys.stderr.write("[collect] error: %s\n" % error)
    if len(manifest["errors"]) > 5:
        sys.stderr.write("[collect] ... %d more errors (see manifest)\n" % (len(manifest["errors"]) - 5))


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="collect.py",
        description="One-command case collection: raw artifacts + hashed manifest. Requires Windows; elevation strongly recommended.",
    )
    ap.add_argument("--case", required=True, help="case output directory (created if missing)")
    ap.add_argument("--volume", default="C:", help="volume to read ($MFT, USN journal) - default C:")
    ap.add_argument("--channels", default=",".join(DEFAULT_CHANNELS), help="event log channels (comma-separated)")
    ap.add_argument("--prefetch-dir", default=DEFAULT_PREFETCH_DIR, help="prefetch source directory")
    ap.add_argument("--evtx-epl", action="store_true", help="also copy binary .evtx via wevtutil epl (archival)")
    ap.add_argument("--mft-max-bytes", type=lambda s: int(s, 0), default=None, help="cap $MFT stream copy (default: full)")
    ap.add_argument("--skip-registry", action="store_true")
    ap.add_argument("--skip-prefetch", action="store_true")
    ap.add_argument("--skip-evtx", action="store_true")
    ap.add_argument("--skip-mft", action="store_true")
    ap.add_argument("--skip-usn", action="store_true")
    ap.add_argument("--no-hash", action="store_true", help="skip SHA256 hashing (fast mode; manifest records null)")
    ap.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    args = ap.parse_args(argv)

    if not WINREG_OK or sys.platform != "win32":
        sys.stderr.write("[collect] fatal: collect.py requires Windows\n")
        return 1
    if args.mft_max_bytes is not None and args.mft_max_bytes <= 0:
        ap.error("--mft-max-bytes must be positive")
    channels = [c.strip() for c in args.channels.split(",") if c.strip()]
    if not args.skip_evtx and not channels:
        ap.error("--channels is empty (or use --skip-evtx)")
    args.channels = channels

    case_dir = os.path.abspath(args.case)
    try:
        os.makedirs(case_dir, exist_ok=True)
    except OSError as exc:
        sys.stderr.write("[collect] fatal: cannot create case dir: %s\n" % exc)
        return 1

    # A case directory is an evidence container. Reusing a populated directory
    # could mix files from different collection runs or overwrite prior evidence.
    if os.listdir(case_dir):
        sys.stderr.write("[collect] fatal: case directory is not empty; choose a new case path: %s\n" % case_dir)
        return 1

    started_at = now_iso()
    case = Case(case_dir)
    case.skip_registry = args.skip_registry
    case.skip_prefetch = args.skip_prefetch
    case.skip_evtx = args.skip_evtx
    case.skip_mft = args.skip_mft
    case.skip_usn = args.skip_usn
    case.elevated = is_elevated()
    if not case.elevated:
        sys.stderr.write(
            "[collect] not elevated: $MFT, USN journal and registry steps will be skipped and recorded as such\n"
        )

    machine = {}
    def collect_machine_info(record):
        nonlocal machine
        machine = machine_info(args.volume)
        machine_path = os.path.join(case_dir, "machine_info.json")
        with open(machine_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(machine, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        case.add_file(machine_path, "winreg/ctypes", "machine_info")
        return [case.rel(machine_path)]

    case.run_step("machine_info", collect_machine_info)

    step_registry(case, case.elevated)
    step_prefetch(case, args.prefetch_dir)
    step_evtx(case, channels, args.evtx_epl)
    step_mft(case, args.volume, args.mft_max_bytes)
    step_usn(case, args.volume)

    manifest = build_manifest(case, args, started_at, now_iso(), machine)
    manifest_path = os.path.join(case_dir, "manifest.json")
    try:
        with open(manifest_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    except OSError as exc:
        sys.stderr.write("[collect] fatal: cannot write manifest: %s\n" % exc)
        return 1

    print_summary(manifest, args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
