#!/usr/bin/env python3
"""usn_parse.py — honest parser for NTFS USN journal records ($UsnJrnl).

Reads either a captured raw $J stream (offline) or the live journal of a
mounted volume via FSCTL calls (Windows, administrator required). Emits
newline-delimited JSON records conforming to schemas/usn.schema.json plus a
machine-readable report (schemas/usn_report.schema.json).

Honesty contract (see SKILL.md "The golden rule"):
  * uninterpretable bytes are reported as skipped regions — never guessed
  * resynchronization points are counted and reported
  * fields absent from a record version are omitted (V4: no timestamp, no name)
  * anomalies surface in the report; they never crash the parser silently

Structure knowledge: references/usn.md — read it before interpreting output.

Usage:
    python tools/usn_parse.py capture.usn --report report.json
    python tools/usn_parse.py capture.usn --name-contains dropper.exe
    python tools/usn_parse.py --volume C: --limit 100        (admin)
    python tools/usn_parse.py --volume C: --enum --limit 50  (admin, experimental)

Exit codes: 0 success (even with anomalies), 1 fatal error, 2 usage error.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import struct
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = 1

REASON_FLAGS = [
    (0x00000001, "DATA_OVERWRITE"),
    (0x00000002, "DATA_EXTEND"),
    (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"),
    (0x00000020, "NAMED_DATA_EXTEND"),
    (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"),
    (0x00000200, "FILE_DELETE"),
    (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"),
    (0x00001000, "RENAME_OLD_NAME"),
    (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"),
    (0x00008000, "BASIC_INFO_CHANGE"),
    (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"),
    (0x00040000, "ENCRYPTION_CHANGE"),
    (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"),
    (0x00200000, "STREAM_CHANGE"),
    (0x00400000, "TRANSACTED_CHANGE"),
    (0x00800000, "INTEGRITY_CHANGE"),
    (0x80000000, "CLOSE"),
]

SOURCE_FLAGS = [
    (0x1, "DATA_MANAGEMENT"),
    (0x2, "AUXILIARY_DATA"),
    (0x4, "REPLICATION_MANAGEMENT"),
    (0x8, "CLIENT_REPLICATION_MANAGEMENT"),
]

_REASON_KNOWN = 0
for _bit, _name in REASON_FLAGS:
    _REASON_KNOWN |= _bit

_SOURCE_KNOWN = 0
for _bit, _name in SOURCE_FLAGS:
    _SOURCE_KNOWN |= _bit

MIN_REC_LEN = {2: 60, 3: 76, 4: 64}
MAX_REC_LEN = 65536

FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_ENUM_USN_DATA = 0x000900B3
FSCTL_READ_USN_JOURNAL = 0x000900BB
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
IO_BUFFER_SIZE = 1 << 20
MAX_IO_ITERATIONS = 100000

_FT_EPOCH = datetime(1601, 1, 1)
_K32 = None


class UsnToolError(RuntimeError):
    def __init__(self, message, winerror=None):
        super().__init__(message)
        self.winerror = winerror


class Stats:
    def __init__(self):
        self.records = 0
        self.emitted = 0
        self.by_version = {}
        self.by_reason = Counter()
        self.min_usn = None
        self.max_usn = None
        self.min_ft = None
        self.max_ft = None
        self.skipped_regions = []
        self.zero_bytes = 0
        self.garbage_bytes = 0
        self.truncated_bytes = 0
        self.usn_offset_deltas = Counter()
        self.warnings = set()

    def count_record(self, rec, live=False):
        self.records += 1
        version = rec["version"]
        self.by_version[version] = self.by_version.get(version, 0) + 1
        for flag in rec["reason_flags"]:
            self.by_reason[flag] += 1
        usn = rec["usn"]
        if self.min_usn is None or usn < self.min_usn:
            self.min_usn = usn
        if self.max_usn is None or usn > self.max_usn:
            self.max_usn = usn
        ft = rec.get("timestamp_filetime")
        if ft:
            if self.min_ft is None or ft < self.min_ft:
                self.min_ft = ft
            if self.max_ft is None or ft > self.max_ft:
                self.max_ft = ft
        if not live and "record_offset" in rec:
            self.usn_offset_deltas[usn - rec["record_offset"]] += 1


def filetime_to_iso(ft):
    if not ft:
        return None
    try:
        dt = _FT_EPOCH + timedelta(microseconds=ft // 10)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (OverflowError, OSError, ValueError):
        return None


def decode_flags(mask, table, known_mask):
    names = [name for bit, name in table if mask & bit]
    unknown = (mask & ~known_mask) & 0xFFFFFFFF
    return names, unknown


def _is_zero_word(buf, off):
    return struct.unpack_from("<Q", buf, off)[0] == 0


def _header_prefix(buf, off):
    if off + 8 > len(buf):
        return None
    rec_len, major, minor = struct.unpack_from("<IHH", buf, off)
    if major not in MIN_REC_LEN:
        return None
    if rec_len < MIN_REC_LEN[major] or rec_len > MAX_REC_LEN:
        return None
    if rec_len % 8:
        return None
    return (rec_len, major, minor)


def _record_bounds_ok(buf, off, rec_len, major):
    if major == 2:
        if off + 60 > len(buf):
            return False
        name_len, name_off = struct.unpack_from("<HH", buf, off + 56)
        header_len = 60
    elif major == 3:
        if off + 76 > len(buf):
            return False
        name_len, name_off = struct.unpack_from("<HH", buf, off + 72)
        header_len = 76
    else:
        if off + 64 > len(buf):
            return False
        ext_count, ext_size = struct.unpack_from("<HH", buf, off + 60)
        if ext_size < 16:
            return False
        return 64 + ext_count * ext_size <= rec_len
    if name_off < header_len or name_off > rec_len:
        return False
    if name_len > rec_len - name_off:
        return False
    return True


def _find_next_header(buf, start):
    off = (start + 7) & ~7
    n = len(buf)
    while off + 8 <= n:
        prefix = _header_prefix(buf, off)
        if prefix is not None:
            rec_len, major, _minor = prefix
            if off + rec_len > n or _record_bounds_ok(buf, off, rec_len, major):
                return off
        off += 8
    return -1


def _add_region(stats, offset, length, reason, context=None):
    if length <= 0:
        return
    region = {"offset": offset, "length": length, "reason": reason}
    if context:
        region["context"] = context
    stats.skipped_regions.append(region)
    if reason == "zero_fill":
        stats.zero_bytes += length
    elif reason == "no_valid_header":
        stats.garbage_bytes += length
    else:
        stats.truncated_bytes += length


def _parse_record(buf, off, rec_len, major, minor, include_raw, live):
    warnings = []
    if minor != 0:
        warnings.append("unknown_minor_version")

    if major in (2, 3):
        if major == 2:
            frn, pfrn, usn, ft, reason, source, sec, attrs, name_len, name_off = struct.unpack_from(
                "<QQQQIIIIHH", buf, off + 8
            )
            frn_s = "0x%016x" % frn
            pfrn_s = "0x%016x" % pfrn
        else:
            frn_b, pfrn_b, usn, ft, reason, source, sec, attrs, name_len, name_off = struct.unpack_from(
                "<16s16sQQIIIIHH", buf, off + 8
            )
            frn_s = "0x%032x" % int.from_bytes(frn_b, "little")
            pfrn_s = "0x%032x" % int.from_bytes(pfrn_b, "little")

        ts = filetime_to_iso(ft)
        if ft != 0 and ts is None:
            warnings.append("timestamp_out_of_range")
        if name_len % 2:
            warnings.append("odd_name_length")
            name_len -= 1
        name = buf[off + name_off : off + name_off + name_len].decode("utf-16-le", "replace").rstrip("\x00")
        if "\ufffd" in name:
            warnings.append("lossy_name")

        reason_flags, reason_unknown = decode_flags(reason, REASON_FLAGS, _REASON_KNOWN)
        source_flags, source_unknown = decode_flags(source, SOURCE_FLAGS, _SOURCE_KNOWN)
        if reason_unknown:
            warnings.append("unknown_reason_bits")
        if source_unknown:
            warnings.append("unknown_source_bits")

        rec = {"tool": "usn_parse", "schema_version": SCHEMA_VERSION, "artifact": "usn", "version": major, "minor_version": minor}
        if not live:
            rec["record_offset"] = off
        rec.update(
            {
                "usn": usn,
                "file_reference": frn_s,
                "parent_file_reference": pfrn_s,
                "timestamp": ts,
                "timestamp_filetime": ft,
                "reason_mask": reason,
                "reason_flags": reason_flags,
                "reason_unknown_mask": reason_unknown,
                "source_info_mask": source,
                "source_flags": source_flags,
                "source_unknown_mask": source_unknown,
                "security_id": sec,
                "file_attributes": attrs,
                "name": name,
                "warnings": warnings,
            }
        )
    else:
        frn_b, pfrn_b, usn, reason, source, remaining, ext_count, ext_size = struct.unpack_from(
            "<16s16sQIIIHH", buf, off + 8
        )
        frn_s = "0x%032x" % int.from_bytes(frn_b, "little")
        pfrn_s = "0x%032x" % int.from_bytes(pfrn_b, "little")
        if ext_size != 16:
            warnings.append("unexpected_extent_size")

        extents = []
        p = off + 64
        for _ in range(ext_count):
            e_offset, e_length = struct.unpack_from("<qq", buf, p)
            extents.append({"offset": e_offset, "length": e_length})
            p += ext_size

        reason_flags, reason_unknown = decode_flags(reason, REASON_FLAGS, _REASON_KNOWN)
        source_flags, source_unknown = decode_flags(source, SOURCE_FLAGS, _SOURCE_KNOWN)
        if reason_unknown:
            warnings.append("unknown_reason_bits")
        if source_unknown:
            warnings.append("unknown_source_bits")

        rec = {"tool": "usn_parse", "schema_version": SCHEMA_VERSION, "artifact": "usn", "version": 4, "minor_version": minor}
        if not live:
            rec["record_offset"] = off
        rec.update(
            {
                "usn": usn,
                "file_reference": frn_s,
                "parent_file_reference": pfrn_s,
                "reason_mask": reason,
                "reason_flags": reason_flags,
                "reason_unknown_mask": reason_unknown,
                "source_info_mask": source,
                "source_flags": source_flags,
                "source_unknown_mask": source_unknown,
                "remaining_extents": remaining,
                "extent_count": ext_count,
                "extent_size": ext_size,
                "extents": extents,
                "warnings": warnings,
            }
        )

    if include_raw:
        rec["raw_hex"] = buf[off : off + rec_len].hex()
    return rec


def iter_records(buf, stats, include_raw=False, live=False, region_context=None):
    n = len(buf)
    off = 0
    while off < n:
        if n - off < 8:
            chunk = buf[off:]
            reason = "zero_fill" if chunk == b"\x00" * len(chunk) else "no_valid_header"
            _add_region(stats, off, n - off, reason, region_context)
            break

        if _is_zero_word(buf, off):
            start = off
            while n - off >= 8 and _is_zero_word(buf, off):
                off += 8
            if n - off > 0 and buf[off:] == b"\x00" * (n - off):
                off = n
            _add_region(stats, start, off - start, "zero_fill", region_context)
            continue

        prefix = _header_prefix(buf, off)
        if prefix is None:
            start = off
            nxt = _find_next_header(buf, off + 8)
            if nxt < 0:
                _add_region(stats, start, n - start, "no_valid_header", region_context)
                break
            _add_region(stats, start, nxt - start, "no_valid_header", region_context)
            off = nxt
            continue

        rec_len, major, minor = prefix
        if off + rec_len > n:
            _add_region(stats, off, n - off, "truncated_tail", region_context)
            break
        if not _record_bounds_ok(buf, off, rec_len, major):
            start = off
            nxt = _find_next_header(buf, off + 8)
            if nxt < 0:
                _add_region(stats, start, n - start, "no_valid_header", region_context)
                break
            _add_region(stats, start, nxt - start, "no_valid_header", region_context)
            off = nxt
            continue

        rec = _parse_record(buf, off, rec_len, major, minor, include_raw, live)
        stats.count_record(rec, live=live)
        yield rec
        off += rec_len


def record_matches(rec, min_usn=None, max_usn=None, reason_mask=None, name_contains=None):
    if min_usn is not None and rec["usn"] < min_usn:
        return False
    if max_usn is not None and rec["usn"] > max_usn:
        return False
    if reason_mask is not None and not (rec["reason_mask"] & reason_mask):
        return False
    if name_contains is not None:
        name = rec.get("name")
        if name is None or name_contains.lower() not in name.lower():
            return False
    return True


def parse_reason_arg(value):
    v = value.strip()
    if v.lower().startswith("0x"):
        return int(v, 16)
    upper = v.upper()
    if upper.startswith("USN_REASON_"):
        upper = upper[len("USN_REASON_") :]
    for bit, name in REASON_FLAGS:
        if name == upper:
            return bit
    raise ValueError(f"unknown reason flag: {value}")


def build_report(stats, *, mode, input_path=None, input_size=0, journal=None, filters=None, extra_warnings=()):
    warnings = set(stats.warnings)
    warnings.update(extra_warnings)
    if stats.records == 0:
        warnings.add("empty_input" if input_size == 0 else "no_valid_records")
    if stats.truncated_bytes:
        warnings.add("truncated_tail_present")
    if stats.zero_bytes:
        warnings.add("zero_fill_present")

    usn_offset = None
    if mode == "offline" and stats.usn_offset_deltas:
        base, base_count = stats.usn_offset_deltas.most_common(1)[0]
        usn_offset = {
            "distinct_deltas": len(stats.usn_offset_deltas),
            "base_delta": base,
            "anomaly_records": stats.records - base_count,
        }
        if len(stats.usn_offset_deltas) > 1:
            warnings.add("usn_offset_inconsistent")
        elif base != 0:
            warnings.add("capture_not_at_stream_start")

    return {
        "tool": "usn_parse",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": mode,
        "input": {"path": input_path, "size_bytes": input_size},
        "journal": journal,
        "counts": {
            "records": stats.records,
            "emitted": stats.emitted,
            "by_version": dict(stats.by_version),
            "by_reason": dict(stats.by_reason.most_common()),
        },
        "usn_range": {"min": stats.min_usn, "max": stats.max_usn},
        "time_range": {
            "min_utc": filetime_to_iso(stats.min_ft),
            "max_utc": filetime_to_iso(stats.max_ft),
        },
        "skipped_regions": stats.skipped_regions,
        "usn_offset": usn_offset,
        "filters": filters or {},
        "warnings": sorted(warnings),
    }


def _open_jsonl(path):
    if path == "-":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(newline="\n")
        return sys.stdout, False
    return open(path, "w", encoding="utf-8", newline="\n"), True


def _emit_records(gen, args, stats, reason_mask):
    fh, should_close = _open_jsonl(args.jsonl)
    try:
        for rec in gen:
            if not record_matches(rec, args.min_usn, args.max_usn, reason_mask, args.name_contains):
                continue
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            stats.emitted += 1
            if args.limit is not None and stats.emitted >= args.limit:
                stats.warnings.add("stopped_early_by_limit")
                break
    finally:
        if should_close:
            fh.close()


def _kernel32():
    global _K32
    if sys.platform != "win32":
        raise UsnToolError("live USN access requires Windows")
    if _K32 is None:
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.restype = ctypes.c_void_p
        k.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        k.DeviceIoControl.restype = ctypes.c_int
        k.DeviceIoControl.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        k.CloseHandle.restype = ctypes.c_int
        _K32 = k
    return _K32


def open_volume(volume):
    k = _kernel32()
    v = volume.strip()
    if v.startswith("\\\\?\\"):
        v = v[4:]
    if v.startswith("\\\\.\\"):
        path = v
    else:
        v = v.rstrip("\\")
        letter = v.rstrip(":")
        path = "\\\\.\\" + letter + ":"
    handle = k.CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
    if not handle or handle == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        message = f"cannot open {path}: {ctypes.FormatError(err)} (winerror {err})"
        if err == 5:
            message += "; administrator privileges are required for live USN access"
        raise UsnToolError(message, winerror=err)
    return handle


def close_volume(handle):
    try:
        _kernel32().CloseHandle(handle)
    except Exception:
        pass


def _device_io(handle, code, in_bytes, out_size):
    k = _kernel32()
    in_buf = ctypes.create_string_buffer(in_bytes, len(in_bytes)) if in_bytes is not None else None
    in_len = len(in_bytes) if in_bytes is not None else 0
    out_buf = ctypes.create_string_buffer(out_size)
    returned = ctypes.c_uint32(0)
    ok = k.DeviceIoControl(
        handle,
        code,
        ctypes.cast(in_buf, ctypes.c_void_p) if in_buf is not None else None,
        in_len,
        ctypes.cast(out_buf, ctypes.c_void_p),
        out_size,
        ctypes.byref(returned),
        None,
    )
    if not ok:
        err = ctypes.get_last_error()
        raise UsnToolError(
            f"DeviceIoControl 0x{code:08X} failed: {ctypes.FormatError(err)} (winerror {err})",
            winerror=err,
        )
    return bytes(out_buf.raw[: returned.value])


def query_journal(handle):
    out = _device_io(handle, FSCTL_QUERY_USN_JOURNAL, None, 128)
    if len(out) < 56:
        raise UsnToolError(f"USN_JOURNAL_DATA too short: {len(out)} bytes (expected >= 56)")
    jid, first, nxt, lowest, mx, mx_size, delta = struct.unpack_from("<QQQQQQQ", out, 0)
    return {
        "journal_id": jid,
        "first_usn": first,
        "next_usn": nxt,
        "lowest_valid_usn": lowest,
        "max_usn": mx,
        "maximum_size": mx_size,
        "allocation_delta": delta,
        "structure_bytes": len(out),
    }


def iter_live_read(handle, journal_id, start_usn, stats, include_raw):
    current = start_usn
    for _ in range(MAX_IO_ITERATIONS):
        inb = struct.pack("<QIIQQQ", current, 0xFFFFFFFF, 0, 0, 0, journal_id)
        out = _device_io(handle, FSCTL_READ_USN_JOURNAL, inb, IO_BUFFER_SIZE)
        if len(out) < 8:
            break
        next_usn = struct.unpack_from("<Q", out, 0)[0]
        for rec in iter_records(out[8:], stats, include_raw=include_raw, live=True, region_context="io-buffer"):
            yield rec
        if next_usn <= current or len(out) <= 8:
            break
        current = next_usn


def iter_live_enum(handle, stats, include_raw):
    start_frn = 0
    for _ in range(MAX_IO_ITERATIONS):
        inb = struct.pack("<QQQ", start_frn, 0, 0x7FFFFFFFFFFFFFFF)
        out = _device_io(handle, FSCTL_ENUM_USN_DATA, inb, IO_BUFFER_SIZE)
        if len(out) < 8:
            break
        next_frn = struct.unpack_from("<Q", out, 0)[0]
        for rec in iter_records(out[8:], stats, include_raw=include_raw, live=True, region_context="io-buffer"):
            yield rec
        if next_frn == 0 or next_frn <= start_frn:
            break
        start_frn = next_frn


def _print_summary(report, quiet):
    if quiet:
        return
    counts = report["counts"]
    regions = report["skipped_regions"]
    region_txt = ", ".join(f"{r['reason']}:{r['length']}" for r in regions[:5]) or "none"
    sys.stderr.write(
        f"[usn_parse] mode={report['mode']} records={counts['records']} "
        f"emitted={counts['emitted']} by_version={counts['by_version']}\n"
    )
    sys.stderr.write(f"[usn_parse] skipped_regions={len(regions)} ({region_txt})\n")
    warn = report["warnings"]
    sys.stderr.write(f"[usn_parse] warnings: {', '.join(warn) if warn else 'none'}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="usn_parse.py",
        description="Honest parser for NTFS USN journal records. Structure knowledge: references/usn.md",
    )
    ap.add_argument("input", nargs="?", help="raw $J capture file (offline mode)")
    ap.add_argument("--volume", metavar="X:", help="live mode: volume to read, e.g. C: (requires admin)")
    ap.add_argument("--enum", action="store_true", help="live mode: FSCTL_ENUM_USN_DATA inventory (experimental)")
    ap.add_argument("--start-usn", type=lambda s: int(s, 0), default=None, help="live read start USN (default: FirstUsn)")
    ap.add_argument("--jsonl", default="-", help="JSONL output path ('-' = stdout, default)")
    ap.add_argument("--report", default=None, help="write machine-readable JSON report to this path")
    ap.add_argument("--raw", action="store_true", help="include raw record bytes as hex (raw_hex)")
    ap.add_argument("--limit", type=int, default=None, help="stop after N emitted records")
    ap.add_argument("--min-usn", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--max-usn", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--reason", default=None, help="only records containing this reason flag (NAME or 0xHEX)")
    ap.add_argument("--name-contains", default=None, help="only records whose name contains this substring (case-insensitive)")
    ap.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    args = ap.parse_args(argv)

    if bool(args.input) == bool(args.volume):
        ap.error("provide exactly one of INPUT (offline capture) or --volume X: (live)")

    try:
        reason_mask = parse_reason_arg(args.reason) if args.reason else None
    except ValueError as exc:
        ap.error(str(exc))

    stats = Stats()
    journal = None
    extra_warnings = []
    input_path = None
    input_size = 0
    filters = {
        "min_usn": args.min_usn,
        "max_usn": args.max_usn,
        "reason": args.reason,
        "name_contains": args.name_contains,
        "limit": args.limit,
        "start_usn": args.start_usn,
    }

    if args.volume:
        mode = "live-enum" if args.enum else "live-read"
        handle = None
        try:
            handle = open_volume(args.volume)
            journal = query_journal(handle)
            if args.enum:
                extra_warnings.append("enum_mode_experimental")
                gen = iter_live_enum(handle, stats, args.raw)
            else:
                start = args.start_usn if args.start_usn is not None else journal["first_usn"]
                gen = iter_live_read(handle, journal["journal_id"], start, stats, args.raw)
            _emit_records(gen, args, stats, reason_mask)
        except UsnToolError as exc:
            sys.stderr.write(f"[usn_parse] fatal: {exc}\n")
            return 1
        finally:
            if handle is not None:
                close_volume(handle)
    else:
        mode = "offline"
        input_path = args.input
        try:
            with open(input_path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            sys.stderr.write(f"[usn_parse] fatal: cannot read {input_path}: {exc}\n")
            return 1
        input_size = len(data)
        gen = iter_records(data, stats, include_raw=args.raw, live=False)
        _emit_records(gen, args, stats, reason_mask)

    report = build_report(
        stats,
        mode=mode,
        input_path=input_path,
        input_size=input_size,
        journal=journal,
        filters=filters,
        extra_warnings=extra_warnings,
    )
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
        except OSError as exc:
            sys.stderr.write(f"[usn_parse] fatal: cannot write report: {exc}\n")
            return 1
    _print_summary(report, args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
