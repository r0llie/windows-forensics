#!/usr/bin/env python3
"""mft_parse.py — honest parser for NTFS $MFT FILE records.

Reads a captured raw $MFT file (the bytes of the MFT data stream) and emits
newline-delimited JSON records conforming to schemas/mft.schema.json plus a
machine-readable report (schemas/mft_report.schema.json).

Honesty contract (see SKILL.md "The golden rule"):
  * USA/fixup is verified before parsing; mismatches are warned, never hidden
  * unparseable slots and aborted attribute walks are declared, never guessed
  * deleted records are reported as deleted; slack bytes are never attributed
  * timestomp output is observations only, not verdicts (references/mft.md §10)

Structure knowledge: references/mft.md — read it before interpreting output.

Usage:
    python tools/mft_parse.py capture.mft --report report.json
    python tools/mft_parse.py capture.mft --deleted --name-contains dropper
    python tools/mft_parse.py capture.mft --record-size 4096 --raw --limit 100

Exit codes: 0 success (even with anomalies), 1 fatal error, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

TOOL_VERSION = "0.2.0"
SCHEMA_VERSION = 1

FILE_MAGIC = b"FILE"
END_MARKER = 0xFFFFFFFF

FLAG_IN_USE = 0x0001
FLAG_DIRECTORY = 0x0002
FLAG_EXTENSION = 0x0004
FLAG_SPECIAL_INDEX = 0x0008

ATTR_TYPE_NAMES = {
    0x10: "STANDARD_INFORMATION",
    0x20: "ATTRIBUTE_LIST",
    0x30: "FILE_NAME",
    0x40: "OBJECT_ID",
    0x50: "SECURITY_DESCRIPTOR",
    0x60: "VOLUME_NAME",
    0x70: "VOLUME_INFORMATION",
    0x80: "DATA",
    0x90: "INDEX_ROOT",
    0xA0: "INDEX_ALLOCATION",
    0xB0: "BITMAP",
    0xC0: "REPARSE_POINT",
    0xD0: "EA_INFORMATION",
    0xE0: "EA",
    0xF0: "PROPERTY_SET",
    0x100: "LOGGED_UTILITY_STREAM",
}

NAMESPACE_NAMES = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32 & DOS"}
NAME_PREFERENCE = [3, 1, 0, 2]

RECORD_SIZE_CANDIDATES = (1024, 4096, 2048, 8192, 512)
MAX_ATTRIBUTES_PER_RECORD = 1024
MAX_RUNS_PER_ATTRIBUTE = 4096

_FT_EPOCH = datetime(1601, 1, 1)


class MftToolError(RuntimeError):
    pass


class Stats:
    def __init__(self):
        self.slots = 0
        self.parsed = 0
        self.in_use = 0
        self.deleted = 0
        self.directories = 0
        self.extensions = 0
        self.emitted = 0
        self.zero_slots = 0
        self.no_magic_slots = 0
        self.parse_errors = 0
        self.usa_mismatches = 0
        self.extension_attributes = 0
        self.stale_attribute_list_entries = 0
        self.linked_extension_records = 0
        self.timestomp_records = 0
        self.timestomp = Counter()
        self.skipped_regions = []
        self.warnings = set()

    def count_record(self, rec):
        self.parsed += 1
        if rec["in_use"]:
            self.in_use += 1
        else:
            self.deleted += 1
        if rec["is_directory"]:
            self.directories += 1
        if rec["is_extension"]:
            self.extensions += 1
        if rec["timestomp_flags"]:
            self.timestomp_records += 1
            for flag in rec["timestomp_flags"]:
                self.timestomp[flag] += 1


def filetime_to_iso(ft):
    if not ft:
        return None
    try:
        dt = _FT_EPOCH + timedelta(microseconds=ft // 10)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (OverflowError, OSError, ValueError):
        return None


def add_skip(stats, offset, length, reason):
    if length <= 0:
        return
    regions = stats.skipped_regions
    if regions:
        last = regions[-1]
        if last["reason"] == reason and last["offset"] + last["length"] == offset:
            last["length"] += length
            return
    regions.append({"offset": offset, "length": length, "reason": reason})


def detect_record_size(buf):
    n = len(buf)
    scan = min(n, 8 << 20)
    best = None
    for size in RECORD_SIZE_CANDIDATES:
        slots = scan // size
        if slots < 1:
            continue
        hits = 0
        for i in range(slots):
            if buf[i * size : i * size + 4] == FILE_MAGIC:
                hits += 1
        frac = hits / slots
        key = (frac, -size)
        if best is None or key > best[0]:
            best = (key, size, frac, slots)
    if best is None or best[2] < 0.5:
        return None, {}
    return best[1], {"magic_ratio": round(best[2], 4), "sampled_slots": best[3]}


def apply_fixup(buf, off, record_size, warnings):
    rec = bytearray(buf[off : off + record_size])
    usa_off, usa_words = struct.unpack_from("<HH", rec, 0x04)
    if usa_words < 2 or usa_off < 8 or usa_off + usa_words * 2 > record_size:
        warnings.append("usa_invalid")
        return bytes(rec)
    num_sectors = usa_words - 1
    if record_size % num_sectors:
        warnings.append("usa_invalid")
        return bytes(rec)
    sector_size = record_size // num_sectors
    if sector_size % 512:
        warnings.append("usa_unusual_sector_size")
    usn = struct.unpack_from("<H", rec, usa_off)[0]
    positions = [i * sector_size - 2 for i in range(1, num_sectors + 1)]
    for pos in positions:
        if pos + 2 > record_size or struct.unpack_from("<H", rec, pos)[0] != usn:
            warnings.append("usa_mismatch")
            return bytes(rec)
    for i, pos in enumerate(positions, start=1):
        original = struct.unpack_from("<H", rec, usa_off + 2 * i)[0]
        struct.pack_into("<H", rec, pos, original)
    return bytes(rec)


def decode_runs(buf, start):
    runs = []
    lcn = 0
    p = start
    n = len(buf)
    while p < n and len(runs) < MAX_RUNS_PER_ATTRIBUTE:
        header = buf[p]
        p += 1
        if header == 0:
            return runs, None
        length_size = header & 0x0F
        offset_size = header >> 4
        if length_size == 0 or p + length_size + offset_size > n:
            return runs, "runlist_truncated"
        clusters = int.from_bytes(buf[p : p + length_size], "little")
        p += length_size
        if offset_size == 0:
            runs.append({"lcn": None, "clusters": clusters})
        else:
            delta = int.from_bytes(buf[p : p + offset_size], "little", signed=True)
            p += offset_size
            lcn += delta
            runs.append({"lcn": lcn, "clusters": clusters})
    if len(runs) >= MAX_RUNS_PER_ATTRIBUTE:
        return runs, "runlist_too_long"
    return runs, "runlist_terminator_missing"


def parse_si(value, warnings):
    if len(value) < 48:
        warnings.append("standard_information_too_short")
        return None
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", value, 0)
    out = {
        "created": filetime_to_iso(created),
        "created_filetime": created,
        "modified": filetime_to_iso(modified),
        "modified_filetime": modified,
        "mft_modified": filetime_to_iso(mft_modified),
        "mft_modified_filetime": mft_modified,
        "accessed": filetime_to_iso(accessed),
        "accessed_filetime": accessed,
        "dos_flags": struct.unpack_from("<I", value, 0x20)[0],
        "value_length": len(value),
    }
    if len(value) >= 0x38:
        out["owner_id"] = struct.unpack_from("<I", value, 0x30)[0]
        out["security_id"] = struct.unpack_from("<I", value, 0x34)[0]
    if len(value) >= 0x40:
        out["quota_charged"] = struct.unpack_from("<Q", value, 0x38)[0]
    if len(value) >= 0x48:
        out["last_usn"] = struct.unpack_from("<Q", value, 0x40)[0]
    return out


def parse_fn(value, warnings):
    if len(value) < 0x42:
        warnings.append("file_name_too_short")
        return None
    parent = struct.unpack_from("<Q", value, 0)[0]
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", value, 0x08)
    allocated, real, flags, reparse = struct.unpack_from("<QQII", value, 0x28)
    name_len = value[0x40]
    namespace = value[0x41]
    name_bytes = value[0x42 : 0x42 + name_len * 2]
    if len(name_bytes) < name_len * 2:
        warnings.append("file_name_truncated")
        return None
    return {
        "parent_reference": "0x%016x" % parent,
        "created": filetime_to_iso(created),
        "created_filetime": created,
        "modified": filetime_to_iso(modified),
        "modified_filetime": modified,
        "mft_modified": filetime_to_iso(mft_modified),
        "mft_modified_filetime": mft_modified,
        "accessed": filetime_to_iso(accessed),
        "accessed_filetime": accessed,
        "allocated_size": allocated,
        "real_size": real,
        "flags": flags,
        "namespace": namespace,
        "namespace_name": NAMESPACE_NAMES.get(namespace, "unknown"),
        "name": name_bytes.decode("utf-16-le", "replace"),
    }


def parse_attribute_list(value, warnings):
    entries = []
    p = 0
    n = len(value)
    while p + 26 <= n:
        atype, alen, name_len, name_off = struct.unpack_from("<IHBB", value, p)
        if alen == 0:
            break
        if alen < 26 or p + alen > n:
            warnings.append("attribute_list_entry_out_of_range")
            break
        start_vcn, base_ref, aid = struct.unpack_from("<QQH", value, p + 8)
        entry_name = None
        if name_len:
            name_start = p + name_off
            if name_off > 0 and name_start + name_len * 2 <= p + alen:
                entry_name = value[name_start : name_start + name_len * 2].decode("utf-16-le", "replace")
        entries.append(
            {
                "type": atype,
                "type_name": ATTR_TYPE_NAMES.get(atype, "UNKNOWN"),
                "starting_vcn": start_vcn,
                "record_number": base_ref & 0xFFFFFFFFFFFF,
                "record_sequence": base_ref >> 48,
                "base_reference": "0x%016x" % base_ref,
                "attribute_id": aid,
                "name": entry_name,
            }
        )
        p += alen
    return entries


def build_extension_index(buf, record_size):
    """Map (base record number, base sequence number) -> extension record numbers.

    A header-only sweep: every FILE record whose BaseRecordReference has a
    non-zero sequence is an extension record for that base incarnation. This
    mirrors MFTECmd's MftRecordToBaseRecord linkage (key = entry-seq) and also
    works when the base record's $ATTRIBUTE_LIST is non-resident (its content
    is not in the $MFT stream). Sequence-aware keying avoids merging stale
    extension records left over from a previous incarnation of the record.
    Callers must look deleted base records up under sequence-1: NTFS
    increments the base sequence when the record is freed, so extension
    records recorded against the previous incarnation still reference it.
    """
    index = {}
    n = len(buf)
    off = 0
    while off + record_size <= n:
        if buf[off : off + 4] == FILE_MAGIC:
            base_ref = struct.unpack_from("<Q", buf, off + 0x20)[0]
            if base_ref:
                entry = base_ref & 0xFFFFFFFFFFFF
                seq = base_ref >> 48
                if seq:
                    index.setdefault((entry, seq), []).append(off // record_size)
        off += record_size
    return index


def merge_extension_records(buf, record_size, ext_offsets, file_names, data_attrs, attributes, warnings, stats):
    """Merge $FILE_NAME / $DATA attributes from linked extension records.

    Mirrors MFTECmd: every attribute of every extension record linked via
    BaseRecordReference becomes part of the base record's attribute set.
    Records that cannot be parsed are reported, never guessed.
    """
    for rec_no in ext_offsets:
        ext_off = rec_no * record_size
        raw = buf[ext_off : ext_off + record_size]
        if raw == b"\x00" * record_size or raw[:4] != FILE_MAGIC:
            warnings.append("extension_record_not_a_file_record")
            continue
        ext = apply_fixup(buf, ext_off, record_size, [])
        e_first, _e_flags, e_used = struct.unpack_from("<HHI", ext, 0x14)
        e_used = min(e_used, record_size)
        off = e_first
        count = 0
        while off + 16 <= e_used and count < MAX_ATTRIBUTES_PER_RECORD:
            count += 1
            atype, alen, non_res, name_len, name_off, aflags, aid = struct.unpack_from("<IIBBHHH", ext, off)
            if atype == END_MARKER or alen < 24 or alen % 8 or off + alen > record_size:
                break
            aname = None
            if name_len and name_off >= 0x10 and off + name_off + name_len * 2 <= off + alen:
                aname = ext[off + name_off : off + name_off + name_len * 2].decode("utf-16-le", "replace")
            attributes.append(
                {
                    "type": atype,
                    "type_name": ATTR_TYPE_NAMES.get(atype, "UNKNOWN"),
                    "non_resident": non_res,
                    "id": aid,
                    "flags": aflags,
                    "length": alen,
                    "name": aname,
                    "fragment_record": rec_no,
                }
            )
            stats.extension_attributes += 1
            if atype == 0x30 and not non_res:
                value_length, value_offset = struct.unpack_from("<IH", ext, off + 16)
                if value_offset >= 0x18 and off + value_offset + value_length <= off + alen:
                    fn = parse_fn(ext[off + value_offset : off + value_offset + value_length], warnings)
                    if fn is not None and not any(
                        f["name"] == fn["name"]
                        and f["namespace"] == fn["namespace"]
                        and f["created_filetime"] == fn["created_filetime"]
                        for f in file_names
                    ):
                        file_names.append(fn)
            elif atype == 0x80:
                if not non_res:
                    value_length = struct.unpack_from("<I", ext, off + 16)[0]
                    data_attrs.append({"name": aname, "non_resident": False, "size": value_length, "fragment_record": rec_no})
                else:
                    starting_vcn, _last_vcn = struct.unpack_from("<qq", ext, off + 16)
                    runs_offset, compression_unit = struct.unpack_from("<HH", ext, off + 32)
                    a_alloc, a_real, a_init = struct.unpack_from("<QQQ", ext, off + 40)
                    runs, run_warning = decode_runs(ext, off + runs_offset)
                    if run_warning:
                        warnings.append(run_warning)
                    data_attrs.append(
                        {
                            "name": aname,
                            "non_resident": True,
                            "size": a_real,
                            "allocated_size": a_alloc,
                            "initialized_size": a_init,
                            "compression_unit": compression_unit,
                            "run_count": len(runs),
                            "first_lcn": runs[0]["lcn"] if runs else None,
                            "fragmented": len(runs) > 1,
                            "starting_vcn": starting_vcn,
                            "fragment_record": rec_no,
                        }
                    )
            off += alen


def merge_attribute_list_fragments(
    buf, record_size, base_index, attribute_list, file_names, data_attrs, attributes, warnings, stats, skip=()
):
    """Fallback: resolve $FILE_NAME / $DATA fragments named by $ATTRIBUTE_LIST entries.

    Covers extension records that do not carry a BaseRecordReference link
    (unusual layouts). Extension records already merged via the base-ref
    index are skipped.
    """
    resolved = 0
    for entry in attribute_list:
        if entry["type"] not in (0x30, 0x80):
            continue
        rec_no = entry["record_number"]
        if rec_no == base_index or rec_no in skip:
            continue
        ext_off = rec_no * record_size
        if ext_off + record_size > len(buf):
            if "attribute_list_extension_outside_capture" not in warnings:
                warnings.append("attribute_list_extension_outside_capture")
            continue
        raw = buf[ext_off : ext_off + record_size]
        if raw == b"\x00" * record_size or raw[:4] != FILE_MAGIC:
            if "attribute_list_extension_not_a_file_record" not in warnings:
                warnings.append("attribute_list_extension_not_a_file_record")
            continue
        target_seq = struct.unpack_from("<H", raw, 0x10)[0]
        if entry["record_sequence"] != target_seq:
            stats.stale_attribute_list_entries += 1
            if "attribute_list_entry_stale" not in warnings:
                warnings.append("attribute_list_entry_stale")
            continue
        ext = apply_fixup(buf, ext_off, record_size, [])
        e_first, e_flags, e_used = struct.unpack_from("<HHI", ext, 0x14)
        e_used = min(e_used, record_size)
        off = e_first
        candidates = []
        while off + 16 <= e_used:
            atype, alen, non_res, name_len, name_off, aflags, aid = struct.unpack_from("<IIBBHHH", ext, off)
            if atype == END_MARKER:
                break
            if alen < 24 or alen % 8 or off + alen > record_size:
                break
            if atype == entry["type"]:
                candidates.append((off, atype, alen, bool(non_res), name_len, name_off, aflags, aid))
            off += alen
        chosen = None
        for cand in candidates:
            if cand[7] == entry["attribute_id"]:
                chosen = cand
                break
        if chosen is None and len(candidates) == 1:
            chosen = candidates[0]
        if chosen is None:
            continue
        off, atype, alen, non_res, name_len, name_off, aflags, aid = chosen
        aname = None
        if name_len:
            name_start = off + name_off
            if name_off >= 0x10 and name_start + name_len * 2 <= off + alen:
                aname = ext[name_start : name_start + name_len * 2].decode("utf-16-le", "replace")
        attributes.append(
            {
                "type": atype,
                "type_name": ATTR_TYPE_NAMES.get(atype, "UNKNOWN"),
                "non_resident": non_res,
                "id": aid,
                "flags": aflags,
                "length": alen,
                "name": aname,
                "fragment_record": rec_no,
            }
        )
        if atype == 0x30 and not non_res:
            value_length, value_offset = struct.unpack_from("<IH", ext, off + 16)
            if value_offset >= 0x18 and off + value_offset + value_length <= off + alen:
                fn = parse_fn(ext[off + value_offset : off + value_offset + value_length], warnings)
                if fn is not None and not any(
                    f["name"] == fn["name"]
                    and f["namespace"] == fn["namespace"]
                    and f["created_filetime"] == fn["created_filetime"]
                    for f in file_names
                ):
                    file_names.append(fn)
                    resolved += 1
        elif atype == 0x80:
            if not non_res:
                value_length = struct.unpack_from("<I", ext, off + 16)[0]
                data_attrs.append({"name": aname, "non_resident": False, "size": value_length, "fragment_record": rec_no})
                resolved += 1
            else:
                starting_vcn, _last_vcn = struct.unpack_from("<qq", ext, off + 16)
                runs_offset, compression_unit = struct.unpack_from("<HH", ext, off + 32)
                a_alloc, a_real, a_init = struct.unpack_from("<QQQ", ext, off + 40)
                runs, run_warning = decode_runs(ext, off + runs_offset)
                if run_warning:
                    warnings.append(run_warning)
                data_attrs.append(
                    {
                        "name": aname,
                        "non_resident": True,
                        "size": a_real,
                        "allocated_size": a_alloc,
                        "initialized_size": a_init,
                        "compression_unit": compression_unit,
                        "run_count": len(runs),
                        "first_lcn": runs[0]["lcn"] if runs else None,
                        "fragmented": len(runs) > 1,
                        "starting_vcn": starting_vcn,
                        "fragment_record": rec_no,
                    }
                )
                resolved += 1
    if resolved:
        stats.extension_attributes += resolved


def select_primary_fn(file_names):
    for namespace in NAME_PREFERENCE:
        for fn in file_names:
            if fn["namespace"] == namespace:
                return fn
    return None


def compute_timestomp_flags(si, primary_fn):
    flags = []
    if si is None:
        return flags
    times = [
        si["created_filetime"],
        si["modified_filetime"],
        si["mft_modified_filetime"],
        si["accessed_filetime"],
    ]
    if all(t == 0 for t in times):
        flags.append("si_timestamps_zero")
    else:
        for t in (si["created_filetime"], si["modified_filetime"]):
            if t and t % 10_000_000 == 0:
                flags.append("si_whole_second_precision")
                break
    if primary_fn is not None:
        fn_created = primary_fn["created_filetime"]
        if si["created_filetime"] and fn_created and si["created_filetime"] < fn_created:
            flags.append("si_created_before_fn_created")
    return flags


def parse_record(buf, off, record_size, index, stats, include_raw, ext_offsets=()):
    raw = buf[off : off + record_size]
    if raw == b"\x00" * record_size:
        stats.zero_slots += 1
        add_skip(stats, off, record_size, "zero_fill")
        return None
    if raw[:4] != FILE_MAGIC:
        stats.no_magic_slots += 1
        add_skip(stats, off, record_size, "no_file_magic")
        return None

    warnings = []
    rec = apply_fixup(buf, off, record_size, warnings)
    if "usa_mismatch" in warnings:
        stats.usa_mismatches += 1

    lsn, seq, links, first_attr, flags, used, allocated, base_ref, next_attr_id = struct.unpack_from(
        "<QHHHHIIQH", rec, 0x08
    )
    used = min(used, record_size)

    if first_attr < 0x2A or first_attr >= record_size:
        warnings.append("first_attribute_offset_invalid")
        first_attr = None
    if used < 0x30 or (first_attr is not None and used < first_attr):
        warnings.append("used_size_out_of_range")

    attributes = []
    standard_information = None
    file_names = []
    data_attrs = []
    attribute_list = []
    has_attribute_list = False

    attr_off = first_attr
    attr_end = min(used, record_size) if first_attr is not None else None
    count = 0
    while attr_off is not None and attr_end is not None and attr_off + 16 <= attr_end:
        if count >= MAX_ATTRIBUTES_PER_RECORD:
            warnings.append("attribute_count_limit_reached")
            break
        count += 1
        atype, alen, non_res, name_len, name_off, aflags, aid = struct.unpack_from(
            "<IIBBHHH", rec, attr_off
        )
        if atype == END_MARKER:
            break
        if alen < 24 or alen % 8 or attr_off + alen > record_size:
            warnings.append("attribute_walk_aborted")
            break

        aname = None
        if name_len:
            name_start = attr_off + name_off
            if name_off < 0x10 or name_len > 255 or name_start + name_len * 2 > attr_off + alen:
                warnings.append("attribute_name_out_of_range")
            else:
                aname = rec[name_start : name_start + name_len * 2].decode("utf-16-le", "replace")

        inventory = {
            "type": atype,
            "type_name": ATTR_TYPE_NAMES.get(atype, "UNKNOWN"),
            "non_resident": bool(non_res),
            "id": aid,
            "flags": aflags,
            "length": alen,
            "name": aname,
        }

        if not non_res:
            value_length, value_offset = struct.unpack_from("<IH", rec, attr_off + 16)
            value_start = attr_off + value_offset
            value = None
            if value_offset < 0x18 or value_start + value_length > attr_off + alen:
                warnings.append("attribute_value_out_of_range")
            else:
                value = rec[value_start : value_start + value_length]
            inventory["value_length"] = value_length
            attributes.append(inventory)

            if value is not None:
                if atype == 0x10:
                    if standard_information is not None:
                        warnings.append("multiple_standard_information")
                    else:
                        standard_information = parse_si(value, warnings)
                elif atype == 0x30:
                    fn = parse_fn(value, warnings)
                    if fn is not None:
                        file_names.append(fn)
                elif atype == 0x80:
                    data_attrs.append({"name": aname, "non_resident": False, "size": value_length})
                elif atype == 0x20:
                    has_attribute_list = True
                    attribute_list = parse_attribute_list(value, warnings)
        else:
            starting_vcn, last_vcn = struct.unpack_from("<qq", rec, attr_off + 16)
            runs_offset, compression_unit = struct.unpack_from("<HH", rec, attr_off + 32)
            a_alloc, a_real, a_init = struct.unpack_from("<QQQ", rec, attr_off + 40)
            inventory["value_length"] = a_real
            inventory["starting_vcn"] = starting_vcn
            inventory["last_vcn"] = last_vcn
            attributes.append(inventory)

            if atype == 0x80:
                runs, run_warning = decode_runs(rec, attr_off + runs_offset)
                if run_warning:
                    warnings.append(run_warning)
                data_attrs.append(
                    {
                        "name": aname,
                        "non_resident": True,
                        "size": a_real,
                        "allocated_size": a_alloc,
                        "initialized_size": a_init,
                        "compression_unit": compression_unit,
                        "run_count": len(runs),
                        "first_lcn": runs[0]["lcn"] if runs else None,
                        "fragmented": len(runs) > 1,
                    }
                )
            elif atype == 0x20:
                has_attribute_list = True
                warnings.append("attribute_list_non_resident")

        attr_off += alen

    if ext_offsets:
        merge_extension_records(buf, record_size, ext_offsets, file_names, data_attrs, attributes, warnings, stats)
    if has_attribute_list and attribute_list and not (flags & FLAG_EXTENSION):
        merge_attribute_list_fragments(
            buf, record_size, index, attribute_list, file_names, data_attrs, attributes, warnings, stats, skip=ext_offsets
        )

    primary_fn = select_primary_fn(file_names)
    primary_name = primary_fn["name"] if primary_fn else None
    if flags & FLAG_DIRECTORY:
        size = 0
    elif data_attrs:
        size = data_attrs[0]["size"]
    elif primary_fn is not None:
        size = primary_fn["real_size"]
    else:
        size = 0

    timestomp_flags = compute_timestomp_flags(standard_information, primary_fn)
    frn = (seq << 48) | index

    record = {
        "tool": "mft_parse",
        "schema_version": SCHEMA_VERSION,
        "artifact": "mft",
        "record_number": index,
        "record_offset": off,
        "in_use": bool(flags & FLAG_IN_USE),
        "is_directory": bool(flags & FLAG_DIRECTORY),
        "is_extension": bool(flags & FLAG_EXTENSION),
        "has_special_index": bool(flags & FLAG_SPECIAL_INDEX),
        "flags": flags,
        "sequence_number": seq,
        "hard_link_count": links,
        "file_reference": "0x%016x" % frn,
        "lsn": lsn,
        "used_size": used,
        "allocated_record_size": record_size,
        "base_record_reference": ("0x%016x" % base_ref) if base_ref else None,
        "next_attribute_id": next_attr_id,
        "has_attribute_list": has_attribute_list,
        "attribute_list": attribute_list,
        "attributes": attributes,
        "primary_name": primary_name,
        "size": size,
        "file_names": file_names,
        "timestomp_flags": timestomp_flags,
        "warnings": warnings,
    }
    if standard_information is not None:
        record["standard_information"] = standard_information
    if data_attrs:
        record["data"] = data_attrs
    if include_raw:
        record["raw_hex"] = raw.hex()
    return record


def iter_records(buf, record_size, stats, include_raw=False):
    n = len(buf)
    if record_size is None:
        return
    off = 0
    ext_index = build_extension_index(buf, record_size)
    stats.linked_extension_records = sum(len(v) for v in ext_index.values())
    while off + record_size <= n:
        stats.slots += 1
        if buf[off : off + 4] == FILE_MAGIC:
            key_seq = struct.unpack_from("<H", buf, off + 0x10)[0]
            key_flags = struct.unpack_from("<H", buf, off + 0x16)[0]
            if not key_flags & FLAG_IN_USE:
                key_seq -= 1
            ext_offsets = ext_index.get((off // record_size, key_seq), ())
        else:
            ext_offsets = ()
        try:
            record = parse_record(
                buf,
                off,
                record_size,
                off // record_size,
                stats,
                include_raw,
                ext_offsets,
            )
        except Exception:
            stats.parse_errors += 1
            record = None
        if record is not None:
            stats.count_record(record)
            yield record
        off += record_size
    tail = n - off
    if tail:
        add_skip(stats, off, tail, "truncated_tail")


def record_matches(record, in_use=None, deleted=None, name_contains=None, min_size=None):
    if in_use and not record["in_use"]:
        return False
    if deleted and record["in_use"]:
        return False
    if name_contains is not None:
        name = record["primary_name"]
        if name is None or name_contains.lower() not in name.lower():
            return False
    if min_size is not None:
        size = record["size"]
        if size is None or size < min_size:
            return False
    return True


def build_report(stats, *, input_path=None, input_size=0, record_size=None, record_size_detection=None, filters=None):
    warnings = set(stats.warnings)
    if input_size == 0:
        warnings.add("empty_input")
    elif stats.parsed == 0:
        warnings.add("no_valid_records")
    if any(r["reason"] == "truncated_tail" for r in stats.skipped_regions):
        warnings.add("truncated_tail_present")
    if stats.zero_slots:
        warnings.add("zero_slots_present")
    if stats.no_magic_slots:
        warnings.add("no_magic_slots_present")
    if stats.usa_mismatches:
        warnings.add("usa_mismatch_records_present")
    if stats.parse_errors:
        warnings.add("record_parse_errors_present")

    return {
        "tool": "mft_parse",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": "offline",
        "input": {"path": input_path, "size_bytes": input_size},
        "record_size": record_size,
        "record_size_detection": record_size_detection,
        "counts": {
            "slots": stats.slots,
            "parsed": stats.parsed,
            "in_use": stats.in_use,
            "deleted": stats.deleted,
            "directories": stats.directories,
            "extension_flag_records": stats.extensions,
            "extension_records_linked": stats.linked_extension_records,
            "extension_attributes_merged": stats.extension_attributes,
            "stale_attribute_list_entries": stats.stale_attribute_list_entries,
            "emitted": stats.emitted,
            "zero_slots": stats.zero_slots,
            "no_magic_slots": stats.no_magic_slots,
            "parse_errors": stats.parse_errors,
        },
        "timestomp": {
            "records_with_flags": stats.timestomp_records,
            "by_flag": dict(stats.timestomp.most_common()),
            "note": "observations only, not verdicts — interpretation and false-positive sources: references/mft.md section 10",
        },
        "skipped_regions": stats.skipped_regions,
        "filters": filters or {},
        "warnings": sorted(warnings),
    }


def _open_jsonl(path):
    if path == "-":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(newline="\n")
        return sys.stdout, False
    return open(path, "w", encoding="utf-8", newline="\n"), True


def _emit_records(records, args, stats):
    fh, should_close = _open_jsonl(args.jsonl)
    try:
        for record in records:
            if not record_matches(
                record,
                in_use=args.in_use,
                deleted=args.deleted,
                name_contains=args.name_contains,
                min_size=args.min_size,
            ):
                continue
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            stats.emitted += 1
            if args.limit is not None and stats.emitted >= args.limit:
                stats.warnings.add("stopped_early_by_limit")
                break
    finally:
        if should_close:
            fh.close()


def _print_summary(report, quiet):
    if quiet:
        return
    counts = report["counts"]
    sys.stderr.write(
        f"[mft_parse] record_size={report['record_size']} slots={counts['slots']} "
        f"parsed={counts['parsed']} in_use={counts['in_use']} deleted={counts['deleted']} "
        f"emitted={counts['emitted']}\n"
    )
    ts = report["timestomp"]
    sys.stderr.write(
        f"[mft_parse] timestomp_candidates={ts['records_with_flags']} by_flag={ts['by_flag']}\n"
    )
    warn = report["warnings"]
    sys.stderr.write(f"[mft_parse] warnings: {', '.join(warn) if warn else 'none'}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="mft_parse.py",
        description="Honest parser for NTFS $MFT records. Structure knowledge: references/mft.md",
    )
    ap.add_argument("input", help="raw $MFT capture file")
    ap.add_argument("--record-size", type=int, default=None, help="FILE record size in bytes (default: auto-detect)")
    ap.add_argument("--in-use", action="store_true", help="only records with the in-use flag set")
    ap.add_argument("--deleted", action="store_true", help="only deleted records (in-use flag clear)")
    ap.add_argument("--name-contains", default=None, help="only records whose primary name contains this substring (case-insensitive)")
    ap.add_argument("--min-size", type=int, default=None, help="only records with primary $FN real size >= N bytes")
    ap.add_argument("--jsonl", default="-", help="JSONL output path ('-' = stdout, default)")
    ap.add_argument("--report", default=None, help="write machine-readable JSON report to this path")
    ap.add_argument("--raw", action="store_true", help="include raw record bytes as hex (raw_hex, as read before fixup)")
    ap.add_argument("--limit", type=int, default=None, help="stop after N emitted records")
    ap.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    args = ap.parse_args(argv)

    if args.in_use and args.deleted:
        ap.error("--in-use and --deleted are mutually exclusive")
    if args.record_size is not None and args.record_size <= 0:
        ap.error("--record-size must be positive")

    try:
        with open(args.input, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        sys.stderr.write(f"[mft_parse] fatal: cannot read {args.input}: {exc}\n")
        return 1

    stats = Stats()
    input_size = len(data)
    detection = None
    record_size = args.record_size

    if record_size is None and data:
        record_size, detection = detect_record_size(data)
        if record_size is None:
            sys.stderr.write(
                "[mft_parse] fatal: cannot detect the FILE record size (no reliable 'FILE' magic grid); "
                "pass --record-size explicitly\n"
            )
            return 1
        stats.warnings.add("record_size_auto_detected")

    filters = {
        "in_use": args.in_use,
        "deleted": args.deleted,
        "name_contains": args.name_contains,
        "min_size": args.min_size,
        "limit": args.limit,
        "record_size": record_size,
    }

    records = iter_records(data, record_size, stats, include_raw=args.raw)
    _emit_records(records, args, stats)

    report = build_report(
        stats,
        input_path=args.input,
        input_size=input_size,
        record_size=record_size,
        record_size_detection=detection,
        filters=filters,
    )
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
        except OSError as exc:
            sys.stderr.write(f"[mft_parse] fatal: cannot write report: {exc}\n")
            return 1
    _print_summary(report, args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
