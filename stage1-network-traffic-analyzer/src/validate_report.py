#!/usr/bin/env python3
"""Validate a Stage 1 traffic report against the INTEGRATION.md §6 schema.

The Stage 7 SIEM must never ingest an unvalidated report: this script is the
ingestion gate. It checks structure and types only — never payload content
(the analyzer is metadata-only by design).

Usage:
    python3 validate_report.py report.json [more.json ...]
    python3 validate_report.py - < report.json          # stdin
    python3 validate_report.py --json-only report.json  # machine verdict line

Accepts schema "traffic-report/1.0" and "traffic-report/1.1" (additive rule:
1.0 reports stay valid; a 1.1 report must carry the correlation metadata).
Exit codes: 0 = all valid, 1 = at least one invalid, 2 = usage/IO error.

Standard library only, so it can run anywhere the analyzer runs.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Any

# Fields every report must carry (traffic-report/1.0 — never removed).
REQUIRED_V1 = (
    "schema_version", "generated_at", "packets", "bytes", "malformed_packets",
    "protocols", "top_sources", "top_destinations", "top_flows", "tcp_flags",
    "detections",
)
# Additive correlation metadata (traffic-report/1.1, INTEGRATION.md §6).
REQUIRED_V11 = REQUIRED_V1 + ("report_id", "sensor", "capture_start", "capture_end")

KNOWN_SCHEMA_VERSIONS = ("traffic-report/1.0", "traffic-report/1.1")

# report_id is generated as sb-tr-<UTCstamp>-<8 hex chars> (stable, sortable,
# collision-safe at lab scale).
REPORT_ID_RE = re.compile(r"^sb-tr-\d{8}T\d{6}Z-[0-9a-f]{8}$")

# Structured flows only — a flat "a -> b" string is a parsing-hostile
# regression the contract explicitly forbids (§6).
FLOW_KEYS = ("proto", "src", "src_port", "dst", "dst_port", "count")


def _is_iso8601_with_offset(value: str) -> bool:
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    # The time convention (INTEGRATION.md §4) requires an explicit offset;
    # a trailing Z or +HH:MM / -HH:MM both qualify.
    return bool(re.search(r"(?:Z|[+-]\d{2}:\d{2})$", value))


def _is_nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_ranked(report: dict[str, Any], key: str, problems: list[str]) -> None:
    entries = report.get(key)
    if not isinstance(entries, list):
        problems.append(f"{key} must be a list")
        return
    for entry in entries:
        if not isinstance(entry, dict) or "value" not in entry or "count" not in entry:
            problems.append(f"{key} entries must be objects with 'value' and 'count'")
            return
        if not _is_nonneg_int(entry["count"]):
            problems.append(f"{key} entry count must be a non-negative integer")
            return


def _validate_flows(report: dict[str, Any], problems: list[str]) -> None:
    flows = report.get("top_flows")
    if not isinstance(flows, list):
        problems.append("top_flows must be a list")
        return
    for flow in flows:
        if not isinstance(flow, dict):
            problems.append("top_flows entries must be structured objects, never flat strings")
            return
        missing = [k for k in FLOW_KEYS if k not in flow]
        if missing:
            problems.append(f"top_flows entry missing keys: {', '.join(missing)}")
            return
        if not _is_nonneg_int(flow["count"]):
            problems.append("top_flows entry count must be a non-negative integer")
            return
        if any(isinstance(v, str) and "->" in v for v in flow.values()):
            problems.append("top_flows entries must not embed '->' strings (structured, not flat)")
            return


def _validate_window(report: dict[str, Any], problems: list[str]) -> None:
    start, end = report.get("capture_start"), report.get("capture_end")
    for name, value in (("capture_start", start), ("capture_end", end)):
        if value is not None and (not isinstance(value, str) or not _is_iso8601_with_offset(value)):
            problems.append(f"{name} must be null or an ISO-8601 UTC timestamp with offset")
    if isinstance(start, str) and isinstance(end, str) and start > end:
        problems.append("capture_start must not be after capture_end")


def validate_report(report: Any) -> list[str]:
    """Return a list of problems (empty list = valid). Never raises."""
    problems: list[str] = []
    if not isinstance(report, dict):
        return ["report must be a JSON object"]

    version = report.get("schema_version")
    if version not in KNOWN_SCHEMA_VERSIONS:
        problems.append(f"schema_version must be one of {', '.join(KNOWN_SCHEMA_VERSIONS)}")
        return problems

    required = REQUIRED_V11 if version == "traffic-report/1.1" else REQUIRED_V1
    missing = [k for k in required if k not in report]
    if missing:
        problems.append(f"missing required fields: {', '.join(missing)}")
        return problems

    if not _is_iso8601_with_offset(report["generated_at"]):
        problems.append("generated_at must be an ISO-8601 UTC timestamp with offset")
    for key in ("packets", "bytes", "malformed_packets"):
        if not _is_nonneg_int(report[key]):
            problems.append(f"{key} must be a non-negative integer")
    if not isinstance(report["protocols"], dict) or not all(
        isinstance(v, int) for v in report["protocols"].values()
    ):
        problems.append("protocols must be an object of protocol -> integer count")
    if not isinstance(report["tcp_flags"], dict) or not all(
        isinstance(v, int) for v in report["tcp_flags"].values()
    ):
        problems.append("tcp_flags must be an object of flag-string -> integer count")
    if not isinstance(report["detections"], list):
        problems.append("detections must be a list")
    else:
        for finding in report["detections"]:
            if not isinstance(finding, dict) or "type" not in finding or "severity" not in finding:
                problems.append("detections entries need at least 'type' and 'severity'")
                break

    _validate_ranked(report, "top_sources", problems)
    _validate_ranked(report, "top_destinations", problems)
    _validate_flows(report, problems)

    if version == "traffic-report/1.1":
        report_id = report.get("report_id")
        if not isinstance(report_id, str) or not REPORT_ID_RE.match(report_id):
            problems.append("report_id must match sb-tr-<UTCstamp>-<8hex> (e.g. sb-tr-20260914T120000Z-1a2b3c4d)")
        if not isinstance(report.get("sensor"), str) or not report.get("sensor"):
            problems.append("sensor must be a non-empty string")
        _validate_window(report, problems)

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Stage 1 traffic report JSON (INTEGRATION.md §6).")
    parser.add_argument("reports", nargs="+", help="report file(s), or '-' for stdin")
    parser.add_argument("--json-only", action="store_true",
                        help="machine output: one JSON verdict object per report on stdout")
    args = parser.parse_args(argv)

    exit_code = 0
    for path in args.reports:
        if path == "-":
            name, raw = "<stdin>", sys.stdin.read()
        else:
            try:
                name, raw = path, open(path, encoding="utf-8").read()
            except OSError as error:
                print(f"INVALID {path}: cannot read ({error})", file=sys.stderr)
                exit_code = 2
                continue
        try:
            report = json.loads(raw)
        except json.JSONDecodeError as error:
            problems = [f"invalid JSON: {error}"]
        else:
            problems = validate_report(report)

        if args.json_only:
            print(json.dumps({"report": name, "valid": not problems, "problems": problems}))
        else:
            status = "VALID" if not problems else "INVALID"
            print(f"[{status}] {name}")
            for problem in problems:
                print(f"  - {problem}")
        if problems and exit_code == 0:
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
