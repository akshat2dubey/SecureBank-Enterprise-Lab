#!/usr/bin/env python3
"""Passive network traffic analyzer built with Scapy.

Use only on networks, hosts, and packet-capture files that you are authorized
to inspect. This program captures metadata for visibility; it does not send,
modify, replay, or store packet payloads.

Scope boundary (intentional, not a defect): this is a lab-scale user-space
packet analyzer. It is not designed for production-grade capture throughput
and does not replace dedicated monitoring platforms such as Zeek or Suricata.
It is meant to teach traffic analysis and to feed the SecureBank lab's
reporting/telemetry pipeline (see INTEGRATION.md in the repo root).
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any

try:
    from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, Packet, sniff, rdpcap
except ImportError as error:
    # Keep --help usable and give a clear setup action when Scapy is absent.
    SCAPY_IMPORT_ERROR: ImportError | None = error
else:
    SCAPY_IMPORT_ERROR = None

from detections import DetectionConfig, FlowKey, run_detections

# Bound memory for long captures: past this many unique values, new keys are
# skipped instead of stored, keeping space O(MAX_UNIQUE) regardless of runtime.
MAX_UNIQUE = 100_000

# Schema version of the JSON report (see INTEGRATION.md section 6). Bump this
# whenever a report field changes meaning — SIEM/IR consumers key on it.
SCHEMA_VERSION = "traffic-report/1.0"


def _ip_endpoints(packet: Packet) -> tuple[str, str]:
    """Return IP endpoints, preferring IPv4; empty strings if neither is present."""
    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    return (ip.src, ip.dst) if ip is not None else ("", "")


def dissect(packet: Packet) -> tuple[str, str, str, str | None, str | None, str | None]:
    """Dissect a packet once, returning protocol, endpoints, ports, and TCP flags.

    A single pass here replaces three separate per-packet scans, since every
    layer check walks the packet's layer list.
    """
    tcp = packet.getlayer(TCP)
    if tcp is not None:
        src, dst = _ip_endpoints(packet)
        return "TCP", src, dst, str(tcp.sport), str(tcp.dport), str(tcp.flags)
    udp = packet.getlayer(UDP)
    if udp is not None:
        src, dst = _ip_endpoints(packet)
        return "UDP", src, dst, str(udp.sport), str(udp.dport), None
    icmp = packet.getlayer(ICMP)
    if icmp is not None:
        src, dst = _ip_endpoints(packet)
        return "ICMP", src, dst, None, None, None
    arp = packet.getlayer(ARP)
    if arp is not None:
        return "ARP", arp.psrc, arp.pdst, None, None, None
    ip = packet.getlayer(IP)
    if ip is not None:
        return "IPv4-other", ip.src, ip.dst, None, None, None
    ipv6 = packet.getlayer(IPv6)
    if ipv6 is not None:
        return "IPv6-other", ipv6.src, ipv6.dst, None, None, None
    return "Other", "", "", None, None, None


@dataclass(slots=True)
class TrafficAnalyzer:
    packet_count: int = 0
    byte_count: int = 0
    malformed_packets: int = 0
    protocol_counts: Counter[str] = field(default_factory=Counter)
    source_counts: Counter[str] = field(default_factory=Counter)
    destination_counts: Counter[str] = field(default_factory=Counter)
    flow_counts: Counter[FlowKey] = field(default_factory=Counter)
    tcp_flag_counts: Counter[str] = field(default_factory=Counter)
    detection_config: DetectionConfig = field(default_factory=DetectionConfig)

    @staticmethod
    def _bump(counter: Counter[str], key: str) -> None:
        """Increment key in O(1) time without letting the counter grow unbounded."""
        if key in counter or len(counter) < MAX_UNIQUE:
            counter[key] += 1

    def process(self, packet: Packet, show_packets: bool = False) -> None:
        """Record packet metadata in O(1) time. Payloads are intentionally ignored.

        A malformed/truncated/unexpected packet is counted in
        `malformed_packets` and skipped — it must never crash the run.
        """
        try:
            protocol, src, dst, sport, dport, flags = dissect(packet)
        except Exception:
            self.malformed_packets += 1
            return
        self.packet_count += 1
        self.byte_count += len(packet)
        self.protocol_counts[protocol] += 1
        if src:
            self._bump(self.source_counts, src)
            self._bump(self.destination_counts, dst)
            flow: FlowKey = (protocol, src, sport, dst, dport)
            if flow in self.flow_counts or len(self.flow_counts) < MAX_UNIQUE:
                self.flow_counts[flow] += 1
        if flags is not None:
            self._bump(self.tcp_flag_counts, flags)
        if show_packets:
            try:
                print(packet.summary())
            except Exception:
                # A packet can be malformed in ways that break summary() too.
                self.malformed_packets += 1

    @staticmethod
    def top(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
        # most_common uses heapq: O(n log limit), cheaper than a full sort.
        return [{"value": item, "count": count} for item, count in counter.most_common(limit)]

    def report(self, top_n: int) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "packets": self.packet_count,
            "bytes": self.byte_count,
            "malformed_packets": self.malformed_packets,
            "protocols": dict(self.protocol_counts.most_common()),
            "top_sources": self.top(self.source_counts, top_n),
            "top_destinations": self.top(self.destination_counts, top_n),
            "top_flows": [
                {
                    "proto": proto,
                    "src": src,
                    "src_port": src_port,
                    "dst": dst,
                    "dst_port": dst_port,
                    "count": count,
                }
                for (proto, src, src_port, dst, dst_port), count in self.flow_counts.most_common(top_n)
            ],
            "tcp_flags": dict(self.tcp_flag_counts.most_common()),
            "detections": run_detections(
                self.flow_counts, self.tcp_flag_counts, self.detection_config
            ),
        }


def display_report(report: dict[str, Any]) -> None:
    print("\n=== Traffic summary ===")
    print(f"Packets: {report['packets']:,}")
    print(f"Bytes:   {report['bytes']:,}")
    if report.get("malformed_packets"):
        print(f"Malformed/skipped: {report['malformed_packets']:,}")

    for title, key in (
        ("Protocols", "protocols"),
        ("Top source addresses", "top_sources"),
        ("Top destination addresses", "top_destinations"),
        ("Top flows", "top_flows"),
        ("TCP flags", "tcp_flags"),
    ):
        entries = report[key]
        if not entries:
            continue
        print(f"\n{title}:")
        if isinstance(entries, dict):
            rows = ((value, count) for value, count in entries.items())
        else:
            def _flow_label(entry: dict[str, Any]) -> str:
                if "proto" in entry:  # structured flow record (traffic-report/1.0)
                    src = entry.get("src", "")
                    dst = entry.get("dst", "")
                    src_port = entry.get("src_port")
                    dst_port = entry.get("dst_port")
                    if src_port is not None or dst_port is not None:
                        return f"{entry['proto']} {src}:{src_port} -> {dst}:{dst_port}"
                    return f"{entry['proto']} {src} -> {dst}"
                return entry.get("value", str(entry))

            rows = ((_flow_label(entry), entry["count"]) for entry in entries)
        for value, count in rows:
            print(f"  {value:<45} {count:>8}")

    detections = report.get("detections") or []
    if detections:
        print("\n=== Detections (heuristic indicators) ===")
        for finding in detections:
            evidence = ", ".join(f"{k}={v}" for k, v in finding.get("evidence", {}).items())
            print(
                f"  [{finding.get('severity', '?').upper():<6}] "
                f"{finding.get('type')}"
                f"{' (source ' + finding.get('source', '') + ')' if finding.get('source') else ''}"
                f" — {finding.get('detail', '')}"
                + (f" [{evidence}]" if evidence else "")
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Passively summarize authorized live or PCAP network traffic."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", help="Interface to monitor live (for example: Ethernet)")
    source.add_argument("--read-pcap", type=Path, help="Analyze an existing PCAP file offline")
    parser.add_argument("--bpf", help="Optional BPF filter for live capture (for example: 'tcp port 443')")
    parser.add_argument("--count", type=int, default=0, help="Stop after this many packets (0 = until timeout/Ctrl+C)")
    parser.add_argument("--timeout", type=float, help="Live-capture duration in seconds")
    parser.add_argument("--top", type=int, default=10, help="Number of rows to show per ranking")
    parser.add_argument("--show-packets", action="store_true", help="Print Scapy one-line packet summaries")
    parser.add_argument("--json-out", type=Path, help="Write metadata-only report as JSON")
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Machine output for SIEM/cron: no human summary; JSON goes to --json-out or stdout (stdout stays clean)",
    )
    detect = parser.add_argument_group("detection thresholds (heuristic indicators)")
    detect.add_argument("--syn-flood-min", type=int, default=None,
                        help="Minimum pure-SYN packets to flag a possible SYN flood")
    detect.add_argument("--port-scan-min-ports", type=int, default=None,
                        help="Minimum distinct destination ports from one source to flag a possible scan")
    detect.add_argument("--telnet-ports", type=str, default=None,
                        help="Comma-separated plaintext legacy ports to flag (default: 23)")
    args = parser.parse_args()
    if args.count < 0 or args.top < 1 or (args.timeout is not None and args.timeout <= 0):
        parser.error("--count must be >= 0, --top must be >= 1, and --timeout must be > 0")
    if args.bpf and args.read_pcap:
        parser.error("--bpf is for live capture only; filter the PCAP before analysis if required")
    if args.syn_flood_min is not None and args.syn_flood_min < 0:
        parser.error("--syn-flood-min must be >= 0")
    if args.port_scan_min_ports is not None and args.port_scan_min_ports < 1:
        parser.error("--port-scan-min-ports must be >= 1")
    if args.json_only and args.show_packets:
        parser.error("--json-only cannot be combined with --show-packets (interactive output would pollute machine output)")
    return args


def main() -> int:
    args = parse_args()
    if SCAPY_IMPORT_ERROR is not None:
        print(
            "Error: Scapy is not installed. Install it with: python -m pip install scapy",
            file=sys.stderr,
        )
        return 2

    # Assemble the detection config from CLI overrides (defaults otherwise).
    kwargs: dict[str, Any] = {}
    if args.syn_flood_min is not None:
        kwargs["syn_flood_min_syn"] = args.syn_flood_min
    if args.port_scan_min_ports is not None:
        kwargs["port_scan_min_ports"] = args.port_scan_min_ports
    if args.telnet_ports:
        kwargs["telnet_ports"] = tuple(int(p) for p in args.telnet_ports.split(","))
    config = DetectionConfig(**kwargs)

    analyzer = TrafficAnalyzer(detection_config=config)
    process = partial(analyzer.process, show_packets=args.show_packets)
    try:
        if args.read_pcap:
            if not args.read_pcap.is_file():
                raise FileNotFoundError(f"PCAP file not found: {args.read_pcap}")
            for packet in rdpcap(str(args.read_pcap), count=args.count or -1):
                process(packet)
        else:
            # In --json-only mode, stdout must stay machine-clean: status goes
            # to stderr so a pipe (cron -> SIEM) never sees prose.
            if args.json_only:
                print("Capturing passively (json-only; status on stderr). Ctrl+C to stop.", file=sys.stderr)
            else:
                print("Capturing passively. Press Ctrl+C to stop.")
            sniff(
                iface=args.interface,
                filter=args.bpf,
                prn=process,
                store=False,
                count=args.count,
                timeout=args.timeout,
            )
    except KeyboardInterrupt:
        if args.json_only:
            print("Capture stopped by user.", file=sys.stderr)
        else:
            print("\nCapture stopped by user.")
    except PermissionError:
        # Subclass of OSError — must be caught BEFORE the broader handler or
        # this friendly message is dead code.
        print("Error: packet capture requires elevated capture permissions.", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    report = analyzer.report(args.top)
    if args.json_only:
        payload = json.dumps(report, indent=2)
        if args.json_out:
            try:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(payload + "\n", encoding="utf-8")
            except OSError as error:
                print(f"Error: could not write {args.json_out}: {error}", file=sys.stderr)
                return 2
            print(f"Metadata report saved to {args.json_out}", file=sys.stderr)
        else:
            print(payload)
        return 0

    display_report(report)
    if args.json_out:
        try:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        except OSError as error:
            print(f"Error: could not write {args.json_out}: {error}", file=sys.stderr)
            return 2
        print(f"\nMetadata report saved to {args.json_out}")
    return 0


if __name__ == "__main__":
    # Restore the default SIGINT handler so Ctrl+C interrupts a live sniff promptly.
    signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
