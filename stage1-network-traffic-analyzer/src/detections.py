#!/usr/bin/env python3
"""Heuristic detection layer for the SecureBank traffic analyzer.

These are NOT production-grade intrusion-detection rules. Each rule is a
simple, explainable threshold check over the analyzer's aggregate counters,
designed for the lab: it points a human at something worth a second look,
and it can be extended by adding one more function to this module.

Design rules:
  * Rules run at report time over already-collected metadata — O(flows),
    not O(packets) — so detection adds no per-packet cost.
  * Every finding carries a `type`, a `severity`, a `source`/`detail`, and
    an `evidence` dict, so a SIEM (Stage 7) or an incident handler
    (Stage 8) can consume it without parsing prose.
  * Thresholds are plain constants with CLI overrides in the analyzer
    (--syn-flood-min, --port-scan-min-ports, --telnet-ports).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

# --- Default thresholds (documented; overridable from the CLI) ----------------
DEFAULT_SYN_FLOOD_MIN_SYN = 100      # at least this many pure-SYN packets...
DEFAULT_SYN_FLOOD_RATIO = 3.0        # ...and at least 3x more SYNs than SYN-ACKs
DEFAULT_PORT_SCAN_MIN_PORTS = 15     # distinct destination ports from one source
DEFAULT_TELNET_PORTS = (23,)         # unencrypted legacy services to flag


@dataclass(slots=True, frozen=True)
class DetectionConfig:
    syn_flood_min_syn: int = DEFAULT_SYN_FLOOD_MIN_SYN
    syn_flood_ratio: float = DEFAULT_SYN_FLOOD_RATIO
    port_scan_min_ports: int = DEFAULT_PORT_SCAN_MIN_PORTS
    telnet_ports: tuple[int, ...] = DEFAULT_TELNET_PORTS


# A flow key is the 5-tuple (proto, src, src_port, dst, dst_port) that the
# analyzer already counts; None ports mean "no ports for this protocol".
FlowKey = tuple[str, str, str | None, str, str | None]


def detect_syn_flood(
    tcp_flags: Counter[str] | dict[str, int],
    config: DetectionConfig,
) -> dict[str, Any] | None:
    """Flag a burst of SYNs with almost no completed handshakes.

    Heuristic: pure-SYN packets (flag "S") far outnumber SYN-ACK responses
    (flag "SA"). A real connection attempt produces one of each; a flood
    produces many SYNs and few or no SA replies.
    """
    syn = int(tcp_flags.get("S", 0))
    syn_ack = int(tcp_flags.get("SA", 0))
    if syn < config.syn_flood_min_syn:
        return None
    if syn_ack > 0 and syn < config.syn_flood_ratio * syn_ack:
        return None
    return {
        "type": "possible_syn_flood",
        "severity": "medium",
        "detail": "many SYN packets with few completed handshakes",
        "evidence": {
            "syn_packets": syn,
            "syn_ack_packets": syn_ack,
            "threshold_min_syn": config.syn_flood_min_syn,
        },
    }


def detect_port_scan(
    flows: Counter[FlowKey] | dict[FlowKey, int],
    config: DetectionConfig,
) -> dict[str, Any] | None:
    """Flag one source touching many distinct destination ports.

    Heuristic: group flows by source address and count distinct destination
    ports. A single host probing many ports in one capture window is a
    classic scan indicator. Only the worst offender is reported.
    """
    ports_per_src: dict[str, set[str]] = {}
    for (proto, src, _sport, _dst, dport), count in flows.items():
        if proto not in ("TCP", "UDP") or dport is None or count == 0:
            continue
        ports_per_src.setdefault(src, set()).add(dport)
    worst_src = max(ports_per_src, key=lambda s: len(ports_per_src[s]), default=None)
    if worst_src is None:
        return None
    unique_ports = len(ports_per_src[worst_src])
    if unique_ports < config.port_scan_min_ports:
        return None
    return {
        "type": "possible_port_scan",
        "severity": "low",
        "source": worst_src,
        "detail": "one source touched many distinct destination ports",
        "evidence": {
            "unique_destination_ports": unique_ports,
            "threshold_min_ports": config.port_scan_min_ports,
        },
    }


def detect_suspicious_service(
    flows: Counter[FlowKey] | dict[FlowKey, int],
    config: DetectionConfig,
) -> list[dict[str, Any]]:
    """Flag connections to known-unencrypted legacy services (e.g. Telnet).

    Heuristic: any flow whose destination port is in the configured list.
    Presence alone is not proof of abuse — it is an indicator worth
    investigating, because the traffic crosses the wire in plaintext.
    """
    findings: list[dict[str, Any]] = []
    ports_seen: dict[int, int] = {}
    for (proto, _src, _sport, _dst, dport), count in flows.items():
        if dport is None:
            continue
        try:
            port = int(dport)
        except ValueError:
            continue
        if port in config.telnet_ports:
            ports_seen[port] = ports_seen.get(port, 0) + int(count)
    for port, count in sorted(ports_seen.items()):
        findings.append(
            {
                "type": "suspicious_service",
                "severity": "low",
                "detail": f"plaintext legacy service on port {port}",
                "evidence": {"port": port, "packets": count},
            }
        )
    return findings


def run_detections(
    flows: Counter[FlowKey],
    tcp_flags: Counter[str],
    config: DetectionConfig,
) -> list[dict[str, Any]]:
    """Run every rule and return a flat, JSON-ready findings list."""
    findings: list[dict[str, Any]] = []
    syn_flood = detect_syn_flood(tcp_flags, config)
    if syn_flood is not None:
        findings.append(syn_flood)
    port_scan = detect_port_scan(flows, config)
    if port_scan is not None:
        findings.append(port_scan)
    findings.extend(detect_suspicious_service(flows, config))
    return findings
