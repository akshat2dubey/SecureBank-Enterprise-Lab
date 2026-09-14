"""Tests for the SecureBank Stage 1 network traffic analyzer.

Run from the stage1-network-traffic-analyzer directory:

    python -m pip install scapy pytest
    python -m pytest tests/ -q

Coverage: empty capture, PCAP replay, malformed/truncated packets, IPv4/IPv6,
TCP/UDP/DNS/ICMP/ARP classification, BPF argument validation, the detection
rules, and JSON report schema validity (INTEGRATION.md section 6).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make the analyzer (and its detections module) importable from Project/outputs.
OUTPUTS = Path(__file__).resolve().parent.parent / "Project" / "outputs"
sys.path.insert(0, str(OUTPUTS))

import network_traffic_analyzer as nta  # noqa: E402
import validate_report as vr  # noqa: E402
from detections import DetectionConfig  # noqa: E402
from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, IPv6, TCP, UDP, wrpcap  # noqa: E402

REQUIRED_REPORT_KEYS = {
    "schema_version",
    "generated_at",
    "report_id",          # additive since traffic-report/1.1
    "sensor",             # additive since traffic-report/1.1
    "capture_start",      # additive since traffic-report/1.1
    "capture_end",        # additive since traffic-report/1.1
    "packets",
    "bytes",
    "malformed_packets",
    "protocols",
    "top_sources",
    "top_destinations",
    "top_flows",
    "tcp_flags",
    "detections",
}


def pkt_tcp(src="10.10.10.20", sport=50000, dst="10.10.10.10", dport=22, flags="S"):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)


def pkt_udp(src="10.10.10.20", sport=50000, dst="10.10.10.10", dport=53):
    return Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)


def pkt_http(src="10.10.10.20", sport=50001, dst="10.10.10.10", dport=80):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")


def pkt_icmp(src="10.10.10.20", dst="10.10.10.10"):
    return Ether() / IP(src=src, dst=dst) / ICMP()


def pkt_dns(src="10.10.10.20", dst="10.10.10.10"):
    return Ether() / IP(src=src, dst=dst) / UDP(sport=5353, dport=53) / DNS(qd=DNSQR(qname="securebank.lab"))


def run_main(monkeypatch, argv):
    """Run main() with a synthetic argv; returns (exit_code, json_dict|None)."""
    monkeypatch.setattr(sys, "argv", ["network_traffic_analyzer.py", *argv])
    code = nta.main()
    report = None
    json_path = None
    for i, arg in enumerate(argv):
        if arg == "--json-out" and i + 1 < len(argv):
            json_path = Path(argv[i + 1])
    if json_path is not None and json_path.exists():
        report = json.loads(json_path.read_text(encoding="utf-8"))
    return code, report


# --- Report schema ------------------------------------------------------------

def test_empty_capture_report_schema():
    report = nta.TrafficAnalyzer().report(top_n=10)
    assert set(report) >= REQUIRED_REPORT_KEYS
    assert report["schema_version"] == "traffic-report/1.1"
    assert report["packets"] == 0
    assert report["bytes"] == 0
    assert report["malformed_packets"] == 0
    assert report["detections"] == []
    # ISO-8601 with an explicit offset (INTEGRATION.md §4 canonical +00:00 form).
    # (The old `"Z" not in ts.replace("+00:00", "Z")` could never pass — it
    # manufactured the very "Z" it forbade.)
    assert report["generated_at"].endswith("+00:00")


def test_empty_capture_reports_null_window():
    # No packet was seen -> the capture window is null, not a fabricated
    # start==end pair around report time.
    report = nta.TrafficAnalyzer().report(top_n=10)
    assert report["capture_start"] is None
    assert report["capture_end"] is None


def test_capture_window_reflects_packet_timestamps():
    # PCAP replay must report the ORIGINAL capture window, not the replay
    # wall-clock (Stage 7 correlates capture windows against SIEM timelines).
    from scapy.all import PcapWriter
    analyzer = nta.TrafficAnalyzer()
    p1, p2 = pkt_tcp(), pkt_tcp()
    p1.time = 1_700_000_000.0
    p2.time = 1_700_000_100.0
    analyzer.process(p1)
    analyzer.process(p2)
    report = analyzer.report(top_n=5)
    assert report["capture_start"].startswith("2023-11-14T22:13:20")
    assert report["capture_end"].startswith("2023-11-14T22:15:00")
    assert report["capture_start"] < report["capture_end"]


def test_sensor_default_is_hostname_and_cli_override():
    import socket
    report = nta.TrafficAnalyzer().report(top_n=5)
    assert report["sensor"] == socket.gethostname()
    custom = nta.TrafficAnalyzer(sensor="analyzer-lab-01").report(top_n=5)
    assert custom["sensor"] == "analyzer-lab-01"


def test_report_id_is_stable_format_and_unique():
    r1 = nta.TrafficAnalyzer().report(top_n=5)
    r2 = nta.TrafficAnalyzer().report(top_n=5)
    assert vr.REPORT_ID_RE.match(r1["report_id"]), r1["report_id"]
    assert r1["report_id"] != r2["report_id"]


def test_json_report_is_serializable_and_valid(tmp_path):
    out = tmp_path / "report.json"
    analyzer = nta.TrafficAnalyzer()
    for _ in range(3):
        analyzer.process(pkt_tcp())
    report = analyzer.report(top_n=5)
    # Round-trip through JSON exactly like --json-out does.
    payload = json.loads(json.dumps(report))
    assert payload["packets"] == 3
    assert set(payload) >= REQUIRED_REPORT_KEYS
    # Every report the analyzer emits must pass the Stage 7 ingestion gate.
    assert vr.validate_report(payload) == []


# --- Schema validator (Stage 7 ingestion gate, INTEGRATION.md §6) -------------

def _minimal_v10_report():
    return {
        "schema_version": "traffic-report/1.0",
        "generated_at": "2026-08-09T04:56:31.670573+00:00",
        "packets": 0, "bytes": 0, "malformed_packets": 0,
        "protocols": {}, "top_sources": [], "top_destinations": [],
        "top_flows": [], "tcp_flags": {}, "detections": [],
    }

def test_validator_accepts_v10_and_v11():
    v10 = _minimal_v10_report()
    assert vr.validate_report(v10) == []
    v11 = dict(v10, schema_version="traffic-report/1.1")
    missing = vr.validate_report(v11)
    assert any("missing required fields" in p for p in missing)
    v11.update(report_id="sb-tr-20260914T120000Z-1a2b3c4d", sensor="analyzer",
               capture_start="2026-08-09T04:55:00+00:00",
               capture_end="2026-08-09T04:56:31+00:00")
    assert vr.validate_report(v11) == []


def test_validator_rejects_bad_fields():
    base = dict(_minimal_v10_report())
    bad_cases = [
        ("schema_version", "traffic-report/9.9"),
        ("generated_at", "2026-08-09T04:56:31"),          # no offset
        ("packets", -1),
        ("packets", "3"),
        ("packets", True),                                # bool is not an int
        ("protocols", {"TCP": "3"}),
        ("detections", "none"),
        ("top_flows", ["10.0.0.1 -> 10.0.0.2"]),          # flat string regression
        ("top_flows", [{"proto": "TCP"}]),                # missing keys
        ("top_sources", [{"value": "x", "count": -2}]),
    ]
    for key, value in bad_cases:
        report = dict(base)
        report[key] = value
        assert vr.validate_report(report), f"expected rejection for {key}={value!r}"


def test_validator_v11_extras():
    report = _minimal_v10_report()
    report.update(schema_version="traffic-report/1.1", sensor="analyzer",
                  report_id="not-a-valid-id",
                  capture_start="2026-08-09T04:56:31+00:00",
                  capture_end="2026-08-09T04:55:00+00:00")
    problems = vr.validate_report(report)
    assert any("report_id" in p for p in problems)
    assert any("capture_start must not be after capture_end" in p for p in problems)


# --- Protocol classification --------------------------------------------------

def test_protocol_classification():
    analyzer = nta.TrafficAnalyzer()
    analyzer.process(pkt_tcp(flags="S"))
    analyzer.process(pkt_udp())
    analyzer.process(pkt_icmp())
    analyzer.process(pkt_dns())
    analyzer.process(Ether() / ARP(psrc="10.10.10.20", pdst="10.10.10.10"))
    analyzer.process(Ether() / IPv6(src="fd00:10:10::20", dst="fd00:10:10::10") / TCP(sport=50000, dport=22, flags="S"))
    report = analyzer.report(top_n=10)
    assert report["protocols"]["TCP"] == 2  # IPv4 + IPv6 TCP both label as TCP
    assert report["protocols"]["UDP"] == 2  # plain UDP + DNS (DNS is UDP)
    assert report["protocols"]["ICMP"] == 1
    assert report["protocols"]["ARP"] == 1


def test_ipv4_and_ipv6_endpoints():
    analyzer = nta.TrafficAnalyzer()
    analyzer.process(pkt_tcp(src="10.10.10.20", dst="10.10.10.10"))
    analyzer.process(Ether() / IPv6(src="fd00:10:10::20", dst="fd00:10:10::10") / UDP(sport=50000, dport=53))
    report = analyzer.report(top_n=5)
    sources = {e["value"] for e in report["top_sources"]}
    assert "10.10.10.20" in sources
    assert "fd00:10:10::20" in sources


def test_flow_structure_is_structured_not_flat():
    analyzer = nta.TrafficAnalyzer()
    analyzer.process(pkt_tcp(src="10.10.10.20", sport=40000, dst="10.10.10.10", dport=22, flags="S"))
    analyzer.process(pkt_tcp(src="10.10.10.20", sport=40000, dst="10.10.10.10", dport=22, flags="SA"))
    report = analyzer.report(top_n=5)
    flow = report["top_flows"][0]
    assert flow["proto"] == "TCP"
    assert flow["src"] == "10.10.10.20"
    assert flow["src_port"] == "40000"
    assert flow["dst"] == "10.10.10.10"
    assert flow["dst_port"] == "22"
    assert flow["count"] == 2
    # SIEM consumers must not have to regex-parse flat strings (INTEGRATION.md §6).
    assert "->" not in json.dumps(flow)


# --- Malformed / truncated packets ---------------------------------------------

def test_malformed_packet_is_counted_and_skipped():
    analyzer = nta.TrafficAnalyzer()
    analyzer.process("not a packet")          # raises inside dissect -> skipped
    analyzer.process(object())                # no getlayer -> skipped
    analyzer.process(pkt_tcp())               # still works afterwards
    report = analyzer.report(top_n=5)
    assert report["malformed_packets"] == 2
    assert report["packets"] == 1
    assert report["protocols"]["TCP"] == 1


def test_malformed_packet_never_crashes_pcap_loop(tmp_path, monkeypatch):
    good = pkt_tcp()
    pcap = tmp_path / "mixed.pcap"
    wrpcap(str(pcap), [good])
    out = tmp_path / "report.json"
    # Feed a raw byte string through the full main() path.
    monkeypatch.setattr(sys, "argv", ["nta", "--read-pcap", str(pcap), "--json-out", str(out)])
    # Prepend a malformed "packet" by monkeypatching the analyzer's rdpcap
    # reference (it was imported into its namespace, not scapy.all's).
    original = nta.rdpcap

    def mixed(path, count=-1):
        return ["garbage", *original(path, count=count)]

    monkeypatch.setattr(nta, "rdpcap", mixed)
    code = nta.main()
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 0
    assert report["malformed_packets"] == 1
    assert report["packets"] == 1


# --- PCAP replay + CLI ---------------------------------------------------------

def test_pcap_replay_via_main(tmp_path, monkeypatch):
    pcap = tmp_path / "capture.pcap"
    packets = [
        pkt_tcp(flags="S"),
        pkt_tcp(flags="SA"),
        pkt_udp(dport=53),
        pkt_icmp(),
    ]
    wrpcap(str(pcap), packets)
    out = tmp_path / "report.json"
    code, report = run_main(monkeypatch, ["--read-pcap", str(pcap), "--json-out", str(out)])
    assert code == 0
    assert report["packets"] == 4
    assert set(report["protocols"]) == {"TCP", "UDP", "ICMP"}


def test_bpf_rejected_with_pcap(monkeypatch, tmp_path):
    pcap = tmp_path / "x.pcap"
    wrpcap(str(pcap), [pkt_tcp()])
    with pytest.raises(SystemExit):
        run_main(monkeypatch, ["--read-pcap", str(pcap), "--bpf", "tcp"])


def test_count_and_top_validation(monkeypatch):
    with pytest.raises(SystemExit):
        run_main(monkeypatch, ["--interface", "eth0", "--count", "-1"])
    with pytest.raises(SystemExit):
        run_main(monkeypatch, ["--interface", "eth0", "--top", "0"])


def test_json_only_emits_machine_json_to_stdout(tmp_path, monkeypatch, capsys):
    pcap = tmp_path / "c.pcap"
    wrpcap(str(pcap), [pkt_tcp(), pkt_udp()])
    code, _ = run_main(monkeypatch, ["--read-pcap", str(pcap), "--json-only"])
    out = capsys.readouterr().out
    assert code == 0
    report = json.loads(out)  # stdout is pure JSON, parseable without filters
    assert report["packets"] == 2
    assert "=== Traffic summary ===" not in out


def test_json_only_with_json_out_keeps_stdout_clean(tmp_path, monkeypatch, capsys):
    pcap = tmp_path / "c.pcap"
    wrpcap(str(pcap), [pkt_tcp()])
    out = tmp_path / "r.json"
    code, report = run_main(monkeypatch, ["--read-pcap", str(pcap), "--json-only", "--json-out", str(out)])
    captured = capsys.readouterr()
    assert code == 0
    assert report["packets"] == 1
    assert captured.out.strip() == ""  # stdout stays machine-clean


def test_json_only_rejects_show_packets(monkeypatch):
    with pytest.raises(SystemExit):
        run_main(monkeypatch, ["--interface", "eth0", "--json-only", "--show-packets"])


# --- Detection rules ------------------------------------------------------------

def test_detection_syn_flood_fires():
    analyzer = nta.TrafficAnalyzer()
    for i in range(150):
        analyzer.process(pkt_tcp(sport=40000 + i, flags="S"))
    for i in range(10):
        analyzer.process(pkt_tcp(sport=40000 + i, flags="SA"))
    report = analyzer.report(top_n=5)
    types = {d["type"] for d in report["detections"]}
    assert "possible_syn_flood" in types
    finding = next(d for d in report["detections"] if d["type"] == "possible_syn_flood")
    assert finding["severity"] == "medium"
    assert finding["evidence"]["syn_packets"] == 150


def test_detection_syn_flood_silent_for_normal_traffic():
    analyzer = nta.TrafficAnalyzer()
    for i in range(10):
        analyzer.process(pkt_tcp(flags="S"))
        analyzer.process(pkt_tcp(flags="SA"))
    report = analyzer.report(top_n=5)
    assert all(d["type"] != "possible_syn_flood" for d in report["detections"])


def test_detection_port_scan_fires():
    analyzer = nta.TrafficAnalyzer()
    for port in range(20):
        analyzer.process(pkt_tcp(dport=10000 + port, flags="S"))
    report = analyzer.report(top_n=5)
    finding = next((d for d in report["detections"] if d["type"] == "possible_port_scan"), None)
    assert finding is not None
    assert finding["source"] == "10.10.10.20"
    assert finding["evidence"]["unique_destination_ports"] >= 15


def test_detection_telnet_service_fires():
    analyzer = nta.TrafficAnalyzer()
    analyzer.process(pkt_tcp(dport=23, flags="S"))
    analyzer.process(pkt_tcp(dport=23, flags="SA"))
    report = analyzer.report(top_n=5)
    finding = next((d for d in report["detections"] if d["type"] == "suspicious_service"), None)
    assert finding is not None
    assert finding["evidence"]["port"] == 23


def test_detection_thresholds_are_configurable():
    analyzer = nta.TrafficAnalyzer(detection_config=DetectionConfig(port_scan_min_ports=5))
    for port in range(8):
        analyzer.process(pkt_tcp(dport=20000 + port, flags="S"))
    report = analyzer.report(top_n=5)
    assert any(d["type"] == "possible_port_scan" for d in report["detections"])
