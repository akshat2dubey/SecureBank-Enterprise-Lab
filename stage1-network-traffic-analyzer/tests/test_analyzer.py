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
from detections import DetectionConfig  # noqa: E402
from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, IPv6, TCP, UDP, wrpcap  # noqa: E402

REQUIRED_REPORT_KEYS = {
    "schema_version",
    "generated_at",
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
    assert report["schema_version"] == "traffic-report/1.0"
    assert report["packets"] == 0
    assert report["bytes"] == 0
    assert report["malformed_packets"] == 0
    assert report["detections"] == []
    assert "Z" not in report["generated_at"].replace("+00:00", "Z")  # ISO-8601 with offset


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
