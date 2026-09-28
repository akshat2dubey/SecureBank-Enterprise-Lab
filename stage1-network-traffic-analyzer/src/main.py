#!/usr/bin/env python3
"""Entry point for the SecureBank Stage 1 network traffic analyzer.

The implementation lives in src/network_traffic_analyzer.py; both invocations
are equivalent:

    python src/main.py --read-pcap incident.pcap --json-out report.json
    python src/network_traffic_analyzer.py --read-pcap incident.pcap --json-out report.json
"""

from __future__ import annotations

from network_traffic_analyzer import main

if __name__ == "__main__":
    raise SystemExit(main())
