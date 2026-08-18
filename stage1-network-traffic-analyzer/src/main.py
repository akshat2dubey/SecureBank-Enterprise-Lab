#!/usr/bin/env python3
"""Thin entry point for the SecureBank Stage 1 network traffic analyzer.

The implementation lives in Project/outputs/network_traffic_analyzer.py
(kept there as the project's documented deliverable); this launcher makes
`python src/main.py ...` work with the same options. Both entry points are
equivalent:

    python src/main.py --read-pcap incident.pcap --json-out report.json
    python Project/outputs/network_traffic_analyzer.py --read-pcap incident.pcap --json-out report.json
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "Project" / "outputs"))

from network_traffic_analyzer import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
