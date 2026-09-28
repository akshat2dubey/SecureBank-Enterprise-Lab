# How to Explain the Network Traffic Analyzer

This is a passive traffic **summarizer**. Think of it as a security guard at a
building entrance who counts visitors, notes where they came from and where
they are going, and watches for patterns. It does not open their bags (packet
payloads), alter their route, or send traffic of its own.

> **Version note:** the line-by-line walkthrough below documents the original
> 213-line version of `network_traffic_analyzer.py`. The analyzer has since
> evolved (schema-versioned reports, malformed-packet handling, structured
> flows, and the `detections.py` heuristic layer) while keeping the same
> architecture: one dissect pass per packet, counters, report, display. The
> concepts explained here — protocol labeling, endpoint extraction, bounded
> counters, report assembly, safe run loop — all still apply verbatim.

## A 30-second explanation

“The program receives packets from either a live, authorized network interface
or an existing PCAP file. For each packet, it identifies the highest-level
protocol it understands, extracts only addressing and port metadata, and adds
that information to counters. When capture ends, it prints and optionally
writes a JSON summary of the busiest protocols, hosts, flows, and TCP flags.”

## Line-by-line walkthrough

Blank lines (3, 8, 10, 20, and similar lines) do nothing at runtime. They are
there only to separate ideas and make the program easier for people to read.

### Lines 1–27: identity, safety statement, and imports

- **1 — `#!/usr/bin/env python3`:** This is a *shebang*. On macOS/Linux, if the
  file is made executable, the operating system uses it to find Python 3. On
  Windows it is harmless; the Python command you use starts the script.
- **2 — opening triple quotes:** Begins the module docstring: a built-in
  description of what the whole file is for.
- **3:** A blank line inside that description, used like a paragraph break.
- **4:** Begins the authorization reminder. Traffic capture can expose private
  information, so permission is a security and legal requirement.
- **5:** States the design boundary: the tool collects metadata for visibility
  only; it does not actively interfere with traffic.
- **6:** Finishes that boundary by saying payload content is neither replayed
  nor saved. A payload is the actual data being carried, such as page contents.
- **7 — closing triple quotes:** Ends the module docstring.
- **9 — `from __future__ import annotations`:** Makes type hints lazy. Python
  stores hints such as `Packet` as descriptions rather than needing the class to
  exist immediately. That is why `--help` can work even when Scapy is missing.
- **11 — `import argparse`:** Loads Python’s standard command-line parser. It
  turns options such as `--timeout 60` into usable program settings.
- **12 — `import json`:** Loads support for saving the final summary as JSON, a
  common structured text format.
- **13 — `import signal`:** Loads operating-system signal handling. We use it
  to make Ctrl+C stop a live capture cleanly.
- **14 — `import sys`:** Gives access to standard input/output/error. This code
  uses `sys.stderr` for problems, so errors stay distinct from normal results.
- **15 — `from collections import Counter`:** Imports a dictionary-like counter
  that starts missing values at zero and is perfect for “how many times?” data.
- **16 — `from dataclasses import dataclass, field`:** Imports tools that create
  a simple data-holding class without hand-writing its constructor.
- **17 — `from datetime import datetime, timezone`:** Imports time tools so the
  report can identify exactly when it was generated, in UTC.
- **18 — `from pathlib import Path`:** Imports a safer, clearer representation
  for filesystem paths such as a PCAP input or JSON output.
- **19 — `from typing import Any`:** Imports a type-hint escape hatch for
  report values that may be strings, numbers, lists, or dictionaries.
- **21 — `try:`:** Begins an attempt to load the external Scapy package.
- **22:** Imports the Scapy protocol layers (`ARP`, `IP`, `IPv6`, `TCP`, and so
  on), its generic `Packet` type, `sniff` for live capture, and `rdpcap` for
  reading an offline capture file.
- **23 — `except ImportError as error:`:** If Scapy cannot be imported, catch
  that particular failure instead of immediately crashing.
- **24 — comment:** Explains the reason for the graceful fallback: a person can
  still run `--help` and learn the setup step.
- **25:** Saves the import error in a module-level variable. `ImportError | None`
  means “either an import error or no value.”
- **26 — `else:`:** Runs only when the `try` block succeeded.
- **27:** Records that no Scapy import error happened by storing `None`.

### Lines 30–44: label a packet by protocol

- **30 — `def protocol_name(...) -> str:`:** Defines a reusable function that
  accepts one packet and promises to return a text label.
- **31 — docstring:** States the function’s purpose in plain language.
- **32 — `if packet.haslayer(TCP):`:** Asks Scapy whether this packet contains a
  TCP layer. A packet is a stack of layers, such as Ethernet → IP → TCP.
- **33 — `return "TCP"`:** If it does, label the packet TCP and immediately
  leave the function.
- **34–35:** Do the same check and label for UDP.
- **36–37:** Do the same for ICMP, the protocol commonly used by ping and
  network error/control messages.
- **38–39:** Do the same for ARP, which maps an IPv4 address to a local network
  hardware address.
- **40–41:** If it is IPv6 but not one of the more specific protocols above,
  label it `IPv6-other`.
- **42–43:** Likewise, label an otherwise unrecognized IPv4 packet
  `IPv4-other`.
- **44:** If none of the known layers exists, use the catch-all label `Other`.

**How to say it aloud:** “I test the more specific transport protocols first.
That gives a useful label like TCP instead of only saying the packet used IP.”

### Lines 47–54: find addresses without inspecting contents

- **47 — `def ip_endpoints(...) -> tuple[str, str] | None:`:** Defines a helper
  that returns a pair of source/destination addresses, or `None` if none can be
  determined.
- **48:** Checks for an IPv4 layer.
- **49:** Returns that layer’s source (`src`) and destination (`dst`) addresses.
  This is header metadata, not payload content.
- **50–51:** Applies exactly the same approach to IPv6 packets.
- **52:** Checks whether the packet is ARP.
- **53:** ARP names the addresses differently: `psrc` and `pdst` mean protocol
  source and protocol destination. We return them in the same consistent order.
- **54:** Returns `None` for packets with none of those address layers.

### Lines 57–67: turn a packet into a flow label

- **57 — `def flow_key(...) -> str | None:`:** Defines a function that creates
  a readable flow identifier, or returns `None` if the packet has no endpoint.
- **58:** Calls the previous helper once and stores the result.
- **59:** Checks whether that helper found nothing.
- **60:** Stops early in that case, because a flow cannot be described without
  endpoints.
- **62 — `source, destination = endpoints`:** Unpacks the two returned values
  into names that make later code easier to understand.
- **63:** Checks for TCP because TCP has source and destination **ports**.
- **64:** Builds a string such as `TCP 10.0.0.5:51542 -> 1.1.1.1:443`. The `f`
  means Python inserts values into the braces. Ports distinguish different
  conversations using the same two IP addresses.
- **65–66:** Does the same for UDP packets and their UDP ports.
- **67:** For protocols without TCP/UDP ports, creates a simpler address-only
  flow string.

### Lines 70–104: the in-memory counting engine

- **70 — `@dataclass`:** Tells Python to generate useful boilerplate for the
  class, especially an initializer that sets up its fields.
- **71 — `class TrafficAnalyzer:`:** Starts the class that owns all counters
  during one run of the program.
- **72 — `packet_count: int = 0`:** Starts the total number of seen packets at
  zero.
- **73:** Starts total observed packet bytes at zero.
- **74:** Creates a fresh `Counter` for protocol labels for each analyzer.
- **75:** Creates a fresh counter for source addresses.
- **76:** Creates a fresh counter for destination addresses.
- **77:** Creates a fresh counter for flow labels.
- **78:** Creates a fresh counter for the TCP flag combinations seen.

  `default_factory=Counter` matters: it creates a separate empty counter for
  every `TrafficAnalyzer`. Without it, multiple analyzer objects could
  accidentally share the same mutable counter.

- **80 — `def process(...) -> None:`:** Defines the method called once per
  packet. `self` means “this particular analyzer”; `None` means it updates
  internal state instead of returning a result.
- **81 — docstring:** Makes the privacy choice explicit: process header
  metadata, deliberately ignore payload content.
- **82:** Gets the packet’s protocol label using `protocol_name`.
- **83:** Adds one to the total packet count.
- **84:** Adds the packet’s length in bytes. `len(packet)` is the size Scapy
  sees for that packet.
- **85:** Increments the count for this protocol. A missing protocol starts at
  zero because `Counter` handles it automatically.
- **87:** Extracts endpoints once for reuse.
- **88:** Continues only when endpoints are available. A tuple with two
  addresses is truthy; `None` is falsey.
- **89:** Adds one to the counter for the source address at position zero.
- **90:** Adds one to the counter for the destination address at position one.
- **92:** Builds a flow label using the packet and the protocol already found.
- **93:** Only count it if a label was successfully made.
- **94:** Adds one to that flow’s count.
- **96:** Checks whether the packet has TCP fields.
- **97:** Converts the TCP flag set to text (for example `S`, `SA`, or `A`) and
  increments its count. Flags help show connection starts, acknowledgements,
  resets, and finishes.
- **99:** Checks whether the user asked for per-packet console output.
- **100:** Prints Scapy’s compact one-line summary. It is not full payload
  output, but packet headers can still be sensitive.
- **102 — `@staticmethod`:** Declares the next helper does not need `self` or
  access to any one analyzer’s state.
- **103 — `def top(...)`:** Defines a generic helper: take a counter and a
  maximum number of results, then return JSON-friendly dictionaries.
- **104:** `most_common(limit)` sorts the counter from highest count down.
  The list comprehension turns each `(item, count)` pair into `{"value": ...,
  "count": ...}`. That consistent shape makes later display and JSON export
  simple.

### Lines 106–116: create the complete report

- **106 — `def report(...)`:** Defines a method that turns all the internal
  counters into one report dictionary.
- **107 — `{`:** Starts that dictionary.
- **108:** Records the current UTC timestamp in ISO 8601 format, such as
  `2026-08-08T12:34:56+00:00`.
- **109:** Includes the total packet count.
- **110:** Includes the total byte count.
- **111:** Adds every protocol count, ordered most-common first. `dict(...)`
  makes it directly serializable to JSON.
- **112:** Adds the requested number of busiest source addresses.
- **113:** Adds the busiest destination addresses.
- **114:** Adds the busiest flows.
- **115:** Adds TCP flag counts in JSON-ready form.
- **116 — `}`:** Closes the report dictionary and returns it.

### Lines 119–140: print the report for a person

- **119 — `def display_report(...)`:** Defines a function that formats the
  report nicely in the terminal.
- **120:** Prints a blank line followed by the report heading. `\n` means a
  newline.
- **121:** Prints packet count with thousands separators because `:,` formats
  12000 as `12,000`.
- **122:** Prints byte count in the same way.
- **124 — `for title, key in (...)`:** Iterates over five report sections. Each
  pair gives a human heading and the matching key in the report dictionary.
- **125:** Names the protocol section and its data key.
- **126:** Names the source-address section and its data key.
- **127:** Names the destination-address section and its data key.
- **128:** Names the flow section and its data key.
- **129:** Names the TCP-flag section and its data key.
- **130:** Ends the tuple of section definitions.
- **131:** Retrieves the data for the current section.
- **132:** Checks if that section has no data.
- **133 — `continue`:** Skips printing an empty section and moves to the next
  loop item.
- **134:** Prints the section heading, with a preceding blank line.
- **135:** Determines whether the section uses a dictionary representation
  (`protocols` and `tcp_flags`) rather than a list.
- **136:** Loops through a dictionary’s key/value pairs.
- **137:** Prints a left-aligned 45-character label and a right-aligned
  8-character count. Alignment makes the table legible.
- **138 — `else:`:** Handles list-shaped sections (`top_sources`,
  `top_destinations`, and `top_flows`).
- **139:** Loops through each `{"value", "count"}` record.
- **140:** Prints the value and count using the same aligned layout.

### Lines 143–161: read and validate command-line options

- **143 — `def parse_args() -> argparse.Namespace:`:** Defines the function
  that converts what the person typed into an `args` settings object.
- **144:** Creates the argument parser.
- **145:** Sets the one-sentence description displayed by `--help`.
- **146:** Finishes the multi-line parser call.
- **147:** Creates a *required mutually exclusive group*. The user must choose
  exactly one source: live interface or offline PCAP.
- **148:** Adds `--interface`, a text option such as `Ethernet` for live capture.
- **149:** Adds `--read-pcap`; `type=Path` automatically turns its text into a
  Path object for later file checks.
- **150:** Adds optional `--bpf`, a Berkeley Packet Filter expression passed to
  the live capture backend. For example, `tcp port 443` reduces capture to
  HTTPS-related TCP packets.
- **151:** Adds `--count`, converts it to an integer, and defaults it to zero.
  Zero means no packet limit.
- **152:** Adds optional `--timeout`, converting seconds to a decimal number.
- **153:** Adds `--top`, defaulting to ten rows in each ranking.
- **154:** Adds a Boolean switch. `store_true` means it is false unless the
  user includes `--show-packets`, when it becomes true.
- **155:** Adds an optional output path for the JSON report.
- **156:** Actually parses the command line; invalid syntax automatically gets
  a help-style error from `argparse`.
- **157:** Performs extra validation that `argparse` cannot express as simply:
  no negative packet count, at least one top row, and positive timeout.
- **158:** Stops with a clear usage error if any of those rules is violated.
- **159:** Checks a policy of this program: do not accept a BPF expression when
  reading a PCAP offline.
- **160:** Explains that policy and stops with a usage error. Filtering an
  existing PCAP should be done before analysis with a dedicated PCAP tool.
- **161:** Returns the validated settings to the caller.

### Lines 164–207: run the analysis safely

- **164 — `def main() -> int:`:** Defines the program’s main workflow. It
  returns an exit status: zero means success; nonzero means an error.
- **165:** Reads and validates the user’s command-line settings.
- **166:** Checks whether Scapy failed to import earlier.
- **167:** Starts printing a readable setup error.
- **168:** Tells the person the exact package-install command to run.
- **169:** Sends that text to standard error, not normal output.
- **170:** Finishes the `print` call.
- **171:** Returns exit code 2, a conventional code for command/setup errors.
- **172:** Creates a new analyzer with empty counters.
- **174 — nested `handle_packet`:** Defines the callback Scapy will run for
  every live packet. Keeping it here lets it use this run’s `analyzer` and
  `args` without global variables.
- **175:** Passes the packet into the analyzer and forwards the user’s
  `--show-packets` choice.
- **177 — `try:`:** Begins error handling around reading or sniffing traffic.
- **178:** Chooses the offline path when `--read-pcap` was supplied.
- **179:** Confirms the specified PCAP is an actual file before trying to parse
  it.
- **180:** Raises a clear file-not-found error with the missing path if it is
  not.
- **181:** Reads packets from the PCAP. `str(...)` gives Scapy a normal path
  string; `args.count or -1` means “the user’s positive limit, otherwise
  Scapy’s unlimited marker `-1`.”
- **182:** Sends each offline packet through exactly the same processing logic
  used for live traffic.
- **183 — `else:`:** Runs when the user selected `--interface` instead.
- **184:** Tells the user live passive capture has started and how to stop it.
- **185 — `sniff(`:** Calls Scapy’s live-capture function.
- **186:** Chooses the authorized network interface to listen on.
- **187:** Passes the optional BPF filter through to the capture engine.
- **188:** Supplies `handle_packet` as the per-packet callback.
- **189:** Uses `store=False`, so Scapy does not retain every whole packet in
  memory. This prevents unnecessary memory growth and supports the
  metadata-only design.
- **190:** Supplies the user’s packet limit; zero means no count limit.
- **191:** Supplies the optional time limit.
- **192:** Closes the `sniff` call.
- **193 — `except KeyboardInterrupt:`:** Catches Ctrl+C, which is a normal way
  to end an open-ended live capture.
- **194:** Prints confirmation that the user stopped it.
- **195 — `except (FileNotFoundError, OSError) as error:`:** Catches input-file
  and general operating-system errors, such as an unavailable interface.
- **196:** Displays the operating system’s message on standard error.
- **197:** Returns exit code 2 for that failure.
- **198 — `except PermissionError:`:** Intended to catch missing capture
  permissions and offer a friendlier message.
- **199:** The intended friendly permission message.
- **200:** The intended error return code.

  **Important correction to mention:** `PermissionError` is a subtype of
  `OSError`, so lines 198–200 are currently unreachable: the broader handler
  on line 195 catches it first. To make the friendly message work, place the
  `except PermissionError:` block before the `except (FileNotFoundError,
  OSError)` block.

- **202:** Builds the final report from all collected counters.
- **203:** Displays the human-readable version in the terminal.
- **204:** Checks whether the user asked to save JSON too.
- **205:** Serializes the report with two-space indentation and writes UTF-8
  text at the requested path. The output contains aggregate metadata only.
- **206:** Confirms where that JSON file was saved.
- **207:** Returns zero to tell the operating system the run succeeded.

### Lines 210–213: start only when run as a program

- **210 — `if __name__ == "__main__":`:** This is Python’s standard entry-point
  guard. The code below runs when this file is executed directly, but not when
  another Python file imports its functions.
- **211 — comment:** Explains why the signal configuration is present.
- **212:** Associates the Ctrl+C signal (`SIGINT`) with Python’s usual interrupt
  behavior, helping a live sniff stop promptly where the platform supports it.
- **213:** Runs `main()` and passes its integer result to the operating system
  as the program’s exit code. `raise SystemExit(...)` is the conventional,
  clean way to finish a command-line Python program.

## Terms worth knowing for a presentation

- **Packet:** One small unit of data traveling across a network.
- **Header / metadata:** Routing and protocol information, such as addresses,
  ports, and flags. It is distinct from the payload.
- **Payload:** The data being carried by a packet. This tool intentionally does
  not save or analyze it.
- **PCAP:** A file format containing captured packets, used for offline
  investigation.
- **Flow:** A repeatable description of a conversation, usually protocol +
  source address/port + destination address/port.
- **BPF filter:** A concise capture rule that reduces data collected before the
  analyzer sees it.
- **TCP flags:** Small control markers used to create, acknowledge, reset, or
  close a TCP connection.
