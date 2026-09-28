# VM Verification Runbook — Modules 1–2 + Stage 1 integration

**Why this runbook exists:** the repo was reorganized (commit `7d7b5a6`):
Stage 1 code moved from `Project/outputs/` to `src/`, and the completion
reports moved into their stage folders. **Every VM clone must `git pull`
before running anything** — the old paths no longer exist. Time budget:
~30–45 minutes once the VMs are up.

**Golden rule during all of this:** if a guard intentionally aborts
(firewall lockout guard, static-address session guard), that is the design
working. Read the message; the fixes are listed inline below.

---

## 0. Prerequisites

- Three VMs on the lab segment: **server** (Ubuntu 24.04 / Debian 12),
  **Kali**, **analyzer** — addresses per `lab.env` (`SB_SRV_IP`,
  `SB_KALI_IP`, `SB_ANALYZER_IP`).
- Hypervisor mirroring configured for the lab segment (INTEGRATION.md §2) —
  or plan to use the server-side capture fallback (§5 below).
- NAT NIC online on each VM (for `git pull`), and console access (VM window)
  in case SSH drops mid-setup.
- Values below use `lab.env` placeholders — substitute or `source ../lab.env`.

## 1. Sync all three VMs

On **each** VM (server, kali, analyzer):

```bash
cd ~/SecureBank-Enterprise-Lab        # adjust to your clone path
git pull --ff-only origin main
git log --oneline -1                  # expect: 8d9a49e or later
ls stage1-network-traffic-analyzer/   # expect: src/ outputs/ docs/ — NO Project/
```

✅ **Marker:** commit hash `8d9a49e`+ and the new `src/ outputs/ docs/` layout.
❌ `Project/` still visible → the pull didn't land; stop and re-sync.

## 2. Server — apply + verify Modules 1–2

On the **SERVER** VM, over SSH from Kali (the guards depend on a live SSH
session):

```bash
sudo ./scripts/setup.sh
sudo ./tests/module1-verify.sh
```

✅ **Markers:**
- `setup.sh` finishes with its numbered "next steps" banner and writes
  `logs/setup-*.log` (config hashes).
- `module1-verify.sh` prints `Results: N passed, 0 failed` (N ≈ 75–80).
  **FAIL count must be 0.**
- Static addressing proof: the verify suite's "Module 2" section passes
  (lab NIC holds `10.10.10.10/24` + `fd00:10:10::10/64`).

**If a guard aborts:**
- *Firewall guard* — your SSH peer wasn't provably inside the lab subnet.
  Re-check the Kali VM's lab NIC address; re-run from the VM console if SSH
  died anyway (`SB_FIREWALL_SKIP=1` exists as an explicit escape).
- *Static-address guard* — the session would be cut by the IP change. Run
  `setup.sh` from the VM console instead of SSH, or read the message for the
  documented overrides.
- If setup offered a kernel upgrade: `sudo reboot`, re-run
  `module1-verify.sh`, expect `0 failed` again.

Record evidence for the lab manifest:

```bash
sudo ./scripts/collect-forensics.sh
```

## 3. Kali — key-origin check + Module 2 proof via SSH

On **KALI**:

```bash
ls ~/.ssh/                 # your private key lives HERE (C-12: Kali is the sole key origin)
ssh securebank-admin@10.10.10.10 'hostname && ip -4 addr show'
```

✅ **Markers:** key-based login succeeds without a password prompt (if it
doesn't yet, provision once: `ssh-copy-id securebank-admin@10.10.10.10`);
the server reports hostname `securebank-srv` and the **static** lab IP on the
lab NIC — that is Module 2 working, end to end.

## 4. Stage 1 integration test

On the **ANALYZER** VM (root):

```bash
cd stage1-network-traffic-analyzer
python3 -m pip install -r requirements.txt     # if not already installed
sudo ./tests/integration_test.sh eth0          # your lab NIC
```

✅ **Markers (the script prints them):**
- `[PASS] traffic generator ran on Kali`
- `[PASS]` on the SSH flow (cross-host, peer-validated) **and** on an
  HTTP (80/443) flow
- `[VALID]` from `validate_report.py`, then `VAL_OK` and a final PASS summary
- evidence stored under `reports/integration-<timestamp>/`

❌ `ARP/broadcast-only` FAIL ⇒ **hypervisor mirroring is not active** — the
test is telling the truth. Fix mirroring (INTEGRATION.md §2) or use §5.

## 5. Fallback: server-side capture (host-based sensor)

If mirroring is impossible on your hypervisor, capture on the server itself
and document it as a host-based sensor (INTEGRATION.md §2 fallback):

```bash
# on the SERVER:
sudo tcpdump -i <lab-nic> -w /tmp/lab.pcap -G 90 -W 1 &
#   ... then from Kali: run the traffic generator (step 3's SSH session plus
#   stage2 generate-lab-traffic.sh), wait for tcpdump to rotate out ...
sudo python3 stage1-network-traffic-analyzer/src/network_traffic_analyzer.py \
  --read-pcap /tmp/lab.pcap --json-only > /tmp/report.json
python3 stage1-network-traffic-analyzer/src/validate_report.py /tmp/report.json
```

✅ **Marker:** `[VALID]` and the report's flows show Kali↔server SSH + HTTP.

## 6. After everything is green

- Nothing to commit: VM runs produce `logs/` and evidence, which are
  git-ignored. Only contract changes (`lab.env`/`INTEGRATION.md`) get
  commits — and then in the same change, per the rule.
- Update your tracker: **Stage 2 Module 2 → verified**; **Stage 1 → verified
  on-VM**. Module 3 can then start from the pre-install register
  (`docs/module3-service-register.md`).
