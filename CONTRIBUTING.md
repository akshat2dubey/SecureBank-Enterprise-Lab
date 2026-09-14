# Contributing to SecureBank Enterprise Lab

Thanks for helping! This project is **one interconnected cybersecurity
ecosystem**, not nine unrelated mini-projects. Every stage consumes, monitors,
tests, or protects another stage — so a change to *any* file can ripple
downstream. Read this whole page before opening an issue or a pull request.

## 1. Read the contract first (non-negotiable)

Two files at the repo root are the glue that makes the stages one ecosystem.
**Any change to an address, port, or artifact format must update both in the
same commit:**

- **`lab.env`** — the single source of truth for lab identity (subnet, IPs,
  hostnames, admin user, timezone).
- **`INTEGRATION.md`** — the cross-stage contract: address registry, reserved
  ports, UTC timestamp convention, log transport (RFC 5424 → Stage 7 SIEM),
  the Stage 1 report schema (INTEGRATION.md §6 — current: `traffic-report/1.1`,
  additive-only over 1.0), artifact naming, and the
  contract changelog.

If a stage needs an address, it **sources `lab.env`** — never hardcode an IP
inside a script, config, test, or document.

## 2. The golden rules

1. **Never break the contract.** Changing an address/port/format without
   updating `lab.env` + `INTEGRATION.md` is a breaking change. Record it in
   the `INTEGRATION.md` changelog (§10) with date, stage, reason, and impact.
2. **No secrets, ever.** Credentials (especially any VM password) never belong
   in the repository. `logs/` is git-ignored runtime output — keep it that way.
3. **Stage 1 report schema is additive-only.** A field may be *added*; never
   remove or re-purpose one without bumping `schema_version` and updating
   `INTEGRATION.md` §6.
4. **Deferrals are deliberate.** `stage2-securebank-linux-server/docs/
   host-auditing.md` documents why auditd, Fail2Ban, AIDE, and filesystem
   hardening are deferred, with the triggers that would justify them. Don't
   "just install" a control to tick a box — add it only with a documented
   purpose, threat, configuration, and verification (see the hardening
   register).
5. **Scope boundaries are deliberate.** The Stage 1 analyzer is metadata-only
   and lab-scale by design. No payload capture, no Zeek/Suricata migration, no
   full IDS — unless a future stage provides a concrete requirement.
6. **Document before install.** Every new service or control needs a
   hardening-register row (purpose / threat / configuration / verification)
   and a `services.md` entry *before* the package is installed (the Stage 2
   Module 3 gate).
7. **Verify effective state, not file existence.** Follow the pattern of
   `tests/module1-verify.sh`: assert `sshd -T`, `nft list ruleset`, `sysctl`,
   rendered-template `cmp`, and drift detection.
8. **Keep scripts idempotent.** Re-running setup/traffic/verify must be safe.
   Later stages may wrap the Bash in IaC, but the scripts stay re-runnable.
9. **Check downstream consumers.** Before you change Stage 2, ask: what does
   Stage 1/3/7/8/9 read from this? Update those consumers or flag the impact.

## 3. How to contribute

1. **Open an issue first** for anything non-trivial — say which stage(s) you
   intend to touch and why.
2. **Work on a branch** (`git checkout -b stage2/module2-static-ip`), not on
   `main`.
3. **Keep changes small and focused** on one stage/module per PR.
4. **Update the docs that describe your change**: the stage README, the
   hardening register, `services.md`, `INTEGRATION.md` changelog, and — for a
   completed module — the completion report in `reports/` (rebuild with
   `python reports/build_reports.py`).
5. **Run the checks** (see below) and paste the results in the PR.
6. **Open the PR** with the checklist below filled in.

## 4. Pull request checklist

- [ ] Which stage(s)/module(s) does this touch? (state in the PR body)
- [ ] Did you change an address, port, or artifact format?
      → `lab.env` **and** `INTEGRATION.md` (incl. changelog) updated in the
      same PR?
- [ ] Did you add or change a Stage 1 report field?
      → `schema_version` bumped and `INTEGRATION.md` §6 updated?
- [ ] No secrets, keys, or VM credentials in the diff?
- [ ] Scripts pass `bash -n` (or Python compiles / pytest passes)?
- [ ] New controls have register rows (purpose / threat / config / verify)?
- [ ] Downstream consumers checked (did anything else read the thing you changed)?
- [ ] Documentation updated (README / register / services / reports)?

## 5. Local checks

```bash
# Stage 1 (Python analyzer) — needs scapy + pytest
python -m pip install -r stage1-network-traffic-analyzer/requirements.txt
python -m pytest stage1-network-traffic-analyzer/tests/ -q

# Stage 2 shell scripts — syntax
for f in stage2-securebank-linux-server/scripts/*.sh \
         stage2-securebank-linux-server/tests/*.sh; do bash -n "$f"; done

# On the SecureBank VM (root): full effective-state verification
sudo ./stage2-securebank-linux-server/scripts/setup.sh
sudo ./stage2-securebank-linux-server/tests/module1-verify.sh

# Stage 1 <-> Stage 2 integration proof (on the analyzer VM)
sudo ./stage1-network-traffic-analyzer/tests/integration_test.sh eth0
```

## 6. License

By contributing you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
