# Changelog

## Unreleased

- Contributor guide, rule template, issue and pull request templates, security policy.
- `tests/test_rule_pack.py` checks every built-in rule automatically (no misspelt keys,
  id matches source, description, MITRE ids, fires on the samples).
- Packaging ready for PyPI: project URLs, classifiers, SPDX licence field, and a
  Trusted Publishing job in the release workflow.

## 0.2.0

- **Auto-block**: `--block` on `scan` and `watch` blocks the source IP of high/critical
  attacks via iptables/ip6tables (dedicated `LOGSENTRY` chain) or Windows Defender Firewall
  (`netsh`). Preview by default (changes nothing, not even expiry); `--apply` enforces and re-applies saved blocks after a reboot. Allowlist (private ranges, the current
  SSH session, `--allow`), block expiry (`--block-ttl`), `--max-blocks` cap, JSON state file.
- **Live mode**: `logsentry watch` follows auth and web logs, handles rotation and truncation,
  and reports each attack burst once. `--jsonl` appends alerts for a SIEM.
- New commands: `logsentry blocks`, `logsentry unblock <ip>` / `--expired`, `logsentry rules -v`.
- **Deploy**: Dockerfile and docker-compose, hardened systemd unit with a one-command
  installer, standalone Linux and Windows executables built and attached on each release.
- Alerts now record which field they are grouped by (`group_by` in JSON output).
- CI installs the service on a real Linux runner and verifies iptables blocks the attackers.
- 106 tests (was 67).

## 0.1.0

- First release: parsers for Linux auth, Apache/Nginx and Windows Security logs,
  22 detection rules mapped to MITRE ATT&CK, text/JSON/Markdown reports, CI exit codes.
