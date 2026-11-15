# Changelog

## 0.2.0

- **Auto-block**: `--block` on `scan` and `watch` blocks the source IP of high/critical
  attacks via iptables/ip6tables (dedicated `LOGSENTRY` chain) or Windows Defender Firewall
  (`netsh`). Preview by default; `--apply` enforces. Allowlist (private ranges, the current
  SSH session, `--allow`), block expiry (`--block-ttl`), `--max-blocks` cap, JSON state file.
- **Live mode**: `logsentry watch` follows auth and web logs, handles rotation and truncation,
  and reports each attack burst once. `--jsonl` appends alerts for a SIEM.
- New commands: `logsentry blocks`, `logsentry unblock <ip>` / `--expired`, `logsentry rules -v`.
- **Deploy**: Dockerfile and docker-compose, hardened systemd unit with a one-command
  installer, standalone Linux and Windows executables built and attached on each release.
- Alerts now record which field they are grouped by (`group_by` in JSON output).
- CI installs the service on a real Linux runner and verifies iptables blocks the attackers.
- 101 tests (was 67).

## 0.1.0

- First release: parsers for Linux auth, Apache/Nginx and Windows Security logs,
  22 detection rules mapped to MITRE ATT&CK, text/JSON/Markdown reports, CI exit codes.
