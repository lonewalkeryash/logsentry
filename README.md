# LogSentry

[![CI](https://github.com/lonewalkeryash/logsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/lonewalkeryash/logsentry/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**A lightweight, rule-based threat detection engine for security logs.**
LogSentry reads Linux auth logs, web server access logs and Windows Security
events, runs them through YAML detection rules mapped to **MITRE ATT&CK**, and
reports attacks like brute force, password spraying, SQL injection, web shells,
privilege escalation and log tampering.

You can think of it as a tiny SIEM correlation engine you run from the command line.

```
$ logsentry scan samples/auth.log

CRITICAL LS-AUTH-003  Successful SSH login after brute force [203.0.113.45]
         15 event(s)  2026-11-14 02:13:00 -> 02:14:10  MITRE T1110, T1078
         e.g. samples/auth.log:15  Nov 14 02:14:10 web01 sshd[1064]: Accepted password for deploy from 203.0.113.45 port 50099 ssh2

HIGH     LS-AUTH-001  SSH brute force [203.0.113.45]
         14 event(s)  2026-11-14 02:13:00 -> 02:13:52  MITRE T1110.001

HIGH     LS-AUTH-007  User added to privileged group
         1 event(s)  2026-11-14 02:18:30  MITRE T1098
         e.g. samples/auth.log:18  Nov 14 02:18:30 web01 usermod[1067]: add 'sysupdate' to group 'sudo'

MEDIUM   LS-AUTH-005  Sudo used to spawn a root shell
MEDIUM   LS-AUTH-006  New local user account created
...
Summary: 1 critical, 5 high, 2 medium  (8 alerts)
```

The sample above shows a full attack chain picked out of 80 log lines:
brute force → account compromise → root shell → backdoor user → added to `sudo`.

---

## Features

- **3 log formats**, auto-detected: Linux `auth.log` (sshd / sudo / useradd / usermod),
  Apache/Nginx combined access logs, and Windows Security/System events exported as JSON lines.
- **22 built-in detection rules** covering 18 MITRE ATT&CK techniques and sub-techniques. Each rule is a small YAML file.
- **3 rule types:**
  - `pattern`: one event is enough (SQLi payload, log cleared, encoded PowerShell)
  - `threshold`: N events, or N *distinct* values, per group in a sliding time window (brute force, password spraying, directory busting)
  - `sequence`: ordered, correlated steps from the same source (many failures *then* a success = compromised account)
- **Burst de-duplication:** a 5,000-line brute force produces one alert, not 1,000.
- **Reports** as coloured terminal output, JSON (for SIEM/SOAR pipelines) or Markdown (for tickets and incident write-ups).
- **CI-friendly exit codes**: `--fail-on high` exits `1` when findings reach that severity.
- **One dependency** (PyYAML); the rest is plain standard-library Python.
- **52 unit and end-to-end tests**, run on Linux and Windows through GitHub Actions.

## Detection coverage

| ID | Detection | Type | Severity | MITRE ATT&CK |
|---|---|---|---|---|
| LS-AUTH-001 | SSH brute force | threshold | high | T1110.001 |
| LS-AUTH-002 | SSH password spraying | threshold (distinct users) | high | T1110.003 |
| LS-AUTH-003 | Successful SSH login after brute force | sequence | critical | T1110, T1078 |
| LS-AUTH-004 | Direct root login over SSH | pattern | high | T1078.003 |
| LS-AUTH-005 | Sudo used to spawn a root shell | pattern | medium | T1548.003 |
| LS-AUTH-006 | New local user account created | pattern | medium | T1136.001 |
| LS-AUTH-007 | User added to privileged group | pattern | high | T1098 |
| LS-WEB-001 | SQL injection attempt | pattern | high | T1190 |
| LS-WEB-002 | Path traversal / LFI | pattern | high | T1190, T1083 |
| LS-WEB-003 | Cross-site scripting attempt | pattern | medium | T1059.007 |
| LS-WEB-004 | Known vulnerability scanner (sqlmap, nikto, gobuster…) | pattern | medium | T1595.002 |
| LS-WEB-005 | Directory / content brute forcing | threshold | medium | T1595.003 |
| LS-WEB-006 | Possible web shell access | pattern | critical | T1505.003 |
| LS-WEB-007 | Web login brute force | threshold | high | T1110 |
| LS-WIN-001 | Windows logon brute force (4625) | threshold | high | T1110.001 |
| LS-WIN-002 | Windows password spraying | threshold (distinct users) | high | T1110.003 |
| LS-WIN-003 | Successful logon after brute force (4625 → 4624) | sequence | critical | T1110, T1078 |
| LS-WIN-004 | Security event log cleared (1102) | pattern | critical | T1070.001 |
| LS-WIN-005 | New user account created (4720) | pattern | medium | T1136.001 |
| LS-WIN-006 | Account added to Administrators (4732/4728) | pattern | high | T1098 |
| LS-WIN-007 | Suspicious / encoded PowerShell (4688) | pattern | high | T1059.001, T1027 |
| LS-WIN-008 | New service installed (7045) | pattern | medium | T1543.003 |

## Install

```bash
git clone https://github.com/lonewalkeryash/logsentry.git
cd logsentry
pip install -e ".[dev]"
```

## Usage

```bash
# scan one or more files (format is auto-detected)
logsentry scan samples/auth.log samples/access.log samples/windows_security.jsonl

# real server logs
sudo logsentry scan /var/log/auth.log /var/log/nginx/access.log

# JSON for a pipeline, Markdown for a ticket
logsentry scan /var/log/auth.log -o json --out report.json
logsentry scan samples/access.log -o markdown

# only high+ findings, and fail a CI job if anything critical shows up
logsentry scan app.log --min-severity high --fail-on critical

# list rules / add your own
logsentry rules
logsentry scan auth.log --extra-rules ./my-rules/
```

Exit codes: `0` = clean (or below `--fail-on`), `1` = findings at/above `--fail-on`, `2` = error.

### Exporting Windows events

```powershell
Get-WinEvent -LogName Security -MaxEvents 5000 | ForEach-Object {
  $x = [xml]$_.ToXml(); $d = @{ EventID = $_.Id; TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o"); Computer = $_.MachineName }
  $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  $d | ConvertTo-Json -Compress
} | Out-File -Encoding utf8 security.jsonl
```

## How it works

```
 log files ──► parsers ──► normalised Events ──► detection engine ──► Alerts ──► text / JSON / Markdown
               (auth,        {timestamp,          ▲                               + exit code
                web,          source, fields})    │
                windows)                      YAML rules
                                         (pattern / threshold / sequence)
```

1. **Parsing.** Each parser turns a raw line into an `Event` with a timestamp, a source
   (`auth`/`web`/`windows`) and normalised fields such as `action`, `src_ip`, `user`, `url`,
   `url_decoded`, `status` and `event_id`. URLs are percent-decoded so `%27%20OR%201%3D1` is caught.
2. **Rules.** Rules are loaded from YAML and validated when they load (bad severity, missing
   `group_by` and so on fail early with a clear message). Each rule's `match:` block is compiled into a matcher.
3. **Engine.** Events are sorted by time and fed to each rule:
   - *threshold* keeps a sliding-window deque per group (such as per source IP) and fires
     when the count (or distinct-value count) reaches the threshold. Later events from the same
     burst are folded into the open alert instead of making new ones.
   - *sequence* keeps one bucket per step per group and fires only when every earlier step
     reached its `min_count` inside the window before the final step happened.
4. **Reporting.** Alerts are sorted by severity, then by time. Each one carries its first/last
   seen times, an event count, ATT&CK IDs and the original log lines as evidence.

### Example: how the "compromised account" rule fires

```yaml
id: LS-AUTH-003
title: Successful SSH login after brute force
severity: critical
mitre: [T1110, T1078]
source: auth
type: sequence
group_by: src_ip
window: 15m
steps:
  - match: {action: ssh_failed}
    min_count: 5
  - match: {action: ssh_success}
```

For each source IP, LogSentry counts failed logins inside a rolling 15-minute window.
A successful login from the *same IP* while that count is 5 or more raises a critical alert
that contains the whole chain. A user who mistypes a password three times and then logs in does not trigger it.

## Writing your own rules

Drop a `.yml` file in a folder and pass `--extra-rules folder/`. Several rules can live in one
file, separated by `---`.

```yaml
id: CUSTOM-001
title: Access to admin panel from outside office range
severity: medium
mitre: [T1078]
source: web
type: pattern
match:
  url: {regex: '^/admin'}
  src_ip: {regex: '^(?!10\.)'}
```

Match operators: `field: value` (equals), `field: [a, b]` (any of), `{regex: ...}`
(case-insensitive), `{gte|lte|gt|lt: n}`, `{exists: true}`. Every condition must match.

## Sample data and testing

`samples/` contains **synthetic** logs made by `scripts/generate_samples.py`. They
mix normal traffic with planted attacks. All IPs come from the RFC 5737
documentation ranges and every user and host name is made up.

```bash
pytest -v                          # 52 tests: parsers, engine logic, end-to-end on the samples
python scripts/generate_samples.py # regenerate the samples
python scripts/benchmark.py        # throughput on a 200k-line synthetic auth log
```

The end-to-end tests check that **every planted attack is detected** and that **no alert
fires on the benign 192.0.2.0/24 hosts**. The only exception is the deliberate root-login misconfiguration.

Benchmark on a laptop (Python 3.14, Windows 11): 200,000 lines parsed and checked against all 22 rules in about 3.1 s, around 64,000 lines/sec.

## Roadmap

- [ ] Sigma rule import
- [ ] Live tail mode (`logsentry watch /var/log/auth.log`)
- [ ] GeoIP / threat-intel enrichment for source IPs
- [ ] Syslog / journald JSON input
- [ ] HTML dashboard report

## Disclaimer

LogSentry is a defensive, educational tool for analysing logs **you own or are
authorised to review**. It does not scan, probe or attack anything.

## License

MIT © Yashas S Reddy
