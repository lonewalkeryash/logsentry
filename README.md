# LogSentry

[![CI](https://github.com/lonewalkeryash/logsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/lonewalkeryash/logsentry/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**A lightweight threat detection and response tool for security logs.**
LogSentry reads Linux auth logs, web server access logs and Windows Security
events, runs them through YAML detection rules mapped to **MITRE ATT&CK**, and
reports attacks like brute force, password spraying, SQL injection, web shells,
privilege escalation and log tampering. It can follow logs live and
**automatically block the attacking IP** at the host firewall (iptables or
Windows Defender Firewall).

You can think of it as a tiny SIEM correlation engine plus a fail2ban-style
responder, run from the command line or as a service.

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
- **22 built-in detection rules** covering 17 MITRE ATT&CK techniques and sub-techniques (13 parent techniques). Each rule is a small YAML file.
- **3 rule types:**
  - `pattern`: one event is enough (SQLi payload, log cleared, encoded PowerShell)
  - `threshold`: N events, or N *distinct* values, per group in a sliding time window (brute force, password spraying, directory busting)
  - `sequence`: ordered, correlated steps from the same source (many failures *then* a success = compromised account)
- **Burst de-duplication:** a 5,000-line brute force produces one alert, not 1,000.
- **Reports** as coloured terminal output, JSON (for SIEM/SOAR pipelines) or Markdown (for tickets and incident write-ups).
- **CI-friendly exit codes**: `--fail-on high` exits `1` when findings reach that severity.
- **Live monitoring**: `logsentry watch` follows growing logs, survives log rotation, and alerts within a second.
- **Auto-block**: blocks the source IP of high-severity attacks with iptables or `netsh`, with a preview mode,
  allowlist, block expiry and a cap on active blocks so it can't lock you out.
- **Easy deploy**: `pip install`, a standalone executable with no Python needed, a Docker image, or a
  one-command systemd service installer.
- **One dependency** (PyYAML); the rest is plain standard-library Python.
- **200+ unit, rule-quality and end-to-end tests**, run on Linux and Windows through GitHub Actions. CI also installs the
  service on a real Linux runner and checks that iptables actually blocks the attackers.

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
| LS-WEB-003 | Cross-site scripting attempt | pattern | medium | T1190 |
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

Pick whichever suits you. Every option brings its own dependencies.

| Option | Command | Needs |
|---|---|---|
| **pip / pipx** | `pipx install git+https://github.com/lonewalkeryash/logsentry.git` | Python 3.10+ |
| **Standalone executable** | download `logsentry-linux-x86_64` or `logsentry-windows-x86_64.exe` from [Releases](https://github.com/lonewalkeryash/logsentry/releases) | nothing |
| **Docker** | `docker build -t logsentry .` | Docker |
| **Linux service** | `sudo ./deploy/install.sh` (see [Deploy](#deploy)) | Python 3.10+, systemd |
| **From source** | `git clone https://github.com/lonewalkeryash/logsentry.git && cd logsentry && pip install -e ".[dev]"` | Python 3.10+ |

If your shell says `logsentry: command not found` (pip's script folder isn't on `PATH`),
use `python -m logsentry` instead. It takes the same arguments.

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

# list rules (with -v: what each one detects) / add your own
logsentry rules -v
logsentry scan auth.log --extra-rules ./my-rules/

# follow logs live
logsentry watch /var/log/auth.log --format auth
logsentry watch /var/log/nginx/access.log --format web --jsonl alerts.jsonl
```

Exit codes: `0` = clean (or below `--fail-on`), `1` = findings at/above `--fail-on`, `2` = error.

## Auto-block (response)

Add `--block` to `scan` or `watch` and LogSentry blocks the source IP of every
**high or critical** attack at the host firewall.

```bash
# 1. preview: prints the firewall commands it WOULD run, changes nothing
logsentry scan samples/auth.log samples/access.log samples/windows_security.jsonl --year 2026 --block

# 2. enforce (root on Linux, an Administrator shell on Windows)
sudo logsentry watch /var/log/auth.log --format auth --block --apply --allow 198.51.100.0/24

# 3. review and undo
sudo logsentry blocks
sudo logsentry unblock 203.0.113.45
sudo logsentry unblock --expired
```

```
08:14:02 HIGH     LS-AUTH-001  SSH brute force [203.0.113.45]  6 event(s) ...
[block]   203.0.113.45 blocked via iptables for LS-AUTH-001 SSH brute force (expires 2026-11-16 08:14)
```

Replaying the sample SSH attack through `watch`, the brute-force rule fires on
the 5th failed password. With `--apply` the attacker is cut off there; in the
sample they needed 15 attempts to get in.

| Firewall | Option | What it does |
|---|---|---|
| iptables / ip6tables (Linux) | `--firewall iptables` | adds `-s <ip> -j DROP` to a dedicated `LOGSENTRY` chain hooked into `INPUT` |
| Windows Defender Firewall | `--firewall netsh` | adds an inbound block rule named `LogSentry-block-<ip>` |

The default (`auto`) picks `netsh` on Windows and `iptables` on Linux. iptables
rules also apply on hosts that use ufw.

**Guard rails.** An auto-blocker that can be tricked into blocking the wrong
thing is a liability, so:

- **Preview by default.** Nothing changes without `--apply`.
- **Only real attacker IPs.** A rule must group by `src_ip`, and the value must
  parse as an IP address. Log text is attacker-controlled, so anything else
  (`1.2.3.4; rm -rf /`, `-j ACCEPT`) is refused, and commands run as argument
  lists, never through a shell.
- **Never locks you out.** Loopback, private (RFC 1918, ULA), link-local and
  CGNAT ranges, the IP of the SSH session you're running it from, and anything
  passed with `--allow` are never blocked.
- **Bounded.** Blocks expire after `--block-ttl` (default `24h`; `0` = never),
  and at most `--max-blocks` (default 500) can be active at once. On a busy
  internet-facing server, raise it or shorten the TTL.
- **Survives restarts.** Firewall rules are lost on reboot, so with `--apply`
  unexpired blocks from the state file are re-applied when LogSentry starts.
  The state file is re-read before every change, so a manual `unblock` sticks
  even while the service is running.
- **Tunable.** `--block-severity critical` blocks only confirmed compromises
  (e.g. a successful login after brute force).
- **Auditable.** Every block is recorded in a JSON state file
  (`--state`, `$LOGSENTRY_STATE`, default `~/.logsentry/blocks.json`).

> Behind a reverse proxy, CDN or load balancer, web logs show the proxy's IP,
> not the visitor's. Add the proxy's range with `--allow`, or don't auto-block
> from web logs.

## Deploy

### Linux server (systemd)

```bash
git clone https://github.com/lonewalkeryash/logsentry.git
cd logsentry
sudo ./deploy/install.sh
journalctl -u logsentry -f          # live alerts
```

The installer creates a virtualenv in `/opt/logsentry` with all dependencies,
installs the [`logsentry.service`](https://github.com/lonewalkeryash/logsentry/blob/main/deploy/logsentry.service) unit and starts it.
It starts in **preview mode**. Edit `/etc/logsentry/logsentry.env`, add
`--apply` (and `--allow <your IP>`), then `sudo systemctl restart logsentry`.
The service runs with only the capabilities it needs (`CAP_NET_ADMIN`,
`CAP_NET_RAW`, `CAP_DAC_READ_SEARCH`) and a read-only filesystem.
`sudo ./deploy/install.sh --uninstall` removes it and its firewall chain.

### Docker

```bash
docker build -t logsentry .
docker run --rm -v "$PWD/samples:/logs:ro" logsentry scan /logs/auth.log --year 2026   # detection only
docker compose up -d                                                                   # live SSH protection
```

Detection needs no privileges. To block, the container must share the host's
network namespace and have `NET_ADMIN`; [`docker-compose.yml`](https://github.com/lonewalkeryash/logsentry/blob/main/docker-compose.yml)
sets that up in preview mode (add `--apply` to the command to enforce).

> Blocks go in the host's `INPUT` chain, which protects services running on the
> host (like SSH). Ports published by *other* Docker containers are routed
> through `FORWARD` and `DOCKER-USER` instead, so they are not covered.

### Windows

Download `logsentry-windows-x86_64.exe` from [Releases](https://github.com/lonewalkeryash/logsentry/releases)
(no Python needed), export events as shown below, and run from an
**Administrator** PowerShell:

```powershell
.\logsentry-windows-x86_64.exe scan security.jsonl --block            # preview
.\logsentry-windows-x86_64.exe scan security.jsonl --block --apply    # add firewall rules
.\logsentry-windows-x86_64.exe unblock 203.0.113.200
```

Run it from Task Scheduler every few minutes for continuous protection.

### Build the standalone executable yourself

```bash
pip install . pyinstaller
bash packaging/build_binary.sh      # -> dist/logsentry (or dist/logsentry.exe)
```

Pushing a `v*` tag runs [`release.yml`](https://github.com/lonewalkeryash/logsentry/blob/main/.github/workflows/release.yml), which builds,
tests and attaches the Linux and Windows executables to a GitHub release.

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
                windows)                      YAML rules           │
                                         (pattern / threshold / sequence)   ▼
                                                                  responder ──► firewall block
                                                              (allowlist, TTL, cap)  (iptables / netsh)
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
5. **Live mode.** `watch` polls each file for new lines, keeps a rolling buffer as long as the
   longest rule window, re-runs the engine on it and prints only alerts from new bursts.
6. **Response.** The responder turns eligible alerts into firewall blocks after the checks
   listed under [Auto-block](#auto-block-response).

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

## Contributing

New detection rules are the easiest way to help: a rule is a few lines of YAML
plus a few sample log lines, and the test suite checks it automatically. See
[CONTRIBUTING.md](https://github.com/lonewalkeryash/logsentry/blob/main/CONTRIBUTING.md)
for a 10-minute walkthrough and the
[rule template](https://github.com/lonewalkeryash/logsentry/blob/main/docs/rule-template.yml).
Issues labelled
[`good first issue`](https://github.com/lonewalkeryash/logsentry/labels/good%20first%20issue)
are a good place to start. To report a vulnerability in LogSentry itself, see
[SECURITY.md](https://github.com/lonewalkeryash/logsentry/blob/main/SECURITY.md).

## Sample data and testing

`samples/` contains **synthetic** logs made by `scripts/generate_samples.py`. They
mix normal traffic with planted attacks. All IPs come from the RFC 5737
documentation ranges and every user and host name is made up.

```bash
pytest -v                          # parsers, engine, rule pack, live watch, auto-block, end-to-end
python scripts/generate_samples.py # regenerate the samples
python scripts/benchmark.py        # throughput on a 200k-line synthetic auth log
```

The end-to-end tests check that **every planted attack is detected** and that **no alert
fires on the benign 192.0.2.0/24 hosts**. The only exception is the deliberate root-login misconfiguration.

Benchmark on a laptop (Python 3.14, Windows 11): 200,000 lines parsed and checked against all 22 rules in about 3.5 s, around 55,000 lines/sec.

## Roadmap

- [ ] Sigma rule import
- [x] Live tail mode (`logsentry watch /var/log/auth.log`)
- [x] Automatic IP blocking (iptables / Windows Firewall)
- [ ] nftables and cloud firewall (AWS security group, Cloudflare) backends
- [ ] Live Windows event subscription instead of JSON exports
- [ ] GeoIP / threat-intel enrichment for source IPs
- [ ] Syslog / journald JSON input
- [ ] HTML dashboard report

## Disclaimer

LogSentry is a defensive tool for analysing logs **you own or are authorised
to review** and protecting systems you administer. It does not scan, probe or
attack anything. Test auto-block in preview mode first, and always allowlist
the addresses you manage the server from.

## License

MIT © Yashas S Reddy
