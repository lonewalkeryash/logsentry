"""Log parsers. Each turns raw lines into normalised :class:`Event` objects.

Supported formats:

* ``auth``    - Linux syslog auth log (``/var/log/auth.log``): sshd, sudo, useradd
* ``web``     - Apache/Nginx combined access log
* ``windows`` - Windows Security events exported as JSON lines
                (e.g. ``Get-WinEvent ... | ForEach-Object { $_ | ConvertTo-Json -Compress }``)
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator
from urllib.parse import unquote_plus

from .events import Event

# --------------------------------------------------------------------------- auth

# Classic "Nov 14 02:13:00" syslog stamps, or the RFC 3339 stamps that
# Ubuntu 24.04 / Debian 12 rsyslog write by default.
_SYSLOG = re.compile(
    r"^(?:(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
_REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<msg>.*)\]$")

# (compiled regex, action name) - first match wins.
# The username is attacker-controlled (sshd logs whatever was typed, spaces and
# all), so the IP is anchored to the END of the line: a username such as
# "x from 10.0.0.1" cannot spoof the source address.
_TAIL = r" from (?P<src_ip>\S+) port \d+(?: ssh\d)?\s*$"
_AUTH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>.*?)" + _TAIL), "ssh_failed"),
    (re.compile(r"Accepted (?:password|publickey) for (?P<user>.*?)" + _TAIL), "ssh_success"),
    (re.compile(r"Invalid user (?P<user>.*?) from (?P<src_ip>\S+)(?: port \d+)?\s*$"), "ssh_invalid_user"),
    (re.compile(r"^\s*(?P<user>\S+) : .*USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.+)$"), "sudo"),
    (re.compile(r"new user: name=(?P<user>[^,\s]+)"), "user_created"),
    (re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'"), "group_add"),
]

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def _to_utc_naive(dt: datetime) -> datetime:
    """Convert aware datetimes to UTC so logs from different zones sort correctly."""
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _iso(value: str) -> datetime:
    value = value.strip().replace("Z", "+00:00")
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)        # .NET writes 7 digits; py<3.11 takes 6
    value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)  # +0100 -> +01:00 for py<3.11
    return _to_utc_naive(datetime.fromisoformat(value))


def parse_auth_line(line: str, year: int) -> Event | None:
    m = _SYSLOG.match(line)
    if not m:
        return None
    try:
        if m["iso"]:
            ts = _iso(m["iso"])
        else:
            h, mi, s = (int(x) for x in m["time"].split(":"))
            ts = datetime(year, _MONTHS[m["month"]], int(m["day"]), h, mi, s)
    except (ValueError, KeyError):
        return None  # e.g. "Feb 29" in a non-leap year: skip the line, don't abort the scan
    msg = m["msg"]
    repeat = 1
    rm = _REPEATED.match(msg)
    if rm:  # rsyslog collapses identical lines: "message repeated 4 times: [ Failed password ...]"
        msg, repeat = rm["msg"], int(rm["n"])
    fields: dict = {"host": m["host"], "process": m["proc"], "action": "other", "message": msg}
    if repeat > 1:
        fields["repeat"] = repeat
    for pattern, action in _AUTH_PATTERNS:
        pm = pattern.search(msg)
        if pm:
            fields["action"] = action
            fields.update({k: v for k, v in pm.groupdict().items() if v is not None})
            break
    return Event(ts, "auth", fields, line)


# ---------------------------------------------------------------------------- web

_COMBINED = re.compile(
    r'^(?P<src_ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+)(?: (?P<protocol>[^"]+))?" (?P<status>\d{3}) (?P<size>\S+)'
    # Apache/Nginx escape quotes inside these fields as \" - honour that so a
    # User-Agent like 'x \"y\" sqlmap/1.8' can't hide the scanner name.
    r'(?: "(?P<referrer>(?:[^"\\]|\\.)*)" "(?P<user_agent>(?:[^"\\]|\\.)*)")?'
)


def parse_web_line(line: str, year: int | None = None) -> Event | None:
    m = _COMBINED.match(line)
    if not m:
        return None
    try:
        ts = _to_utc_naive(datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z"))
    except ValueError:
        return None
    url = m["url"]
    fields = {
        "action": "http_request",
        "src_ip": m["src_ip"],
        "user": None if m["user"] == "-" else m["user"],
        "method": m["method"],
        "url": url,
        # decoded copy so rules catch %27 OR %271%27=%271 style payloads
        "url_decoded": unquote_plus(url),
        "status": int(m["status"]),
        "size": 0 if m["size"] == "-" else int(m["size"]),
        "user_agent": m["user_agent"] or "",
    }
    return Event(ts, "web", fields, line)


# ------------------------------------------------------------------------ windows

# Event ID -> normalised action
_WIN_ACTIONS = {
    4624: "logon_success",
    4625: "logon_failed",
    4720: "user_created",
    4728: "group_add",  # member added to security-enabled global group
    4732: "group_add",  # ... local group (e.g. Administrators)
    4756: "group_add",  # ... universal group (e.g. Enterprise Admins)
    1102: "log_cleared",
    4688: "process_created",
    7045: "service_installed",
}


def _win_time(value: str) -> datetime:
    # Accept ISO-8601 ("2026-11-14T22:01:05Z") or PowerShell's "/Date(1731621665000)/"
    # (optionally "/Date(1731621665000+0100)/" - the epoch value is already UTC).
    m = re.match(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/", value)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc).replace(tzinfo=None)
    return _iso(value)


def parse_windows_line(line: str, year: int | None = None) -> Event | None:
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        rec = json.loads(line)
        event_id = int(rec.get("EventID", rec.get("Id", 0)))
        ts = _win_time(str(rec["TimeCreated"]))
    except (json.JSONDecodeError, KeyError, ValueError, TypeError, AttributeError):
        return None  # malformed record: skip it, never abort the scan
    action = _WIN_ACTIONS.get(event_id, "other")
    if action == "group_add":
        # In 4728/4732/4756 TargetUserName is the GROUP; the member is MemberName/MemberSid
        member = [v for v in (rec.get("MemberName"), rec.get("MemberSid")) if v not in (None, "", "-")]
        user, group = (member[0] if member else None), rec.get("TargetUserName")
    else:
        user, group = rec.get("TargetUserName"), None
    fields = {
        "event_id": event_id,
        "action": action,
        "user": user,
        "subject_user": rec.get("SubjectUserName"),
        "src_ip": rec.get("IpAddress"),
        "host": rec.get("Computer"),
        "logon_type": rec.get("LogonType"),
        "group": group,
        "process": rec.get("NewProcessName"),
        "command": rec.get("CommandLine"),
        "service": rec.get("ServiceName"),
    }
    fields = {k: v for k, v in fields.items() if v not in (None, "", "-")}
    return Event(ts, "windows", fields, line)


# ------------------------------------------------------------------------ dispatch

PARSERS: dict[str, Callable[[str, int], Event | None]] = {
    "auth": parse_auth_line,
    "web": parse_web_line,
    "windows": parse_windows_line,
}


def detect_format(lines: Iterable[str]) -> str | None:
    """Guess the format from the first few non-empty lines."""
    year = datetime.now().year
    sample = [ln for ln in lines if ln.strip()][:20]
    best, best_hits = None, 0
    for name, parser in PARSERS.items():
        hits = sum(1 for ln in sample if parser(ln, year) is not None)
        if hits > best_hits:
            best, best_hits = name, hits
    return best


def parse_file(path: str | Path, fmt: str | None = None, year: int | None = None) -> tuple[str, list[Event], int]:
    """Parse a log file. Returns ``(format, events, skipped_line_count)``."""
    path = Path(path)
    year = year or datetime.now().year
    # utf-8-sig strips the BOM that PowerShell 5.1 `Out-File -Encoding utf8` writes
    lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    fmt = fmt or detect_format(lines)
    if fmt not in PARSERS:
        raise ValueError(f"could not detect log format for {path} (use --format)")
    parser = PARSERS[fmt]
    events, skipped = [], 0
    year_offset, prev = 0, None
    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        ev = parser(line, year + year_offset)
        if ev is None:
            skipped += 1
            continue
        # Classic syslog has no year: a jump back of months (Dec 31 -> Jan 1)
        # means the log rolled into the next year.
        if fmt == "auth" and not line[:1].isdigit():
            if prev and ev.timestamp < prev - timedelta(days=180):
                year_offset += 1
                ev = parser(line, year + year_offset) or ev
            prev = ev.timestamp
        ev.line_no, ev.file = i, str(path)
        events.append(ev)
        # expand "message repeated N times" into N events so thresholds count them
        for _ in range(int(ev.fields.pop("repeat", 1)) - 1):
            events.append(Event(ev.timestamp, ev.source, dict(ev.fields), ev.raw, ev.line_no, ev.file))
    return fmt, events, skipped


def iter_events(paths: Iterable[str | Path], fmt: str | None = None, year: int | None = None) -> Iterator[Event]:
    for p in paths:
        yield from parse_file(p, fmt, year)[1]
