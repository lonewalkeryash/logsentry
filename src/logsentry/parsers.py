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
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator
from urllib.parse import unquote_plus

from .events import Event

# --------------------------------------------------------------------------- auth

_SYSLOG = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

# (compiled regex, action name) - first match wins
_AUTH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>[\d.:a-fA-F]+)"), "ssh_failed"),
    (re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src_ip>[\d.:a-fA-F]+)"), "ssh_success"),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<src_ip>[\d.:a-fA-F]+)"), "ssh_invalid_user"),
    (re.compile(r"^\s*(?P<user>\S+) : .*USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.+)$"), "sudo"),
    (re.compile(r"new user: name=(?P<user>[^,\s]+)"), "user_created"),
    (re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'"), "group_add"),
]

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def parse_auth_line(line: str, year: int) -> Event | None:
    m = _SYSLOG.match(line)
    if not m:
        return None
    h, mi, s = (int(x) for x in m["time"].split(":"))
    ts = datetime(year, _MONTHS[m["month"]], int(m["day"]), h, mi, s)
    msg = m["msg"]
    fields: dict = {"host": m["host"], "process": m["proc"], "action": "other", "message": msg}
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
    r'(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)


def parse_web_line(line: str, year: int | None = None) -> Event | None:
    m = _COMBINED.match(line)
    if not m:
        return None
    ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
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
    4732: "group_add",
    4728: "group_add",
    1102: "log_cleared",
    4688: "process_created",
    7045: "service_installed",
}


def _win_time(value: str) -> datetime:
    # Accept ISO-8601 ("2026-11-14T22:01:05Z") or PowerShell's "/Date(1731621665000)/"
    m = re.match(r"/Date\((\d+)\)/", value)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc).replace(tzinfo=None)
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)


def parse_windows_line(line: str, year: int | None = None) -> Event | None:
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    event_id = int(rec.get("EventID", rec.get("Id", 0)))
    fields = {
        "event_id": event_id,
        "action": _WIN_ACTIONS.get(event_id, "other"),
        "user": rec.get("TargetUserName"),
        "subject_user": rec.get("SubjectUserName"),
        "src_ip": rec.get("IpAddress"),
        "host": rec.get("Computer"),
        "logon_type": rec.get("LogonType"),
        "group": rec.get("TargetGroupName") or rec.get("GroupName"),
        "process": rec.get("NewProcessName"),
        "command": rec.get("CommandLine"),
        "service": rec.get("ServiceName"),
    }
    fields = {k: v for k, v in fields.items() if v not in (None, "", "-")}
    return Event(_win_time(rec["TimeCreated"]), "windows", fields, line)


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
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    fmt = fmt or detect_format(lines)
    if fmt not in PARSERS:
        raise ValueError(f"could not detect log format for {path} (use --format)")
    parser = PARSERS[fmt]
    events, skipped = [], 0
    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        ev = parser(line, year)
        if ev is None:
            skipped += 1
            continue
        ev.line_no, ev.file = i, str(path)
        events.append(ev)
    return fmt, events, skipped


def iter_events(paths: Iterable[str | Path], fmt: str | None = None, year: int | None = None) -> Iterator[Event]:
    for p in paths:
        yield from parse_file(p, fmt, year)[1]
