"""Live mode: follow growing log files and alert (and optionally block) in real time.

Each poll reads the lines appended since the last poll, keeps a rolling buffer
as long as the longest rule window, and re-runs the detection engine on it.
Alerts that belong to a burst already reported are not printed again.

File rotation (logrotate renaming ``auth.log`` and creating a new one) and
truncation are detected and the new file is read from the start. Only the
standard library is used: the files are polled, not watched with inotify.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable

from .blocker import Responder
from .engine import detect
from .events import Alert, Event
from .parsers import PARSERS
from .rules import Rule

LIVE_FORMATS = ("auth", "web")


class Tail:
    """Return the complete lines appended to a file since the last call."""

    def __init__(self, path: str | Path, from_start: bool = False) -> None:
        self.path = Path(path)
        self.from_start = from_start
        self.pos: int | None = None
        self.ident: tuple[int, int] | None = None
        self.partial = ""
        self.missing_reported = False
        # fix the starting point now, so lines written before the first poll are kept
        try:
            st = os.stat(self.path)
            self.pos = 0 if from_start else st.st_size
            self.ident = (st.st_dev, st.st_ino)
        except FileNotFoundError:
            pass

    def read_lines(self) -> list[str]:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            if not self.missing_reported:
                print(f"[watch]   waiting for {self.path} to appear", file=sys.stderr)
                self.missing_reported = True
            # a file that appears (or comes back) later is new: read all of it
            if self.pos is None:
                self.from_start = True
            else:
                self.pos, self.ident, self.partial = 0, None, ""
            return []
        self.missing_reported = False
        ident = (st.st_dev, st.st_ino)
        if self.pos is None:
            self.pos = 0 if self.from_start else st.st_size
            self.ident = ident
        elif self.ident is None or ident != self.ident or st.st_size < self.pos:
            self.pos, self.ident, self.partial = 0, ident, ""  # rotated or truncated
        if st.st_size == self.pos:
            return []
        with open(self.path, "rb") as fh:
            fh.seek(self.pos)
            data = fh.read()
            self.pos = fh.tell()
        text = self.partial + data.decode("utf-8", errors="replace")
        lines = text.split("\n")
        self.partial = lines.pop()  # last piece has no newline yet
        if lines and lines[0].startswith("﻿"):
            lines[0] = lines[0][1:]
        return [ln.rstrip("\r") for ln in lines]


def format_alert(a: Alert) -> str:
    group = f" [{a.group}]" if a.group else ""
    mitre = f"  MITRE {', '.join(a.mitre)}" if a.mitre else ""
    return (f"{datetime.now():%H:%M:%S} {a.severity.upper():<8} {a.rule_id}  {a.title}{group}  "
            f"{a.count} event(s), log time {a.first_seen:%Y-%m-%d %H:%M:%S}{mitre}")


class Watcher:
    def __init__(
        self,
        paths: Iterable[str | Path],
        fmt: str,
        rules: list[Rule],
        *,
        min_severity: str = "low",
        from_start: bool = False,
        year: int | None = None,
        responder: Responder | None = None,
        on_alert: Callable[[Alert], None] | None = None,
    ) -> None:
        if fmt not in LIVE_FORMATS:
            raise ValueError(f"watch supports --format {' or '.join(LIVE_FORMATS)}")
        self.parser = PARSERS[fmt]
        self.tails = [Tail(p, from_start) for p in paths]
        self.rules = [r for r in rules if r.source == fmt]
        self.windows = {r.id: r.window for r in self.rules}
        self.retention = max((r.window for r in self.rules), default=timedelta(minutes=5)) + timedelta(minutes=1)
        self.min_severity = min_severity
        self.year = year
        self.responder = responder
        self.on_alert = on_alert or (lambda a: print(format_alert(a), flush=True))
        self.buffer: list[Event] = []
        self.reported: dict[tuple, datetime] = {}

    def _parse(self, tail: Tail) -> list[Event]:
        events = []
        year = self.year or datetime.now().year
        for line in tail.read_lines():
            if not line.strip():
                continue
            ev = self.parser(line, year)
            if ev is None:
                continue
            ev.file = str(tail.path)
            events.append(ev)
            for _ in range(int(ev.fields.pop("repeat", 1)) - 1):
                events.append(Event(ev.timestamp, ev.source, dict(ev.fields), ev.raw, 0, ev.file))
        return events

    def poll(self) -> list[Alert]:
        """Read new lines, run detection, and return alerts not reported before."""
        new = [ev for tail in self.tails for ev in self._parse(tail)]
        if not new:
            return []
        self.buffer.extend(new)
        alerts = detect(self.buffer, self.rules, self.min_severity)
        # trim only after detecting, so a big batch of new lines is judged as a whole
        cutoff = max(e.timestamp for e in self.buffer) - self.retention
        self.buffer = [e for e in self.buffer if e.timestamp >= cutoff]

        fresh = []
        for alert in alerts:
            if alert.group is not None:
                key: tuple = (alert.rule_id, alert.group)
            else:
                key = (alert.rule_id, alert.first_seen, alert.evidence[0].raw)
            seen = self.reported.get(key)
            if seen is not None and alert.first_seen <= seen + self.windows[alert.rule_id]:
                self.reported[key] = max(seen, alert.last_seen)  # same burst, still going
                continue
            self.reported[key] = alert.last_seen
            fresh.append(alert)
        # forget bursts that ended long ago
        self.reported = {k: v for k, v in self.reported.items() if v >= cutoff - self.retention}

        for alert in fresh:
            self.on_alert(alert)
        if self.responder and fresh:
            self.responder.handle(fresh)
        return fresh

    def run(self, interval: float = 1.0, jsonl: str | None = None) -> None:
        if jsonl:
            sink = open(jsonl, "a", encoding="utf-8")
            printer = self.on_alert

            def both(a: Alert) -> None:
                printer(a)
                sink.write(json.dumps(a.to_dict()) + "\n")
                sink.flush()
            self.on_alert = both
        names = ", ".join(str(t.path) for t in self.tails)
        print(f"[watch]   following {names} with {len(self.rules)} rules (Ctrl-C to stop)", file=sys.stderr, flush=True)
        last_expire = 0.0
        try:
            while True:
                self.poll()
                if self.responder and time.time() - last_expire >= 60:
                    self.responder.expire()
                    last_expire = time.time()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("[watch]   stopped", file=sys.stderr)
        finally:
            if jsonl:
                sink.close()
