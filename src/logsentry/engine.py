"""Detection engine: runs rules over a time-ordered event stream.

Three rule types:

* **pattern**   - a single matching event is suspicious (SQL injection in a URL,
                  security log cleared). With ``group_by`` repeated hits from the
                  same group inside ``window`` are merged into one alert.
* **threshold** - at least ``threshold`` matching events (or ``distinct`` values of
                  a field) from one group inside a sliding ``window``
                  (SSH brute force, password spraying, directory scanning).
* **sequence**  - ordered steps from the same group inside ``window``
                  (many failed logins *followed by* a success = likely compromise).

Each burst produces one alert, so a 500-line brute force is one finding, not 100.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Iterable

from .events import Alert, Event
from .rules import SEVERITIES, Rule

MAX_EVIDENCE = 20


_MISSING = object()


def _group_key(rule: Rule, ev: Event):
    """Group value for ``ev``, None for ungrouped rules, or _MISSING when the
    event lacks the field (e.g. a console logon with no IP). Missing-key events
    are skipped so unrelated events never pile up in one bogus group."""
    if not rule.group_by:
        return None
    value = ev.get(rule.group_by)
    return _MISSING if value is None else str(value)


def _new_alert(rule: Rule, group: str | None, events: list[Event]) -> Alert:
    return Alert(
        rule_id=rule.id, title=rule.title, severity=rule.severity, mitre=rule.mitre,
        description=rule.description, group=group,
        first_seen=events[0].timestamp, last_seen=events[-1].timestamp,
        count=len(events), evidence=list(events[:MAX_EVIDENCE]), group_by=rule.group_by,
    )


def _extend(alert: Alert, ev: Event) -> None:
    alert.count += 1
    alert.last_seen = ev.timestamp
    if len(alert.evidence) < MAX_EVIDENCE:
        alert.evidence.append(ev)


def _run_windowed(rule: Rule, events: list[Event], threshold: int) -> list[Alert]:
    """Shared logic for pattern (threshold=1) and threshold rules."""
    alerts: list[Alert] = []
    windows: dict[str | None, deque[Event]] = defaultdict(deque)
    active: dict[str | None, Alert] = {}

    for ev in events:
        if not rule.matcher(ev):
            continue
        if rule.type == "pattern" and not rule.group_by:
            alerts.append(_new_alert(rule, None, [ev]))
            continue

        key = _group_key(rule, ev)
        if key is _MISSING:
            continue
        current = active.get(key)
        # still inside an ongoing burst: fold into the existing alert
        if current and ev.timestamp - current.last_seen <= rule.window:
            _extend(current, ev)
            continue
        active.pop(key, None)

        win = windows[key]
        win.append(ev)
        while win and ev.timestamp - win[0].timestamp > rule.window:
            win.popleft()

        if rule.distinct:
            score = len({e.get(rule.distinct) for e in win})
        else:
            score = len(win)
        if score >= threshold:
            alert = _new_alert(rule, key, list(win))
            alerts.append(alert)
            active[key] = alert
            win.clear()
    return alerts


def _run_sequence(rule: Rule, events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    n = len(rule.steps)
    # per group, per step: recent matching events
    state: dict[str | None, list[deque[Event]]] = defaultdict(lambda: [deque() for _ in range(n)])

    for ev in events:
        key = _group_key(rule, ev)
        if key is _MISSING:
            continue
        buckets = state[key]
        for bucket in buckets:
            while bucket and ev.timestamp - bucket[0].timestamp > rule.window:
                bucket.popleft()

        # walk steps from last to first so one event can complete a chain
        for idx in range(n - 1, -1, -1):
            step = rule.steps[idx]
            if not step.matcher(ev):
                continue
            if idx == 0:
                buckets[0].append(ev)
                break
            ready = all(len(buckets[j]) >= rule.steps[j].min_count for j in range(idx))
            if not ready:
                continue
            buckets[idx].append(ev)
            if idx == n - 1 and len(buckets[idx]) >= step.min_count:
                chain = sorted((e for b in buckets for e in b), key=lambda e: e.timestamp)
                alerts.append(_new_alert(rule, key, chain))
                for b in buckets:
                    b.clear()
            break
    return alerts


def run_rule(rule: Rule, events: list[Event]) -> list[Alert]:
    relevant = [e for e in events if e.source == rule.source]
    if rule.type == "pattern":
        return _run_windowed(rule, relevant, 1)
    if rule.type == "threshold":
        return _run_windowed(rule, relevant, rule.threshold)
    return _run_sequence(rule, relevant)


def detect(events: Iterable[Event], rules: Iterable[Rule], min_severity: str = "low") -> list[Alert]:
    """Run every rule and return alerts, most severe first, then by time."""
    ordered = sorted(events, key=lambda e: e.timestamp)
    floor = SEVERITIES.index(min_severity)
    alerts: list[Alert] = []
    for rule in rules:
        if SEVERITIES.index(rule.severity) < floor:
            continue
        alerts.extend(run_rule(rule, ordered))
    alerts.sort(key=lambda a: (-SEVERITIES.index(a.severity), a.first_seen))
    return alerts
