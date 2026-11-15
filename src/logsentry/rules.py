"""Loading and validating YAML detection rules.

A rule file looks like::

    id: LS-AUTH-001
    title: SSH brute force
    severity: high              # low | medium | high | critical
    mitre: [T1110.001]
    source: auth                # auth | web | windows
    type: threshold             # pattern | threshold | sequence
    match:
      action: ssh_failed
    group_by: src_ip
    threshold: 5
    window: 5m

Match conditions (all must hold):

* ``field: value``            - equality
* ``field: [a, b]``           - value is one of the list
* ``field: {regex: "..."}``   - case-insensitive regex search
* ``field: {gte: 400}``       - numeric comparisons (gte, lte, gt, lt)
* ``field: {exists: true}``   - field is present
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .events import Event

SEVERITIES = ["low", "medium", "high", "critical"]
RULE_TYPES = {"pattern", "threshold", "sequence"}
SOURCES = {"auth", "web", "windows"}


class RuleError(ValueError):
    pass


def parse_window(value: str | int) -> timedelta:
    """'90s', '5m', '1h' -> timedelta. Bare ints are seconds."""
    if isinstance(value, int):
        return timedelta(seconds=value)
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(value).strip())
    if not m:
        raise RuleError(f"bad window {value!r} (use e.g. 30s, 5m, 1h)")
    n, unit = int(m.group(1)), m.group(2)
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: n})


class Matcher:
    """Compiled form of a rule's ``match:`` block."""

    def __init__(self, spec: dict[str, Any] | None):
        self.checks: list[tuple[str, Any]] = []
        for name, cond in (spec or {}).items():
            self.checks.append((name, self._compile(name, cond)))

    @staticmethod
    def _compile(name: str, cond: Any):
        if isinstance(cond, list):
            allowed = set(cond)
            return lambda v: v in allowed
        if isinstance(cond, dict):
            tests = []
            for op, arg in cond.items():
                if op == "regex":
                    rx = re.compile(arg, re.IGNORECASE)
                    tests.append(lambda v, rx=rx: v is not None and rx.search(str(v)) is not None)
                elif op in ("gte", "lte", "gt", "lt"):
                    cmp = {"gte": float.__ge__, "lte": float.__le__, "gt": float.__gt__, "lt": float.__lt__}[op]
                    tests.append(lambda v, a=float(arg), c=cmp: isinstance(v, (int, float)) and c(float(v), a))
                elif op == "exists":
                    tests.append(lambda v, want=bool(arg): (v is not None) == want)
                else:
                    raise RuleError(f"unknown operator {op!r} on field {name!r}")
            return lambda v: all(t(v) for t in tests)
        return lambda v: v == cond

    def __call__(self, event: Event) -> bool:
        return all(test(event.get(name)) for name, test in self.checks)


@dataclass
class Step:
    matcher: Matcher
    min_count: int = 1


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    source: str
    type: str
    description: str = ""
    mitre: list[str] = field(default_factory=list)
    matcher: Matcher | None = None
    group_by: str | None = None
    threshold: int = 1
    distinct: str | None = None
    window: timedelta = timedelta(minutes=5)
    steps: list[Step] = field(default_factory=list)
    path: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any], path: str = "") -> "Rule":
        where = path or d.get("id", "<rule>")
        for key in ("id", "title", "severity", "source", "type"):
            if key not in d:
                raise RuleError(f"{where}: missing required key {key!r}")
        if d["severity"] not in SEVERITIES:
            raise RuleError(f"{where}: severity must be one of {SEVERITIES}")
        if d["type"] not in RULE_TYPES:
            raise RuleError(f"{where}: type must be one of {sorted(RULE_TYPES)}")
        if d["source"] not in SOURCES:
            raise RuleError(f"{where}: source must be one of {sorted(SOURCES)}")

        rule = cls(
            id=d["id"], title=d["title"], severity=d["severity"], source=d["source"], type=d["type"],
            description=str(d.get("description", "")).strip(),
            mitre=list(d.get("mitre", [])),
            group_by=d.get("group_by"),
            threshold=int(d.get("threshold", 1)),
            distinct=d.get("distinct"),
            window=parse_window(d.get("window", "5m")),
            path=path,
        )
        if rule.type in ("pattern", "threshold"):
            if "match" not in d:
                raise RuleError(f"{where}: {rule.type} rule needs a 'match' block")
            rule.matcher = Matcher(d["match"])
        if rule.type == "threshold" and not rule.group_by:
            raise RuleError(f"{where}: threshold rule needs 'group_by'")
        if rule.type == "sequence":
            steps = d.get("steps") or []
            if len(steps) < 2:
                raise RuleError(f"{where}: sequence rule needs at least 2 steps")
            if not rule.group_by:
                raise RuleError(f"{where}: sequence rule needs 'group_by'")
            rule.steps = [Step(Matcher(s.get("match")), int(s.get("min_count", 1))) for s in steps]
        return rule


def load_rules(directory: str | Path | None = None) -> list[Rule]:
    """Load every ``*.yml`` rule from ``directory`` (default: the built-in rule pack)."""
    if directory is None:
        files = sorted(
            (p for p in resources.files("logsentry").joinpath("rules").iterdir() if p.name.endswith(".yml")),
            key=lambda p: p.name,
        )
    else:
        files = sorted(Path(directory).glob("*.yml"))
    rules, seen = [], set()
    for f in files:
        docs = [doc for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")) if doc]
        for doc in docs:
            rule = Rule.from_dict(doc, path=f.name)
            if rule.id in seen:
                raise RuleError(f"{f.name}: duplicate rule id {rule.id}")
            seen.add(rule.id)
            rules.append(rule)
    return rules
