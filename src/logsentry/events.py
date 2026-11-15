"""The normalised event every parser produces and every rule consumes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Event:
    """One log line, normalised.

    ``source`` is the log family (``auth``, ``web``, ``windows``).
    ``fields`` holds the parsed values rules match on, for example
    ``action``, ``src_ip``, ``user``, ``url``, ``status``.
    """

    timestamp: datetime
    source: str
    fields: dict[str, Any]
    raw: str
    line_no: int = 0
    file: str = ""

    def get(self, name: str, default: Any = None) -> Any:
        return self.fields.get(name, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "file": self.file,
            "line": self.line_no,
            "fields": self.fields,
            "raw": self.raw,
        }


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    mitre: list[str]
    description: str
    group: str | None
    first_seen: datetime
    last_seen: datetime
    count: int
    evidence: list[Event] = field(default_factory=list)
    group_by: str | None = None  # field the group value came from, e.g. "src_ip"

    def to_dict(self, max_evidence: int = 5) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "mitre": self.mitre,
            "description": self.description,
            "group": self.group,
            "group_by": self.group_by,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "evidence": [e.to_dict() for e in self.evidence[:max_evidence]],
        }
