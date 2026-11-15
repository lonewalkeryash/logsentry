"""Render alerts as a terminal report, JSON, or Markdown."""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from typing import Iterable

from .events import Alert
from .rules import SEVERITIES

_COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}
_RESET = "\033[0m"


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


def summary(alerts: Iterable[Alert]) -> dict[str, int]:
    counts = Counter(a.severity for a in alerts)
    return {sev: counts.get(sev, 0) for sev in reversed(SEVERITIES)}


def render_text(alerts: list[Alert], stats: dict, stream=None) -> str:
    stream = stream or sys.stdout
    color = _use_color(stream)
    out = []
    out.append(f"LogSentry scan - {stats['events']} events from {stats['files']} file(s), "
               f"{stats['rules']} rules, {stats['skipped']} unparsed lines")
    out.append("")
    if not alerts:
        out.append("No threats detected.")
        return "\n".join(out)
    for a in alerts:
        sev = a.severity.upper().ljust(8)
        if color:
            sev = f"{_COLORS[a.severity]}{sev}{_RESET}"
        who = f" [{a.group}]" if a.group else ""
        out.append(f"{sev} {a.rule_id}  {a.title}{who}")
        span = a.first_seen.strftime("%Y-%m-%d %H:%M:%S")
        if a.last_seen != a.first_seen:
            span += " -> " + a.last_seen.strftime("%H:%M:%S")
        out.append(f"         {a.count} event(s)  {span}  MITRE {', '.join(a.mitre)}")
        sample = a.evidence[-1]
        out.append(f"         e.g. {sample.file}:{sample.line_no}  {sample.raw.strip()[:110]}")
        out.append("")
    s = summary(alerts)
    out.append("Summary: " + ", ".join(f"{n} {sev}" for sev, n in s.items() if n) + f"  ({len(alerts)} alerts)")
    return "\n".join(out)


def render_json(alerts: list[Alert], stats: dict) -> str:
    return json.dumps(
        {"stats": stats, "summary": summary(alerts), "alerts": [a.to_dict() for a in alerts]},
        indent=2, default=str,
    )


def render_markdown(alerts: list[Alert], stats: dict) -> str:
    lines = ["# LogSentry report", "",
             f"Scanned **{stats['events']}** events from {stats['files']} file(s) with {stats['rules']} rules.", ""]
    if not alerts:
        return "\n".join(lines + ["No threats detected."])
    lines += ["| Severity | Rule | Title | Source | Events | First seen | MITRE ATT&CK |",
              "|---|---|---|---|---|---|---|"]
    for a in alerts:
        mitre = ", ".join(f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)" for t in a.mitre)
        lines.append(f"| {a.severity} | {a.rule_id} | {a.title} | {a.group or '-'} | {a.count} | "
                     f"{a.first_seen:%Y-%m-%d %H:%M:%S} | {mitre} |")
    return "\n".join(lines)


RENDERERS = {"text": render_text, "json": render_json, "markdown": render_markdown}
