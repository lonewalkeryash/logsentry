"""Command-line interface.

    logsentry scan samples/auth.log samples/access.log
    logsentry scan /var/log/auth.log --format auth --output json --fail-on high
    logsentry rules
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import detect
from .parsers import PARSERS, parse_file
from .report import RENDERERS
from .rules import SEVERITIES, RuleError, load_rules

EXIT_OK, EXIT_ALERTS, EXIT_ERROR = 0, 1, 2


def _load(args) -> list:
    rules = load_rules(args.rules) if args.rules else load_rules()
    if getattr(args, "extra_rules", None):
        rules += load_rules(args.extra_rules)
    return rules


def cmd_scan(args) -> int:
    rules = _load(args)
    events, skipped = [], 0
    for path in args.files:
        fmt, evs, skip = parse_file(path, args.format, args.year)
        print(f"[+] {path}: {len(evs)} events ({fmt})", file=sys.stderr)
        events += evs
        skipped += skip
    alerts = detect(events, rules, min_severity=args.min_severity)
    stats = {"files": len(args.files), "events": len(events), "rules": len(rules), "skipped": skipped}

    rendered = RENDERERS[args.output](alerts, stats)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
        print(f"[+] report written to {args.out}", file=sys.stderr)
    else:
        print(rendered)

    if args.fail_on:
        floor = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(a.severity) >= floor for a in alerts):
            return EXIT_ALERTS
    return EXIT_OK


def cmd_rules(args) -> int:
    rules = _load(args)
    for r in sorted(rules, key=lambda r: r.id):
        print(f"{r.id:<12} {r.severity:<9} {r.type:<10} {','.join(r.mitre):<22} {r.title}")
    print(f"\n{len(rules)} rules loaded")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logsentry", description="Rule-based threat detection for security logs.")
    p.add_argument("--version", action="version", version=f"logsentry {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--rules", metavar="DIR", help="use rules from DIR instead of the built-in pack")
    common.add_argument("--extra-rules", metavar="DIR", help="load additional rules from DIR")

    s = sub.add_parser("scan", parents=[common], help="scan log files for threats")
    s.add_argument("files", nargs="+", help="log files to scan")
    s.add_argument("-f", "--format", choices=sorted(PARSERS), help="log format (auto-detected if omitted)")
    s.add_argument("-o", "--output", choices=sorted(RENDERERS), default="text", help="report format")
    s.add_argument("--out", metavar="FILE", help="write the report to FILE")
    s.add_argument("--min-severity", choices=SEVERITIES, default="low", help="ignore rules below this severity")
    s.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any alert is at or above this severity (for CI)")
    s.add_argument("--year", type=int, help="year for syslog timestamps, which omit it (default: current)")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rules", parents=[common], help="list loaded detection rules")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
