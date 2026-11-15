"""Command-line interface.

    logsentry scan samples/auth.log samples/access.log
    logsentry scan /var/log/auth.log --format auth --output json --fail-on high
    logsentry scan /var/log/auth.log --block             # preview firewall blocks
    logsentry watch /var/log/auth.log --format auth --block --apply
    logsentry blocks | logsentry unblock 203.0.113.45
    logsentry rules -v
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .blocker import BACKENDS, BlockError, BlockState, Responder, _fmt_time, get_backend
from .engine import detect
from .parsers import PARSERS, parse_file
from .report import RENDERERS
from .rules import SEVERITIES, RuleError, load_rules, parse_window

EXIT_OK, EXIT_ALERTS, EXIT_ERROR = 0, 1, 2


def _load(args) -> list:
    rules = load_rules(args.rules) if args.rules else load_rules()
    if getattr(args, "extra_rules", None):
        rules += load_rules(args.extra_rules)
    return rules


def _responder(args) -> Responder | None:
    if args.apply and not args.block:
        raise ValueError("--apply only makes sense together with --block")
    if not args.block:
        return None
    ttl = parse_window(args.block_ttl) if args.block_ttl not in ("0", "never") else None
    return Responder(
        get_backend(args.firewall), apply=args.apply, min_severity=args.block_severity,
        allow=args.allow or [], ttl=ttl, max_blocks=args.max_blocks, state=BlockState(args.state),
    )


def cmd_scan(args) -> int:
    rules = _load(args)
    responder = _responder(args)
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

    if responder:
        responder.expire()
        responder.handle(alerts)

    if args.fail_on:
        floor = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(a.severity) >= floor for a in alerts):
            return EXIT_ALERTS
    return EXIT_OK


def cmd_watch(args) -> int:
    from .watch import Watcher

    rules = _load(args)
    responder = _responder(args)
    if responder:
        mode = "APPLY: blocks are enforced" if args.apply else "preview only, add --apply to enforce"
        print(f"[watch]   auto-block on {args.block_severity}+ alerts via {responder.backend.name} ({mode})",
              file=sys.stderr)
    watcher = Watcher(args.files, args.format, rules, min_severity=args.min_severity,
                      from_start=args.from_start, year=args.year, responder=responder)
    watcher.run(interval=args.interval, jsonl=args.jsonl)
    return EXIT_OK


def cmd_blocks(args) -> int:
    state = BlockState(args.state)
    if not state.blocks:
        print(f"no active blocks ({state.path})")
        return EXIT_OK
    print(f"{'IP':<40} {'RULE':<12} {'BACKEND':<9} {'BLOCKED':<17} EXPIRES")
    for ip, rec in sorted(state.blocks.items()):
        print(f"{ip:<40} {rec.get('rule', '?'):<12} {rec.get('backend', '?'):<9} "
              f"{_fmt_time(rec.get('blocked_at')):<17} {_fmt_time(rec.get('expires_at'))}")
    print(f"\n{len(state.blocks)} active block(s) in {state.path}")
    return EXIT_OK


def cmd_unblock(args) -> int:
    state = BlockState(args.state)
    responder = Responder(get_backend(args.firewall), apply=True, state=state, max_blocks=0)
    if args.expired:
        responder.expire()
        return EXIT_OK
    if not args.ips:
        raise ValueError("give one or more IPs to unblock, or --expired")
    ok = all([responder.unblock(ip) for ip in args.ips])
    return EXIT_OK if ok else EXIT_ERROR


def cmd_rules(args) -> int:
    rules = _load(args)
    for r in sorted(rules, key=lambda r: r.id):
        print(f"{r.id:<12} {r.severity:<9} {r.type:<10} {','.join(r.mitre):<22} {r.title}")
        if args.verbose and r.description:
            print(f"{'':<12} {r.description}\n")
    print(f"\n{len(rules)} rules loaded")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logsentry", description="Rule-based threat detection for security logs.")
    p.add_argument("--version", action="version", version=f"logsentry {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--rules", metavar="DIR", help="use rules from DIR instead of the built-in pack")
    common.add_argument("--extra-rules", metavar="DIR", help="load additional rules from DIR")

    block = argparse.ArgumentParser(add_help=False)
    g = block.add_argument_group("auto-block (response)")
    g.add_argument("--block", action="store_true",
                   help="block the source IP of high-severity attacks (preview unless --apply)")
    g.add_argument("--apply", action="store_true", help="actually change the firewall (needs admin/root)")
    g.add_argument("--firewall", choices=["auto", *sorted(BACKENDS)], default="auto",
                   help="firewall backend (default: netsh on Windows, iptables on Linux)")
    g.add_argument("--block-severity", choices=SEVERITIES, default="high",
                   help="lowest alert severity that triggers a block (default: high)")
    g.add_argument("--allow", action="append", metavar="CIDR",
                   help="never block this IP/network (repeatable); private ranges are always allowed")
    g.add_argument("--block-ttl", default="24h", metavar="DURATION",
                   help="lift blocks after this long, e.g. 30m, 24h, 7d; 0 = never (default: 24h)")
    g.add_argument("--max-blocks", type=int, default=50, help="cap on active blocks (default: 50)")
    state = argparse.ArgumentParser(add_help=False)
    state.add_argument("--state", metavar="FILE",
                       help="block state file (default: $LOGSENTRY_STATE or ~/.logsentry/blocks.json)")

    s = sub.add_parser("scan", parents=[common, block, state], help="scan log files for threats")
    s.add_argument("files", nargs="+", help="log files to scan")
    s.add_argument("-f", "--format", choices=sorted(PARSERS), help="log format (auto-detected if omitted)")
    s.add_argument("-o", "--output", choices=sorted(RENDERERS), default="text", help="report format")
    s.add_argument("--out", metavar="FILE", help="write the report to FILE")
    s.add_argument("--min-severity", choices=SEVERITIES, default="low", help="ignore rules below this severity")
    s.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any alert is at or above this severity (for CI)")
    s.add_argument("--year", type=int, help="year for syslog timestamps, which omit it (default: current)")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", parents=[common, block, state],
                       help="follow growing log files and alert in real time")
    w.add_argument("files", nargs="+", help="log files to follow (rotation is handled)")
    w.add_argument("-f", "--format", choices=["auth", "web"], required=True, help="log format")
    w.add_argument("--from-start", action="store_true", help="also process lines already in the files")
    w.add_argument("--interval", type=float, default=1.0, help="seconds between polls (default: 1)")
    w.add_argument("--jsonl", metavar="FILE", help="also append each alert as a JSON line to FILE")
    w.add_argument("--min-severity", choices=SEVERITIES, default="low", help="ignore rules below this severity")
    w.add_argument("--year", type=int, help="year for syslog timestamps (default: current)")
    w.set_defaults(func=cmd_watch)

    b = sub.add_parser("blocks", parents=[state], help="list IPs currently blocked by LogSentry")
    b.set_defaults(func=cmd_blocks)

    u = sub.add_parser("unblock", parents=[state], help="remove LogSentry firewall blocks")
    u.add_argument("ips", nargs="*", help="IP addresses to unblock")
    u.add_argument("--expired", action="store_true", help="remove every block whose TTL has passed")
    u.add_argument("--firewall", choices=["auto", *sorted(BACKENDS)], default="auto",
                   help="backend for IPs not in the state file (default: auto)")
    u.set_defaults(func=cmd_unblock)

    r = sub.add_parser("rules", parents=[common], help="list loaded detection rules")
    r.add_argument("-v", "--verbose", action="store_true", help="also show what each rule detects")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuleError, BlockError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
