"""Measure scan throughput on a large synthetic auth log.

    python scripts/benchmark.py [lines]

Prints lines/second for parse + detect with the built-in rule pack.
"""

from __future__ import annotations

import random
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

from logsentry.engine import detect
from logsentry.parsers import parse_file
from logsentry.rules import load_rules


def make_log(path: Path, n: int) -> None:
    rng = random.Random(7)
    t = datetime(2026, 11, 14)
    with path.open("w", encoding="utf-8") as f:
        for i in range(n):
            t += timedelta(milliseconds=rng.randint(50, 900))
            ip = f"203.0.113.{rng.randint(1, 254)}" if rng.random() < 0.3 else f"192.0.2.{rng.randint(1, 254)}"
            if rng.random() < 0.3:
                msg = f"Failed password for {rng.choice(['root', 'admin', 'deploy'])} from {ip} port {rng.randint(1024, 65535)} ssh2"
            else:
                msg = f"Accepted publickey for alice from {ip} port {rng.randint(1024, 65535)} ssh2"
            f.write(f"{t:%b} {t.day:>2} {t:%H:%M:%S} web01 sshd[{1000 + i % 9000}]: {msg}\n")


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
    rules = load_rules()
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "bench_auth.log"
        make_log(path, n)
        start = time.perf_counter()
        _, events, _ = parse_file(path, "auth", 2026)
        parsed = time.perf_counter()
        alerts = detect(events, rules)
        done = time.perf_counter()
    print(f"lines:   {n:,}")
    print(f"parse:   {parsed - start:.2f}s")
    print(f"detect:  {done - parsed:.2f}s  ({len(alerts)} alerts)")
    print(f"total:   {done - start:.2f}s  -> {n / (done - start):,.0f} lines/sec")


if __name__ == "__main__":
    main()
