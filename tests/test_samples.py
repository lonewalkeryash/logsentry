"""End-to-end: every attack planted in samples/ is detected, and benign activity is not."""

import json
from pathlib import Path

import pytest

from logsentry.cli import main
from logsentry.engine import detect
from logsentry.parsers import parse_file
from logsentry.rules import load_rules

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
FILES = [SAMPLES / "auth.log", SAMPLES / "access.log", SAMPLES / "windows_security.jsonl"]


@pytest.fixture(scope="module")
def alerts():
    events = []
    for f in FILES:
        events += parse_file(f, year=2026)[1]
    return detect(events, load_rules())


def fired(alerts):
    return {(a.rule_id, a.group) for a in alerts}


@pytest.mark.parametrize("rule_id,group", [
    ("LS-AUTH-001", "203.0.113.45"),
    ("LS-AUTH-002", "198.51.100.23"),
    ("LS-AUTH-003", "203.0.113.45"),
    ("LS-AUTH-004", None),
    ("LS-AUTH-005", None),
    ("LS-AUTH-006", None),
    ("LS-AUTH-007", None),
    ("LS-WEB-001", "203.0.113.77"),
    ("LS-WEB-002", "198.51.100.9"),
    ("LS-WEB-003", "198.51.100.9"),
    ("LS-WEB-004", "203.0.113.77"),
    ("LS-WEB-005", "203.0.113.77"),
    ("LS-WEB-006", "203.0.113.77"),
    ("LS-WEB-007", "198.51.100.140"),
    ("LS-WIN-001", "203.0.113.200"),
    ("LS-WIN-002", "198.51.100.66"),
    ("LS-WIN-003", "203.0.113.200"),
    ("LS-WIN-004", None),
    ("LS-WIN-005", None),
    ("LS-WIN-006", None),
    ("LS-WIN-007", None),
    ("LS-WIN-008", None),
])
def test_planted_attack_detected(alerts, rule_id, group):
    assert (rule_id, group) in fired(alerts)


def test_benign_hosts_not_flagged(alerts):
    # 192.0.2.0/24 is normal traffic, except the deliberate root login from .50
    for a in alerts:
        if a.group and a.group.startswith("192.0.2."):
            pytest.fail(f"false positive {a.rule_id} on {a.group}")


def test_cli_json_and_exit_codes(capsys):
    code = main(["scan", *map(str, FILES), "--year", "2026", "--output", "json", "--fail-on", "critical"])
    assert code == 1
    data = json.loads(capsys.readouterr().out)
    assert data["stats"]["events"] > 400
    assert data["summary"]["critical"] >= 4


def test_cli_clean_file_exits_zero(tmp_path, capsys):
    clean = tmp_path / "auth.log"
    clean.write_text("Nov 14 08:00:01 web01 sshd[99]: Accepted publickey for alice from 192.0.2.10 port 5000 ssh2\n")
    assert main(["scan", str(clean), "--fail-on", "low"]) == 0
    assert "No threats detected" in capsys.readouterr().out


def test_cli_bad_file_exits_two(tmp_path):
    bad = tmp_path / "x.log"
    bad.write_text("garbage\n")
    assert main(["scan", str(bad)]) == 2
