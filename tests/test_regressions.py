"""Edge cases found in code review: real-world log quirks and evasion attempts."""

from datetime import datetime, timedelta

from logsentry.engine import detect
from logsentry.events import Event
from logsentry.parsers import parse_auth_line, parse_file, parse_web_line, parse_windows_line
from logsentry.rules import load_rules

RULES = {r.id: r for r in load_rules()}


def test_feb_29_in_non_leap_year_is_skipped_not_fatal():
    assert parse_auth_line("Feb 29 10:00:00 h sshd[1]: Failed password for root from 203.0.113.1 port 22 ssh2", 2026) is None


def test_username_cannot_spoof_source_ip():
    ev = parse_auth_line("Nov 14 02:13:00 h sshd[1]: Failed password for invalid user x from 10.0.0.1 "
                         "from 203.0.113.9 port 22 ssh2", 2026)
    assert ev.get("src_ip") == "203.0.113.9"
    assert ev.get("user") == "x from 10.0.0.1"


def test_username_with_spaces_still_detected():
    ev = parse_auth_line("Nov 14 02:13:00 h sshd[1]: Failed password for invalid user a b from 203.0.113.9 port 22 ssh2", 2026)
    assert ev.get("action") == "ssh_failed"
    assert ev.get("user") == "a b"


def test_rfc3339_syslog_timestamp_ubuntu_2404():
    ev = parse_auth_line("2026-11-14T10:00:00.123456+05:30 h sshd[1]: Accepted publickey for alice from 192.0.2.1 port 5 ssh2", 2026)
    assert ev.get("action") == "ssh_success"
    assert ev.timestamp == datetime(2026, 11, 14, 4, 30, 0, 123456)  # converted to UTC


def test_message_repeated_is_expanded(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text("Nov 14 02:13:00 h sshd[1]: message repeated 6 times: [ Failed password for root from 203.0.113.9 port 22 ssh2]\n")
    _, events, _ = parse_file(f, "auth", 2026)
    assert len(events) == 6
    assert len(detect(events, [RULES["LS-AUTH-001"]])) == 1


def test_syslog_year_rollover(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text("Dec 31 23:59:00 h sshd[1]: Accepted publickey for a from 192.0.2.1 port 5 ssh2\n"
                 "Jan  1 00:01:00 h sshd[1]: Accepted publickey for a from 192.0.2.1 port 5 ssh2\n")
    _, events, _ = parse_file(f, "auth", 2025)
    assert [e.timestamp.year for e in events] == [2025, 2026]


def test_web_timezone_is_normalised_to_utc():
    a = parse_web_line('192.0.2.1 - - [14/Nov/2026:10:00:00 +0100] "GET / HTTP/1.1" 200 1 "-" "x"')
    b = parse_web_line('192.0.2.1 - - [14/Nov/2026:09:30:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"')
    assert a.timestamp < b.timestamp


def test_escaped_quotes_in_user_agent_cannot_hide_scanner():
    ev = parse_web_line(r'192.0.2.1 - - [14/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x \"y\" sqlmap/1.7"')
    assert "sqlmap" in ev.get("user_agent")


def test_real_4732_schema_detected():
    ev = parse_windows_line('{"TimeCreated": "2026-11-14T01:00:00Z", "EventID": 4732, "TargetUserName": "Administrators", '
                            '"MemberName": "-", "MemberSid": "S-1-5-21-1-2-3-1003"}')
    assert ev.get("group") == "Administrators"
    assert ev.get("user") == "S-1-5-21-1-2-3-1003"
    assert len(detect([ev], [RULES["LS-WIN-006"]])) == 1


def test_events_without_group_field_are_not_lumped_together():
    t = datetime(2026, 11, 14)
    events = [Event(t + timedelta(seconds=i), "windows", {"event_id": 4625, "user": f"u{i}"}, "") for i in range(10)]
    assert detect(events, [RULES["LS-WIN-001"], RULES["LS-WIN-002"]]) == []


def _web(url, status=200):
    return parse_web_line(f'192.0.2.1 - - [14/Nov/2026:10:00:00 +0000] "GET {url} HTTP/1.1" {status} 1 "-" "x"')


def test_web_shell_rule_ignores_normal_command_params():
    assert detect([_web("/admin/jobs?command=status")], [RULES["LS-WEB-006"]]) == []
    assert detect([_web("/api?exec=report&id=4")], [RULES["LS-WEB-006"]]) == []
    assert len(detect([_web("/up/img.php?cmd=whoami")], [RULES["LS-WEB-006"]])) == 1


def test_web_login_rule_ignores_oauth_paths():
    r = RULES["LS-WEB-007"]
    assert not r.matcher(parse_web_line('192.0.2.1 - - [14/Nov/2026:10:00:00 +0000] "POST /oauth/token HTTP/1.1" 401 1 "-" "x"'))
    assert r.matcher(parse_web_line('192.0.2.1 - - [14/Nov/2026:10:00:00 +0000] "POST /auth HTTP/1.1" 401 1 "-" "x"'))
