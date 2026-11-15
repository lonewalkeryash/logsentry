from datetime import datetime

from logsentry.parsers import detect_format, parse_auth_line, parse_web_line, parse_windows_line


def test_auth_failed_password_invalid_user():
    ev = parse_auth_line("Nov 14 02:13:00 web01 sshd[1201]: Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2", 2026)
    assert ev.timestamp == datetime(2026, 11, 14, 2, 13, 0)
    assert ev.get("action") == "ssh_failed"
    assert ev.get("user") == "admin"
    assert ev.get("src_ip") == "203.0.113.5"


def test_auth_accepted():
    ev = parse_auth_line("Nov  4 08:00:01 web01 sshd[99]: Accepted publickey for alice from 192.0.2.10 port 5000 ssh2", 2026)
    assert ev.get("action") == "ssh_success"
    assert ev.timestamp.day == 4


def test_auth_sudo():
    ev = parse_auth_line("Nov 14 02:17:10 web01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash", 2026)
    assert ev.get("action") == "sudo"
    assert ev.get("user") == "deploy"
    assert ev.get("target_user") == "root"
    assert ev.get("command") == "/bin/bash"


def test_auth_unrelated_line_is_other():
    ev = parse_auth_line("Nov 14 02:17:10 web01 CRON[5]: pam_unix(cron:session): session opened", 2026)
    assert ev.get("action") == "other"


def test_auth_garbage_returns_none():
    assert parse_auth_line("not a syslog line", 2026) is None


def test_web_combined_and_url_decoding():
    line = ('203.0.113.77 - - [14/Nov/2026:01:20:06 +0000] "GET /products?id=42%27%20OR%20%271%27%3D%271 HTTP/1.1" '
            '200 512 "-" "sqlmap/1.8"')
    ev = parse_web_line(line)
    assert ev.get("status") == 200
    assert ev.get("method") == "GET"
    assert "' OR '1'='1" in ev.get("url_decoded")
    assert ev.get("user_agent") == "sqlmap/1.8"


def test_windows_json():
    ev = parse_windows_line('{"TimeCreated": "2026-11-14T01:45:00Z", "EventID": 4625, "TargetUserName": "Administrator", "IpAddress": "203.0.113.200"}')
    assert ev.get("action") == "logon_failed"
    assert ev.get("user") == "Administrator"
    assert ev.timestamp == datetime(2026, 11, 14, 1, 45)


def test_windows_powershell_date_format():
    ev = parse_windows_line('{"TimeCreated": "/Date(1731548700000)/", "Id": 1102}')
    assert ev.get("action") == "log_cleared"


def test_windows_dotnet_seven_digit_fraction():
    ev = parse_windows_line('{"TimeCreated": "2026-11-15T01:33:59.5757713Z", "EventID": 4624}')
    assert ev.timestamp == datetime(2026, 11, 15, 1, 33, 59, 575771)


def test_windows_malformed_records_skipped():
    assert parse_windows_line('{"EventID": 4624}') is None              # no TimeCreated
    assert parse_windows_line('{"TimeCreated": "yesterday", "EventID": 1}') is None
    assert parse_windows_line('{"TimeCreated": "2026-11-15T01:00:00Z", "EventID": "abc"}') is None
    assert parse_windows_line('{not json') is None


def test_powershell_bom_file(tmp_path):
    from logsentry.parsers import parse_file
    f = tmp_path / "sec.jsonl"
    f.write_bytes(b"\xef\xbb\xbf" + b'{"TimeCreated": "2026-11-15T01:00:00Z", "EventID": 1102}\r\n')
    fmt, events, skipped = parse_file(f)
    assert (fmt, len(events), skipped) == ("windows", 1, 0)


def test_detect_format():
    assert detect_format(["Nov 14 02:13:00 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"]) == "auth"
    assert detect_format(['192.0.2.1 - - [14/Nov/2026:01:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "x"']) == "web"
    assert detect_format(['{"TimeCreated": "2026-11-14T01:45:00Z", "EventID": 4624}']) == "windows"
    assert detect_format(["hello world"]) is None
