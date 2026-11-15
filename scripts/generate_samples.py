"""Generate the synthetic sample logs in ``samples/``.

All IPs come from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and all hosts/users are made up, so the
samples are safe to publish. Output is deterministic (fixed seed).

    python scripts/generate_samples.py
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
rng = random.Random(1337)
BASE = datetime(2026, 11, 14, 0, 0, 0)

NORMAL_IPS = [f"192.0.2.{n}" for n in (10, 11, 14, 22, 31, 40)]
NORMAL_USERS = ["alice", "bob", "carol", "dave"]


def syslog(ts: datetime, proc: str, msg: str, host: str = "web01") -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {host} {proc}: {msg}"


def auth_log() -> list[str]:
    lines: list[tuple[datetime, str]] = []
    pid = 1000

    def add(ts, proc, msg):
        nonlocal pid
        pid += 1
        lines.append((ts, syslog(ts, proc.replace("PID", str(pid)), msg)))

    # background: normal logins and admin work through the day
    for _ in range(40):
        ts = BASE + timedelta(hours=rng.randint(7, 19), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        user, ip = rng.choice(NORMAL_USERS), rng.choice(NORMAL_IPS)
        add(ts, "sshd[PID]", f"Accepted publickey for {user} from {ip} port {rng.randint(40000, 65000)} ssh2")
        if rng.random() < 0.3:
            add(ts + timedelta(minutes=2), "sudo", f"  {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update")
    # a couple of honest typos
    for _ in range(3):
        ts = BASE + timedelta(hours=rng.randint(8, 17), minutes=rng.randint(0, 59))
        add(ts, "sshd[PID]", f"Failed password for carol from 192.0.2.14 port 51200 ssh2")

    # ATTACK 1: brute force from 203.0.113.45, then success -> privilege escalation -> persistence
    t = BASE + timedelta(hours=2, minutes=13)
    for i in range(14):
        user = "root" if i % 2 else "deploy"
        add(t + timedelta(seconds=4 * i), "sshd[PID]", f"Failed password for {user} from 203.0.113.45 port {50000 + i} ssh2")
    t = t + timedelta(seconds=70)
    add(t, "sshd[PID]", "Accepted password for deploy from 203.0.113.45 port 50099 ssh2")
    add(t + timedelta(minutes=3), "sudo", "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
    add(t + timedelta(minutes=4), "useradd[PID]", "new user: name=sysupdate, UID=1002, GID=1002, home=/home/sysupdate, shell=/bin/bash")
    add(t + timedelta(minutes=4, seconds=20), "usermod[PID]", "add 'sysupdate' to group 'sudo'")

    # ATTACK 2: password spraying from 198.51.100.23
    t = BASE + timedelta(hours=4, minutes=40)
    for i, user in enumerate(["test", "oracle", "postgres", "ubuntu", "guest", "ftp"]):
        add(t + timedelta(seconds=20 * i), "sshd[PID]", f"Invalid user {user} from 198.51.100.23 port {41000 + i}")
        add(t + timedelta(seconds=20 * i + 1), "sshd[PID]", f"Failed password for invalid user {user} from 198.51.100.23 port {41000 + i} ssh2")

    # MISCONFIG: direct root login
    add(BASE + timedelta(hours=21, minutes=5), "sshd[PID]", "Accepted password for root from 192.0.2.50 port 60122 ssh2")

    lines.sort(key=lambda x: x[0])
    return [ln for _, ln in lines]


def web_log() -> list[str]:
    lines: list[tuple[datetime, str]] = []
    pages = ["/", "/index.html", "/about", "/products", "/products/42", "/contact", "/static/app.css", "/static/app.js"]
    browsers = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    ]

    def add(ts, ip, method, url, status, ua, size=None):
        size = size if size is not None else rng.randint(300, 9000)
        lines.append((ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {url} HTTP/1.1" {status} {size} "-" "{ua}"'))

    for _ in range(250):
        ts = BASE + timedelta(seconds=rng.randint(0, 86399))
        add(ts, rng.choice(NORMAL_IPS), "GET", rng.choice(pages), 200, rng.choice(browsers))
    for _ in range(8):  # a few real broken links
        ts = BASE + timedelta(seconds=rng.randint(0, 86399))
        add(ts, rng.choice(NORMAL_IPS), "GET", "/old-page", 404, rng.choice(browsers), 0)

    # ATTACK: directory brute force with gobuster
    t = BASE + timedelta(hours=1, minutes=2)
    words = ["admin", "backup", "config", ".git/HEAD", ".env", "wp-admin", "phpmyadmin", "test", "dev", "old",
             "api", "uploads", "private", "db", "sql", "logs", "tmp", "server-status", "console", "cgi-bin",
             "includes", "secret", "staging", "debug", "panel"]
    for i, w in enumerate(words):
        add(t + timedelta(seconds=i), "203.0.113.77", "GET", f"/{w}", 200 if w == "uploads" else 404, "gobuster/3.6", 0)

    # ATTACK: sqlmap against a product page
    t = BASE + timedelta(hours=1, minutes=20)
    payloads = ["42%27", "42%20AND%201%3D1", "42%27%20OR%20%271%27%3D%271", "42%20UNION%20ALL%20SELECT%20NULL%2CNULL--",
                "42%20AND%20SLEEP(5)", "42%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--"]
    for i, p in enumerate(payloads):
        add(t + timedelta(seconds=3 * i), "203.0.113.77", "GET", f"/products?id={p}", 500 if i % 2 else 200,
            "sqlmap/1.8.11#stable (https://sqlmap.org)")

    # ATTACK: path traversal + XSS from another IP
    t = BASE + timedelta(hours=3, minutes=5)
    add(t, "198.51.100.9", "GET", "/download?file=../../../../etc/passwd", 403, browsers[2])
    add(t + timedelta(seconds=5), "198.51.100.9", "GET", "/download?file=..%2F..%2F..%2Fwindows%2Fwin.ini", 403, browsers[2])
    add(t + timedelta(seconds=30), "198.51.100.9", "GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", 200, browsers[2])

    # ATTACK: login brute force
    t = BASE + timedelta(hours=5, minutes=30)
    for i in range(15):
        add(t + timedelta(seconds=6 * i), "198.51.100.140", "POST", "/login", 401, "python-requests/2.32.3", 120)

    # ATTACK: uploaded web shell being used
    t = BASE + timedelta(hours=6, minutes=1)
    for i, c in enumerate(["id", "whoami", "uname%20-a", "cat%20/etc/passwd"]):
        add(t + timedelta(seconds=10 * i), "203.0.113.77", "GET", f"/uploads/shell.php?cmd={c}", 200, "curl/8.5.0", 64)

    lines.sort(key=lambda x: x[0])
    return [ln for _, ln in lines]


def windows_log() -> list[str]:
    recs: list[dict] = []

    def add(ts, event_id, **kw):
        recs.append({"TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "EventID": event_id, "Computer": "WS-FIN-07", **kw})

    for _ in range(30):
        ts = BASE + timedelta(hours=rng.randint(8, 18), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        add(ts, 4624, TargetUserName=rng.choice(NORMAL_USERS), IpAddress=rng.choice(NORMAL_IPS), LogonType=3)

    # ATTACK: RDP brute force on Administrator then success
    t = BASE + timedelta(hours=1, minutes=45)
    for i in range(8):
        add(t + timedelta(seconds=5 * i), 4625, TargetUserName="Administrator", IpAddress="203.0.113.200", LogonType=10)
    t += timedelta(seconds=60)
    add(t, 4624, TargetUserName="Administrator", IpAddress="203.0.113.200", LogonType=10)
    # post-exploitation
    add(t + timedelta(minutes=2), 4688, SubjectUserName="Administrator", NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA")
    add(t + timedelta(minutes=3), 4720, SubjectUserName="Administrator", TargetUserName="svc_backup")
    # real 4732 schema: TargetUserName is the group, MemberSid/MemberName the account added
    add(t + timedelta(minutes=3, seconds=10), 4732, SubjectUserName="Administrator", TargetUserName="Administrators",
        MemberName="-", MemberSid="S-1-5-21-1004336348-1177238915-682003330-1003")
    add(t + timedelta(minutes=5), 7045, ServiceName="WinUpdateHelper")
    add(t + timedelta(minutes=9), 1102, SubjectUserName="Administrator")

    # ATTACK: password spray from another IP
    t = BASE + timedelta(hours=10, minutes=10)
    for i, user in enumerate(["jsmith", "mlee", "akumar", "tgarcia", "pwhite", "hr.admin"]):
        add(t + timedelta(seconds=30 * i), 4625, TargetUserName=user, IpAddress="198.51.100.66", LogonType=3)

    recs.sort(key=lambda r: r["TimeCreated"])
    return [json.dumps(r) for r in recs]


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, gen in [("auth.log", auth_log), ("access.log", web_log), ("windows_security.jsonl", windows_log)]:
        lines = gen()
        (OUT / name).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote samples/{name} ({len(lines)} lines)")


if __name__ == "__main__":
    main()
