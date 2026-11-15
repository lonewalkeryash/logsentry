import io
from datetime import datetime, timedelta

import pytest

from logsentry.blocker import (BlockError, BlockState, IptablesBackend, NetshBackend, Responder,
                               get_backend, parse_ip)
from logsentry.cli import main
from logsentry.events import Alert

T = datetime(2026, 11, 14, 2, 0, 0)


def alert(group="203.0.113.45", severity="critical", group_by="src_ip", rule_id="LS-AUTH-003"):
    return Alert(rule_id, "test", severity, ["T1110"], "", group, T, T, 1, [], group_by)


class FakeFirewall:
    """Pretend iptables: remembers rules, answers -C / -L checks."""

    def __init__(self, fail=False):
        self.calls, self.rules, self.chains, self.fail = [], set(), set(), fail

    def __call__(self, cmd):
        cmd = list(cmd)
        self.calls.append(cmd)
        if self.fail and cmd[1] == "-A":
            return 1, "Permission denied (you must be root)"
        op, rest = cmd[1], tuple(cmd[2:])
        if op == "-L":
            return (0, "") if cmd[3] in self.chains else (1, "no chain")
        if op == "-N":
            self.chains.add(cmd[2])
            return 0, ""
        if op == "-C":
            return (0, "") if rest in self.rules else (1, "")
        if op in ("-A", "-I"):
            self.rules.add(rest if op == "-A" else (rest[0], *rest[2:]))
            return 0, ""
        if op == "-D":
            self.rules.discard(rest)
            return 0, ""
        return 1, "unexpected"


def responder(tmp_path, run=None, **kw):
    kw.setdefault("apply", True)
    return Responder(IptablesBackend(), state=BlockState(tmp_path / "s.json"), run=run or FakeFirewall(),
                     out=io.StringIO(), **kw)


def test_parse_ip_rejects_injection():
    assert str(parse_ip("203.0.113.45")) == "203.0.113.45"
    assert str(parse_ip("::ffff:203.0.113.5")) == "203.0.113.5"
    for bad in ["203.0.113.45; rm -rf /", "-j ACCEPT", "1.2.3.4 -j ACCEPT", "example.com", "", None, "?"]:
        assert parse_ip(bad) is None


def test_apply_blocks_and_records(tmp_path):
    fw = FakeFirewall()
    r = responder(tmp_path, run=fw)
    [d] = r.handle([alert()])
    assert d.action == "blocked"
    assert ("LOGSENTRY", "-s", "203.0.113.45", "-j", "DROP") in fw.rules
    assert ("INPUT", "-j", "LOGSENTRY") in fw.rules          # chain hooked into INPUT
    assert "203.0.113.45" in BlockState(tmp_path / "s.json").blocks  # persisted
    # every call is an argv list, never a shell string
    assert all(isinstance(c, list) for c in fw.calls)


def test_same_ip_blocked_once(tmp_path):
    fw = FakeFirewall()
    r = responder(tmp_path, run=fw)
    r.handle([alert(), alert(rule_id="LS-AUTH-001", severity="high")])
    assert sum(1 for c in fw.calls if c[1] == "-A") == 1


def test_preview_changes_nothing(tmp_path):
    fw = FakeFirewall()
    r = responder(tmp_path, run=fw, apply=False)
    [d] = r.handle([alert()])
    assert d.action == "would-block"
    assert fw.calls == []
    assert not (tmp_path / "s.json").exists()
    assert "iptables -A LOGSENTRY -s 203.0.113.45 -j DROP" in r.out.getvalue()


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "192.168.1.10", "172.20.0.5", "100.64.1.1",
                                "169.254.1.1", "::1", "fe80::1", "fd00::5"])
def test_private_and_local_never_blocked(tmp_path, ip):
    fw = FakeFirewall()
    [d] = responder(tmp_path, run=fw).handle([alert(group=ip)])
    assert d.action == "skipped" and d.reason == "allowlisted"
    assert fw.calls == []


def test_documentation_ranges_are_blockable(tmp_path):
    # Python's is_private covers RFC 5737; we must not rely on it
    [d] = responder(tmp_path).handle([alert(group="198.51.100.23")])
    assert d.action == "blocked"


def test_user_allowlist_and_ssh_session(tmp_path, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "198.51.100.7 51515 10.0.0.2 22")
    r = responder(tmp_path, allow=["203.0.113.0/24"])
    assert [d.reason for d in r.handle([alert(), alert(group="198.51.100.7")])] == ["allowlisted"] * 2


def test_only_src_ip_alerts_and_severity_floor(tmp_path):
    fw = FakeFirewall()
    r = responder(tmp_path, run=fw)
    assert r.handle([alert(group=None, group_by=None)]) == []        # e.g. log cleared
    assert r.handle([alert(group="alice", group_by="user")]) == []   # grouped by something else
    assert r.handle([alert(severity="medium")]) == []                # below --block-severity
    assert fw.calls == []


def test_max_blocks_cap(tmp_path):
    r = responder(tmp_path, max_blocks=2)
    ds = r.handle([alert(group=f"203.0.113.{i}") for i in range(1, 5)])
    assert [d.action for d in ds] == ["blocked", "blocked", "skipped", "skipped"]


def test_failure_is_reported_not_recorded(tmp_path):
    r = responder(tmp_path, run=FakeFirewall(fail=True))
    [d] = r.handle([alert()])
    assert d.action == "failed" and "root" in d.reason
    assert r.state.blocks == {}


def test_ttl_expiry_and_unblock(tmp_path):
    fw, now = FakeFirewall(), [1_000_000.0]
    r = responder(tmp_path, run=fw, ttl=timedelta(hours=1), clock=lambda: now[0])
    r.handle([alert(), alert(group="198.51.100.23")])
    assert r.expire() == []
    now[0] += 3601
    assert sorted(r.expire()) == ["198.51.100.23", "203.0.113.45"]
    assert not any(rule[0] == "LOGSENTRY" for rule in fw.rules)
    assert r.state.blocks == {}


def test_permanent_block_never_expires(tmp_path):
    now = [0.0]
    r = responder(tmp_path, ttl=None, clock=lambda: now[0])
    r.handle([alert()])
    now[0] += 10 ** 9
    assert r.expire() == []


def test_netsh_commands():
    ip = parse_ip("203.0.113.45")
    nb = NetshBackend()
    assert nb.block_cmd(ip) == ["netsh", "advfirewall", "firewall", "add", "rule",
                                "name=LogSentry-block-203.0.113.45", "dir=in", "action=block",
                                "remoteip=203.0.113.45"]
    assert nb.unblock_cmd(ip)[-1] == "name=LogSentry-block-203.0.113.45"


def test_ipv6_uses_ip6tables():
    assert IptablesBackend().block_cmd(parse_ip("2001:db8::1"))[0] == "ip6tables"


def test_unknown_backend():
    with pytest.raises(BlockError):
        get_backend("pf")


def test_cli_preview_on_samples(tmp_path, capsys):
    code = main(["scan", "samples/auth.log", "samples/access.log", "samples/windows_security.jsonl",
                 "--year", "2026", "--block", "--firewall", "iptables", "--state", str(tmp_path / "s.json"),
                 "-o", "json"])
    assert code == 0
    err = capsys.readouterr().err
    planned = {line.split()[3] for line in err.splitlines() if line.startswith("[preview]")}
    assert planned == {"203.0.113.45", "203.0.113.77", "203.0.113.200", "198.51.100.9",
                       "198.51.100.23", "198.51.100.66", "198.51.100.140"}
    assert not any(ip.startswith("192.0.2.") for ip in planned)   # benign hosts untouched
    assert not (tmp_path / "s.json").exists()


def test_cli_apply_requires_block():
    assert main(["scan", "samples/auth.log", "--apply"]) == 2


def test_cli_blocks_empty(tmp_path, capsys):
    assert main(["blocks", "--state", str(tmp_path / "none.json")]) == 0
    assert "no active blocks" in capsys.readouterr().out
