from datetime import datetime, timedelta

import pytest

from logsentry.engine import detect
from logsentry.events import Event
from logsentry.rules import Matcher, Rule, RuleError, load_rules, parse_window

T0 = datetime(2026, 11, 14, 2, 0, 0)


def ev(seconds, source="auth", **fields):
    return Event(T0 + timedelta(seconds=seconds), source, fields, raw=str(fields))


def rule(**kw):
    base = {"id": "T-1", "title": "test", "severity": "high", "source": "auth"}
    base.update(kw)
    return Rule.from_dict(base)


# ---------------------------------------------------------------- matcher / loader

def test_matcher_operators():
    m = Matcher({"status": {"gte": 400}, "url": {"regex": "login"}, "method": ["POST", "PUT"]})
    assert m(ev(0, status=401, url="/LOGIN", method="POST"))
    assert not m(ev(0, status=200, url="/login", method="POST"))
    assert not m(ev(0, status=401, url="/home", method="POST"))
    assert not m(ev(0, status=401, url="/login", method="GET"))


def test_matcher_exists():
    m = Matcher({"user": {"exists": True}})
    assert m(ev(0, user="x"))
    assert not m(ev(0))


def test_parse_window():
    assert parse_window("90s") == timedelta(seconds=90)
    assert parse_window("5m") == timedelta(minutes=5)
    assert parse_window("2h") == timedelta(hours=2)
    with pytest.raises(RuleError):
        parse_window("five minutes")


def test_invalid_rules_rejected():
    with pytest.raises(RuleError):
        rule(type="threshold", match={"action": "x"})  # no group_by
    with pytest.raises(RuleError):
        rule(type="pattern", severity="urgent", match={"a": 1})
    with pytest.raises(RuleError):
        rule(type="sequence", group_by="src_ip", steps=[{"match": {"a": 1}}])


def test_builtin_rules_load_and_have_mitre():
    rules = load_rules()
    assert len(rules) >= 20
    assert len({r.id for r in rules}) == len(rules)
    assert all(r.mitre for r in rules)


# ---------------------------------------------------------------- threshold

BRUTE = dict(type="threshold", match={"action": "ssh_failed"}, group_by="src_ip", threshold=5, window="5m")


def test_threshold_fires_once_per_burst():
    events = [ev(i * 3, action="ssh_failed", src_ip="203.0.113.5") for i in range(20)]
    alerts = detect(events, [rule(**BRUTE)])
    assert len(alerts) == 1
    assert alerts[0].count == 20
    assert alerts[0].group == "203.0.113.5"


def test_threshold_below_limit_is_silent():
    events = [ev(i, action="ssh_failed", src_ip="192.0.2.1") for i in range(4)]
    assert detect(events, [rule(**BRUTE)]) == []


def test_threshold_respects_window():
    # 5 failures but spread over 50 minutes -> not brute force
    events = [ev(i * 600, action="ssh_failed", src_ip="192.0.2.1") for i in range(5)]
    assert detect(events, [rule(**BRUTE)]) == []


def test_threshold_groups_are_independent():
    events = [ev(i, action="ssh_failed", src_ip=f"192.0.2.{i % 5}") for i in range(20)]  # 4 per IP
    assert detect(events, [rule(**BRUTE)]) == []


def test_threshold_distinct_for_password_spray():
    r = rule(type="threshold", match={"action": "ssh_failed"}, group_by="src_ip", distinct="user", threshold=4, window="10m")
    same_user = [ev(i, action="ssh_failed", src_ip="1", user="root") for i in range(10)]
    assert detect(same_user, [r]) == []
    many_users = [ev(i, action="ssh_failed", src_ip="1", user=f"u{i}") for i in range(4)]
    assert len(detect(many_users, [r])) == 1


# ---------------------------------------------------------------- sequence

SEQ = dict(type="sequence", group_by="src_ip", window="15m",
           steps=[{"match": {"action": "ssh_failed"}, "min_count": 5}, {"match": {"action": "ssh_success"}}])


def test_sequence_fail_then_success():
    events = [ev(i, action="ssh_failed", src_ip="1") for i in range(6)] + [ev(30, action="ssh_success", src_ip="1")]
    alerts = detect(events, [rule(**SEQ)])
    assert len(alerts) == 1
    assert alerts[0].count == 7


def test_sequence_success_without_enough_failures():
    events = [ev(i, action="ssh_failed", src_ip="1") for i in range(2)] + [ev(30, action="ssh_success", src_ip="1")]
    assert detect(events, [rule(**SEQ)]) == []


def test_sequence_success_from_other_ip_does_not_count():
    events = [ev(i, action="ssh_failed", src_ip="1") for i in range(6)] + [ev(30, action="ssh_success", src_ip="2")]
    assert detect(events, [rule(**SEQ)]) == []


def test_sequence_outside_window():
    events = [ev(i, action="ssh_failed", src_ip="1") for i in range(6)] + [ev(3600, action="ssh_success", src_ip="1")]
    assert detect(events, [rule(**SEQ)]) == []


# ---------------------------------------------------------------- pattern / engine

def test_pattern_without_group_alerts_per_event():
    r = rule(type="pattern", match={"action": "user_created"})
    events = [ev(0, action="user_created"), ev(5, action="user_created")]
    assert len(detect(events, [r])) == 2


def test_rules_only_see_their_source():
    r = rule(type="pattern", match={"action": "user_created"})
    assert detect([ev(0, source="windows", action="user_created")], [r]) == []


def test_alerts_sorted_by_severity_and_min_severity_filter():
    low = rule(id="L", severity="low", type="pattern", match={"action": "a"})
    crit = rule(id="C", severity="critical", type="pattern", match={"action": "a"})
    events = [ev(0, action="a")]
    assert [a.rule_id for a in detect(events, [low, crit])] == ["C", "L"]
    assert [a.rule_id for a in detect(events, [low, crit], min_severity="high")] == ["C"]
