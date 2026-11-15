import io
import os
from pathlib import Path

import pytest

from logsentry.blocker import BlockState, IptablesBackend, Responder
from logsentry.rules import load_rules
from logsentry.watch import Tail, Watcher

SAMPLE = Path("samples/auth.log").read_text(encoding="utf-8").splitlines(keepends=True)


def append(path, lines):
    with open(path, "a", encoding="utf-8", newline="") as fh:
        fh.writelines(lines)


def watcher(path, **kw):
    seen = []
    w = Watcher([path], "auth", load_rules(), year=2026, on_alert=seen.append, **kw)
    return w, seen


def test_tail_reads_only_new_complete_lines(tmp_path):
    p = tmp_path / "x.log"
    p.write_text("old line\n")
    t = Tail(p)
    assert t.read_lines() == []                 # starts at the end
    append(p, ["one\n", "two"])
    assert t.read_lines() == ["one"]            # "two" has no newline yet
    append(p, [" more\n"])
    assert t.read_lines() == ["two more"]


def test_tail_handles_rotation_and_truncation(tmp_path):
    p = tmp_path / "x.log"
    p.write_text("a\n")
    t = Tail(p)
    t.read_lines()
    os.replace(p, tmp_path / "x.log.1")         # logrotate
    p.write_text("fresh\n")
    assert t.read_lines() == ["fresh"]
    p.write_text("")                            # copytruncate
    assert t.read_lines() == []
    append(p, ["after truncate\n"])
    assert t.read_lines() == ["after truncate"]


def test_tail_waits_for_missing_file(tmp_path):
    p = tmp_path / "later.log"
    t = Tail(p)
    assert t.read_lines() == []
    p.write_text("first\n")
    assert t.read_lines() == ["first"]          # a file that appears later is read from the start


def test_watch_detects_attack_as_it_happens(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    w, seen = watcher(log)
    append(log, SAMPLE[:8])                      # benign traffic + start of the brute force
    w.poll()
    assert not any(a.rule_id == "LS-AUTH-003" for a in seen)
    append(log, SAMPLE[8:20])                    # rest of brute force, then the successful login
    w.poll()
    ids = {a.rule_id for a in seen}
    assert {"LS-AUTH-001", "LS-AUTH-003"} <= ids


def test_watch_does_not_repeat_ongoing_burst(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    w, seen = watcher(log)
    for line in SAMPLE:                          # feed one line per poll
        append(log, [line])
        w.poll()
    counts = {}
    for a in seen:
        counts[(a.rule_id, a.group)] = counts.get((a.rule_id, a.group), 0) + 1
    assert counts[("LS-AUTH-001", "203.0.113.45")] == 1
    assert counts[("LS-AUTH-003", "203.0.113.45")] == 1


def test_watch_from_start_matches_batch_scan(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("".join(SAMPLE))
    w, seen = watcher(log, from_start=True)
    w.poll()
    assert len(seen) == 8                        # same 8 alerts as `logsentry scan samples/auth.log`


def test_watch_blocks_attacker(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    calls = []
    r = Responder(IptablesBackend(), apply=False, state=BlockState(tmp_path / "s.json"),
                  run=lambda c: calls.append(c) or (0, ""), out=io.StringIO())
    w, _ = watcher(log, responder=r)
    append(log, SAMPLE)
    w.poll()
    assert "would block 203.0.113.45" in r.out.getvalue()
    assert "192.0.2." not in r.out.getvalue()


def test_watch_rejects_windows_format(tmp_path):
    with pytest.raises(ValueError):
        Watcher([tmp_path / "x"], "windows", load_rules())


def test_watch_blocks_on_fifth_failed_password(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    r = Responder(IptablesBackend(), apply=False, state=BlockState(tmp_path / "s.json"),
                  run=lambda c: (0, ""), out=io.StringIO())
    w, _ = watcher(log, responder=r)
    for n, line in enumerate(SAMPLE, start=1):
        append(log, [line])
        w.poll()
        if "would block 203.0.113.45" in r.out.getvalue():
            break
    assert n == 5                                # LS-AUTH-001 threshold: 5 failures
