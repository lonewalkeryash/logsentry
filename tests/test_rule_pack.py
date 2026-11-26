"""Quality checks every built-in rule must pass.

These run on the whole rule pack, so a contributed rule is covered as soon as
its YAML file is added - no test code needs to change.
"""

import re
from importlib import resources
from pathlib import Path

import pytest
import yaml

from logsentry.engine import detect
from logsentry.parsers import parse_file
from logsentry.rules import load_rules

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
FILES = [SAMPLES / "auth.log", SAMPLES / "access.log", SAMPLES / "windows_security.jsonl"]

RULE_KEYS = {
    "id", "title", "description", "severity", "mitre", "source", "type",
    "match", "group_by", "threshold", "distinct", "window", "steps",
}
STEP_KEYS = {"match", "min_count"}
ID_PREFIX = {"auth": "LS-AUTH-", "web": "LS-WEB-", "windows": "LS-WIN-"}
MITRE_ID = re.compile(r"T\d{4}(\.\d{3})?")


def _raw_rules():
    """(file name, raw YAML dict) for every built-in rule."""
    out = []
    folder = resources.files("logsentry").joinpath("rules")
    for f in sorted(folder.iterdir(), key=lambda p: p.name):
        if f.name.endswith(".yml"):
            for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
                if doc:
                    out.append((f.name, doc))
    return out


RAW = _raw_rules()
RAW_IDS = [str(doc.get("id", name)) for name, doc in RAW]
RULES = load_rules()


@pytest.fixture(scope="module")
def fired_rule_ids():
    events = []
    for f in FILES:
        events += parse_file(f, year=2026)[1]
    return {a.rule_id for a in detect(events, RULES)}


@pytest.mark.parametrize("name,doc", RAW, ids=RAW_IDS)
def test_no_unknown_keys(name, doc):
    # The loader reads optional keys with .get(), so a typo such as
    # "treshold" would be ignored silently and the rule would use the default.
    unknown = set(doc) - RULE_KEYS
    assert not unknown, f"{name}: unknown key(s) {sorted(unknown)}; allowed: {sorted(RULE_KEYS)}"
    for step in doc.get("steps") or []:
        bad = set(step) - STEP_KEYS
        assert not bad, f"{name}: unknown step key(s) {sorted(bad)}; allowed: {sorted(STEP_KEYS)}"


@pytest.mark.parametrize("rule", RULES, ids=[r.id for r in RULES])
def test_id_matches_source(rule):
    prefix = ID_PREFIX[rule.source]
    assert re.fullmatch(re.escape(prefix) + r"\d{3}", rule.id), (
        f"{rule.id}: a {rule.source} rule id must look like {prefix}001"
    )


@pytest.mark.parametrize("rule", RULES, ids=[r.id for r in RULES])
def test_has_title_and_description(rule):
    assert rule.title.strip(), f"{rule.id}: title is empty"
    assert len(rule.description) >= 20, f"{rule.id}: add a one-sentence description of what this detects"


@pytest.mark.parametrize("rule", RULES, ids=[r.id for r in RULES])
def test_mitre_ids_are_well_formed(rule):
    assert rule.mitre, f"{rule.id}: map the rule to at least one MITRE ATT&CK technique"
    for technique in rule.mitre:
        assert MITRE_ID.fullmatch(str(technique)), (
            f"{rule.id}: {technique!r} is not a technique id (expected T1110 or T1110.001)"
        )


@pytest.mark.parametrize("rule", RULES, ids=[r.id for r in RULES])
def test_rule_fires_on_samples(rule, fired_rule_ids):
    assert rule.id in fired_rule_ids, (
        f"{rule.id} never fires on samples/. Add log lines that trigger it to "
        "scripts/generate_samples.py and regenerate the samples."
    )
