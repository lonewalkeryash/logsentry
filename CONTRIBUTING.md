# Contributing to LogSentry

Thanks for helping. The most useful contribution is a **new detection rule**:
it is a few lines of YAML plus a few sample log lines, and needs no changes to
the Python code. First-time contributors are welcome.

Please only use synthetic data. Never paste real logs, real IP addresses,
hostnames or usernames into an issue or pull request.

## Set up

```bash
git clone https://github.com/<your-username>/logsentry.git
cd logsentry
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

You need Python 3.10 or newer. All tests should pass before you change anything.

## Add a detection rule (about 10 minutes)

A rule detects one attack in a log format LogSentry already reads
(`auth`, `web` or `windows`).

1. **Pick an issue** labelled `new rule`, or open one with the "New detection
   rule" template so nobody duplicates your work.
2. **Write the rule.** Copy a block from [`docs/rule-template.yml`](docs/rule-template.yml)
   into the matching file under `src/logsentry/rules/`, separated from the rule
   above it by `---`. Use the next free id for that file (`LS-AUTH-008`,
   `LS-WEB-008`, `LS-WIN-009`, ...).
3. **Plant an attack in the samples.** Add log lines that should trigger your
   rule to `scripts/generate_samples.py`, then regenerate:

   ```bash
   python scripts/generate_samples.py
   ```

   Add your lines after the existing attacks in that function, with fixed
   values (no `rng` calls), so the existing sample lines do not change.
   Use attacker IPs from `203.0.113.0/24` or `198.51.100.0/24`. The
   `192.0.2.0/24` range is reserved for normal traffic and must stay alert-free.
4. **Check it fires.**

   ```bash
   logsentry scan samples/auth.log samples/access.log samples/windows_security.jsonl --year 2026
   pytest
   ```

   `tests/test_rule_pack.py` checks every rule automatically: no misspelt keys,
   a correct id, a description, valid MITRE ATT&CK ids, and at least one alert
   on the samples. You do not need to write a new test for a new rule.
5. **Update the docs.** Add a row to the "Detection coverage" table in
   `README.md`, update the rule count mentioned there, and add a line to
   `CHANGELOG.md`.
6. **Open a pull request.** One rule per pull request is easiest to review.

### Fields a rule can match on

| Source | Fields |
|---|---|
| `auth` | `action` (`ssh_failed`, `ssh_success`, `ssh_invalid_user`, `sudo`, `user_created`, `group_add`, `other`), `src_ip`, `user`, `target_user`, `command`, `group`, `host`, `process`, `message` |
| `web` | `action` (`http_request`), `src_ip`, `user`, `method`, `url`, `url_decoded`, `status`, `size`, `user_agent` |
| `windows` | `action` (`logon_success`, `logon_failed`, `user_created`, `group_add`, `log_cleared`, `process_created`, `service_installed`, `other`), `event_id`, `src_ip`, `user`, `subject_user`, `host`, `logon_type`, `group`, `process`, `command`, `service` |

The parsers in `src/logsentry/parsers.py` are the source of truth for these
fields. Match on `url_decoded`, not `url`, for web payloads, so
percent-encoded attacks are caught too.

### Match operators

`field: value` (equals), `field: [a, b]` (any of), `{regex: '...'}`
(case-insensitive search), `{gte|lte|gt|lt: n}`, `{exists: true}`. Every
condition in a `match:` block must hold.

### What makes a good rule

- **Low noise.** Say in the pull request what normal activity could trigger it.
- **Grouped by `src_ip`** when the attacker's address is known, so auto-block
  can act on it.
- **A severity that fits.** `critical` is for a confirmed compromise, `high`
  for an attack in progress, `medium` for suspicious activity, `low` for
  information.

## Add a log format (a larger change)

A new format (journald, CloudTrail, Nginx error log, ...) needs Python work:

1. a parser in `src/logsentry/parsers.py` that returns normalised `Event`s,
   and format auto-detection for it;
2. the new source name in `SOURCES` in `src/logsentry/rules.py`, and its id
   prefix in `tests/test_rule_pack.py`;
3. a synthetic sample file from `scripts/generate_samples.py`;
4. parser tests in `tests/test_parsers.py`, including malformed lines (a bad
   line must be skipped, never crash the scan);
5. at least one rule that uses the format.

Open an issue with the "New log format" template first, with a few made-up
example lines, so the field names can be agreed before you write code.

## Other contributions

Bug fixes, false-positive reports, documentation fixes and new firewall or
alert back-ends are all welcome. For anything larger than a small fix, open an
issue first.

## Pull request checklist

- [ ] `pytest` passes locally
- [ ] only synthetic data (documentation IP ranges, made-up names)
- [ ] `README.md` and `CHANGELOG.md` updated if behaviour or rules changed
- [ ] one topic per pull request

CI runs the tests on Linux and Windows with Python 3.10, 3.12 and 3.14.

## Security issues

Do not open a public issue for a vulnerability in LogSentry itself. See
[`SECURITY.md`](SECURITY.md).

## Licence

By contributing you agree that your work is released under the
[MIT licence](LICENSE).
