"""Automatic response: block the source IP of an attack at the host firewall.

Safety model
------------
* **Preview by default.** ``--block`` only prints the firewall commands it would
  run. Nothing changes until ``--apply`` is also given.
* **Only real source IPs.** An alert is eligible only when its rule groups by
  ``src_ip`` and the group value parses as an IP address. The value comes from
  attacker-influenced log text and ends up in a root command line, so anything
  that is not a plain IP is refused, and commands are run as argument lists
  (never through a shell).
* **Never block yourself.** Loopback, private (RFC 1918 / ULA), link-local and
  CGNAT ranges, the IP of the SSH session you are logged in from, and anything
  passed with ``--allow`` are never blocked.
* **Bounded.** ``--max-blocks`` caps how many addresses can be blocked at once,
  and every block expires after ``--block-ttl`` (default 24h).

Backends: ``iptables`` (Linux, rules live in a dedicated ``LOGSENTRY`` chain so
they are easy to inspect and flush) and ``netsh`` (Windows Defender Firewall,
one rule per IP named ``LogSentry-block-<ip>``).
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .events import Alert
from .rules import SEVERITIES

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Runner = Callable[[Sequence[str]], "tuple[int, str]"]

# Ranges that are never blocked. Listed explicitly on purpose: Python's
# ``is_private`` also covers the RFC 5737 documentation ranges, and its exact
# meaning has changed between Python versions.
DEFAULT_ALLOW = [
    "0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
]


class BlockError(RuntimeError):
    pass


def parse_ip(value: object) -> IPAddress | None:
    """Return the value as an IP address, or None if it is anything else."""
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # "::ffff:203.0.113.5" from dual-stack servers
    return ip


def ssh_client_ip() -> str | None:
    """IP of the SSH session this process runs in, so an admin can't lock themselves out."""
    for var in ("SSH_CONNECTION", "SSH_CLIENT"):
        value = os.environ.get(var, "").split()
        if value and parse_ip(value[0]):
            return value[0]
    return None


def default_runner(cmd: Sequence[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(list(cmd), capture_output=True, text=True, timeout=20)
    except FileNotFoundError:
        return 127, f"{cmd[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, f"{cmd[0]}: timed out"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


# ----------------------------------------------------------------------------- backends

class Backend:
    name = "base"

    def block_cmd(self, ip: IPAddress) -> list[str]:
        raise NotImplementedError

    def unblock_cmd(self, ip: IPAddress) -> list[str]:
        raise NotImplementedError

    def is_blocked(self, ip: IPAddress, run: Runner) -> bool:
        raise NotImplementedError

    def prepare(self, ip: IPAddress, run: Runner) -> None:
        """One-time setup before the first block (create chains etc.)."""

    def block(self, ip: IPAddress, run: Runner) -> None:
        self.prepare(ip, run)
        if self.is_blocked(ip, run):
            return
        code, out = run(self.block_cmd(ip))
        if code != 0:
            raise BlockError(out or f"exit code {code}")

    def unblock(self, ip: IPAddress, run: Runner) -> None:
        if not self.is_blocked(ip, run):
            return
        code, out = run(self.unblock_cmd(ip))
        if code != 0:
            raise BlockError(out or f"exit code {code}")


class IptablesBackend(Backend):
    """Linux netfilter via iptables / ip6tables, in a dedicated LOGSENTRY chain."""

    name = "iptables"
    CHAIN = "LOGSENTRY"

    def __init__(self) -> None:
        self._ready: set[str] = set()

    @staticmethod
    def _bin(ip: IPAddress) -> str:
        return "iptables" if ip.version == 4 else "ip6tables"

    def _rule(self, ip: IPAddress) -> list[str]:
        return ["-s", str(ip), "-j", "DROP"]

    def block_cmd(self, ip):
        return [self._bin(ip), "-A", self.CHAIN, *self._rule(ip)]

    def unblock_cmd(self, ip):
        return [self._bin(ip), "-D", self.CHAIN, *self._rule(ip)]

    def is_blocked(self, ip, run):
        return run([self._bin(ip), "-C", self.CHAIN, *self._rule(ip)])[0] == 0

    def prepare(self, ip, run):
        b = self._bin(ip)
        if b in self._ready:
            return
        if run([b, "-n", "-L", self.CHAIN])[0] != 0:
            code, out = run([b, "-N", self.CHAIN])
            if code != 0:
                raise BlockError(f"could not create {self.CHAIN} chain: {out}")
        if run([b, "-C", "INPUT", "-j", self.CHAIN])[0] != 0:
            code, out = run([b, "-I", "INPUT", "1", "-j", self.CHAIN])
            if code != 0:
                raise BlockError(f"could not hook {self.CHAIN} into INPUT: {out}")
        self._ready.add(b)


class NetshBackend(Backend):
    """Windows Defender Firewall via netsh, one inbound block rule per IP."""

    name = "netsh"

    @staticmethod
    def _name(ip: IPAddress) -> str:
        return f"name=LogSentry-block-{ip}"

    def block_cmd(self, ip):
        return ["netsh", "advfirewall", "firewall", "add", "rule", self._name(ip),
                "dir=in", "action=block", f"remoteip={ip}"]

    def unblock_cmd(self, ip):
        return ["netsh", "advfirewall", "firewall", "delete", "rule", self._name(ip)]

    def is_blocked(self, ip, run):
        return run(["netsh", "advfirewall", "firewall", "show", "rule", self._name(ip)])[0] == 0


BACKENDS: dict[str, type[Backend]] = {"iptables": IptablesBackend, "netsh": NetshBackend}


def get_backend(name: str = "auto") -> Backend:
    if name == "auto":
        if sys.platform == "win32":
            name = "netsh"
        elif shutil.which("iptables"):
            name = "iptables"
        else:
            raise BlockError("no supported firewall found (install iptables or pass --firewall)")
    if name not in BACKENDS:
        raise BlockError(f"unknown firewall backend {name!r} (choose from {sorted(BACKENDS)})")
    return BACKENDS[name]()


# ----------------------------------------------------------------------------- state

def default_state_path() -> Path:
    env = os.environ.get("LOGSENTRY_STATE")
    return Path(env) if env else Path.home() / ".logsentry" / "blocks.json"


class BlockState:
    """Active blocks, persisted as JSON so expiry and unblock survive restarts."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_state_path()
        self.blocks: dict[str, dict] = {}
        if self.path.exists():
            try:
                self.blocks = json.loads(self.path.read_text(encoding="utf-8")).get("blocks", {})
            except (json.JSONDecodeError, AttributeError) as exc:
                raise BlockError(f"corrupt state file {self.path}: {exc}") from exc

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"blocks": self.blocks}, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)


# ----------------------------------------------------------------------------- responder

@dataclass
class Decision:
    action: str          # blocked | would-block | skipped | failed
    ip: str | None
    alert: Alert
    reason: str = ""


def _fmt_time(epoch: float | None) -> str:
    return "never" if epoch is None else datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")


class Responder:
    """Turns alerts into firewall blocks, with the guard rails described above."""

    def __init__(
        self,
        backend: Backend,
        *,
        apply: bool = False,
        min_severity: str = "high",
        allow: Iterable[str] = (),
        ttl: timedelta | None = timedelta(hours=24),
        max_blocks: int = 50,
        state: BlockState | None = None,
        run: Runner = default_runner,
        clock: Callable[[], float] = time.time,
        out=None,
    ) -> None:
        self.backend, self.apply, self.run, self.clock = backend, apply, run, clock
        self.floor = SEVERITIES.index(min_severity)
        self.ttl = ttl if ttl and ttl.total_seconds() > 0 else None
        self.max_blocks = max_blocks
        self.state = state if state is not None else BlockState()
        self.out = out or sys.stderr
        self.allow = [ipaddress.ip_network(n, strict=False) for n in DEFAULT_ALLOW]
        for entry in allow:
            try:
                self.allow.append(ipaddress.ip_network(entry, strict=False))
            except ValueError as exc:
                raise BlockError(f"bad --allow value {entry!r}: {exc}") from exc
        me = ssh_client_ip()
        if me:
            self.allow.append(ipaddress.ip_network(me))
        self._planned: set[str] = set()  # dry-run: what we would have blocked this run

    def _say(self, msg: str) -> None:
        print(msg, file=self.out, flush=True)

    def _allowed(self, ip: IPAddress) -> bool:
        return any(ip.version == net.version and ip in net for net in self.allow)

    def _active_count(self) -> int:
        return len(self.state.blocks) + len(self._planned)

    def handle(self, alerts: Iterable[Alert]) -> list[Decision]:
        decisions = []
        for alert in alerts:
            d = self._decide(alert)
            if d:
                decisions.append(d)
        return decisions

    def _decide(self, alert: Alert) -> Decision | None:
        if SEVERITIES.index(alert.severity) < self.floor:
            return None
        if alert.group_by != "src_ip":
            return None  # not attributable to one source address
        ip = parse_ip(alert.group)
        tag = f"{alert.rule_id} {alert.title}"
        if ip is None:
            self._say(f"[skip]    {alert.group!r} is not an IP address ({tag})")
            return Decision("skipped", None, alert, "not an IP")
        key = str(ip)
        if key in self.state.blocks or key in self._planned:
            return None  # already handled; stay quiet
        if self._allowed(ip):
            self._say(f"[skip]    {key} is allowlisted ({tag})")
            return Decision("skipped", key, alert, "allowlisted")
        if self._active_count() >= self.max_blocks:
            self._say(f"[skip]    {key}: --max-blocks limit of {self.max_blocks} reached ({tag})")
            return Decision("skipped", key, alert, "max-blocks")

        now = self.clock()
        expires = now + self.ttl.total_seconds() if self.ttl else None
        if not self.apply:
            self._planned.add(key)
            cmd = " ".join(self.backend.block_cmd(ip))
            self._say(f"[preview] would block {key} for {tag}\n          $ {cmd}")
            return Decision("would-block", key, alert)
        try:
            self.backend.block(ip, self.run)
        except BlockError as exc:
            self._say(f"[error]   could not block {key}: {exc}")
            return Decision("failed", key, alert, str(exc))
        self.state.blocks[key] = {
            "rule": alert.rule_id, "title": alert.title, "severity": alert.severity,
            "backend": self.backend.name, "blocked_at": now, "expires_at": expires,
        }
        self.state.save()
        self._say(f"[block]   {key} blocked via {self.backend.name} for {tag} (expires {_fmt_time(expires)})")
        return Decision("blocked", key, alert)

    def expire(self) -> list[str]:
        """Lift blocks whose TTL has passed. Returns the IPs unblocked."""
        now = self.clock()
        done = []
        for key, rec in list(self.state.blocks.items()):
            if rec.get("expires_at") is not None and rec["expires_at"] <= now:
                if self.unblock(key, quiet=True):
                    self._say(f"[expire]  {key} unblocked (block expired)")
                    done.append(key)
        return done

    def unblock(self, value: str, quiet: bool = False) -> bool:
        ip = parse_ip(value)
        if ip is None:
            raise BlockError(f"{value!r} is not an IP address")
        key = str(ip)
        rec = self.state.blocks.get(key)
        backend = get_backend(rec["backend"]) if rec and rec.get("backend") else self.backend
        try:
            backend.unblock(ip, self.run)
        except BlockError as exc:
            self._say(f"[error]   could not unblock {key}: {exc}")
            return False
        self.state.blocks.pop(key, None)
        self.state.save()
        if not quiet:
            self._say(f"[unblock] {key} removed from {backend.name}")
        return True
