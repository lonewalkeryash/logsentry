# Security policy

LogSentry runs with firewall privileges and reads attacker-controlled log
text, so reports about the tool itself are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
on the repository page go to **Security → Report a vulnerability**.

Useful reports include:

- log lines that make LogSentry block an address it should not (for example an
  allowlisted, private or spoofed address);
- log lines that crash a scan or the `watch` service, or make it use unbounded
  memory or CPU;
- any way to make LogSentry run a command or write a file it should not.

Include the LogSentry version, the command you ran and synthetic log lines
that reproduce the problem. Do not send real logs.

## Not a vulnerability

A missed attack or a false alert is a detection gap, not a vulnerability.
Open a normal issue with the "False positive / missed detection" template.

## Supported versions

Only the latest release receives security fixes.
