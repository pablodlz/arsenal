# Security

Detection tooling: nuclei templates, wordlists, a Burp scan check, a Caido plugin, and standalone
scripts. It runs **against targets you choose**, so the properties that matter are what it sends
and what it keeps.

## Design commitments

- **Nothing here phones home.** No telemetry, no analytics, no update check, no third-party
  request. `phantom-probe.py` uses the standard library and talks only to the URL you pass it.
- **Nothing here writes to a target unprompted.** The Burp check is deliberately **passive only** —
  the active version would fire state-changing mutations, and a scanner must not do that on its
  own. `phantom-probe.py` sends object ids that cannot name a real row unless you pass
  `--foreign-id` yourself.
- **Nothing here stores your traffic.** No cache, no log file, no state directory.

If you find behaviour that contradicts any of those three, it is a security bug in this
repository.

## Reporting a vulnerability

Email **pablogalerani@gmail.com** with the component and a reproducer. Allow a reasonable window
before disclosing publicly.

Things I would treat as vulnerabilities here:

- a template or script that sends a request the operator did not ask for, or to a host they did
  not specify
- command injection through an argument — a hostname or mutation name reaching a shell
- a scan check that leaks request contents into a report, a log, or an issue title
- **a wordlist entry that is actually a live credential or a real identifier**

That last one is the most likely mistake in a repository like this. Every list here is built from
requests I actually sent, so a real value slipping through is a plausible failure — report it and
I will purge it from history, not just from `HEAD`.

## Responsible use

Wordlists and templates are published so that testing is repeatable and reviewable. Running them
against a system you have no permission to test is unauthorized access in most jurisdictions,
programme or not. A permissive licence is not authorization.
