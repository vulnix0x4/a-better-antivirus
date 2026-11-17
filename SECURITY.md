# Security policy

A Better Antivirus runs as SYSTEM, so bugs in it matter. Please report vulnerabilities privately through
GitHub's "Report a vulnerability" (Security tab) rather than a public issue.

Especially interesting:

- ways for a non-admin process to disable, blind or bypass A Better Antivirus (stop the service, strip audit
  rules, get ignored, undo a response, read secrets),
- ways to make the SYSTEM service run attacker-controlled code or touch attacker-chosen files,
- ways for a stealer to tell baits apart from real data cheaply.

Out of scope: attacks that already require administrator rights (see "Honest limitations" in the README).
