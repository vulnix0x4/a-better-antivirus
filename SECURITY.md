# Security policy

A Better Antivirus runs as SYSTEM, so bugs in it matter. Please report vulnerabilities privately through
GitHub's [Report a vulnerability](https://github.com/vulnix0x4/a-better-antivirus/security/advisories/new)
(Security tab) rather than a public issue. You'll get a reply within a few days.

Especially interesting:

- ways for a non-admin process to disable, blind or bypass A Better Antivirus (stop the service, strip audit
  rules, get ignored, undo a response, read secrets),
- ways to make the SYSTEM service run attacker-controlled code or touch attacker-chosen files,
- ways to get the auto-updater to install something that wasn't signed with the release key,
- ways for a stealer to tell baits apart from real data cheaply.

Out of scope: attacks that already require administrator rights (see "Honest limitations" in the README).

## How releases and updates are protected

- Releases are built by GitHub Actions from a tagged commit ([release.yml](.github/workflows/release.yml)).
- Every release ships `SHA256SUMS.txt` and `SHA256SUMS.txt.sig`: an ed25519 signature over the checksum list,
  made with the release key. The public key is compiled into ABA ([internal/update](internal/update/update.go)).
- The auto-updater (and `aba update`) only installs a release whose signature verifies and whose `.exe` matches
  the signed hash. It refuses downgrades, pre-releases and downloads from anywhere but GitHub, and rolls back
  if the new version fails to start.
- Updates are downloaded into `C:\Program Files\File Access Monitor\updates`, which only administrators and
  SYSTEM can write to.

Supported versions: the latest release.
