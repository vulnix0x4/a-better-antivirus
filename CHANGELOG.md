# Changelog

## v0.3.0

- **One click to trust your own apps.** Every alert now asks "Is this program yours?". *It's mine* undoes
  whatever ABA did and stops alerting on that program (rule pinned to its path and publisher). The frozen
  popup's "It's mine" now trusts the program too, instead of only unfreezing it. New `aba trust <alert-id>`.
- **No more alert spam.** A program that keeps reading the same bait without being acted on pops up once
  every 12 hours, not on every launch. Everything is still in `aba alerts`.
- **Learning mode never leaves you unprotected.** Critical threats (unsigned programs from user folders,
  script hosts) are stopped from the first minute; learning only holds back the response to merely
  suspicious programs. Setup only asks about it when it changes something (Strict, custom), and you get a
  notification when it ends.
- **Far fewer false positives from developer tools.** `~/.aws/credentials` is read by every AWS SDK on
  startup (OpenCode, Claude Code, VS Code, Terraform…). Signed programs doing that are now only logged;
  unsigned programs, script hosts and runtimes still trip it.

## v0.2.0

- **Automatic updates.** Setup now asks whether to keep ABA up to date (default: yes). The service checks
  GitHub about once a day and only installs releases whose checksum list is signed with ABA's release key
  (ed25519) and whose download matches the signed hash. It rolls back if the new version doesn't start,
  never downgrades, and waits until any incident is resolved.
- `aba update` installs a new version by hand; `aba update --check` only looks.
- `aba install --auto-update=false` for unattended installs that shouldn't update themselves.
- The dashboard shows the running version and whether auto-update is on.
- Releases now include `SHA256SUMS.txt.sig`.
- Tested against a real Discord token stealer with Windows Defender off: frozen 158 ms after it read a fake
  Discord token ([video](docs/demo.mp4)).

**Upgrading from v0.1.0:** v0.1.0 can't update itself, so run the install command once more (your settings
are kept), and answer the new question about automatic updates.

## v0.1.0

First release: baits for 18 apps, instant freeze, Security-log backup detection, per-severity responses
(freeze, block, kill, isolate), phone alerts (ntfy, Discord, Pushover, email), canary tokens, learning mode,
full uninstall.
