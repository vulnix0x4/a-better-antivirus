# Changelog

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
