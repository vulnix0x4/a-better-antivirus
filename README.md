# A Better Antivirus

> **It's not an antivirus. It's a better one.**

**Catch infostealers in the act.** A Better Antivirus (ABA) plants convincing fake passwords, crypto wallets and app data on your Windows PC: things only malware would ever read. The moment something touches them, ABA freezes it, cuts its internet and tells you, often before your real data has left the machine.

```
> aba test        (example output)

 Fake stealer  C:\Users\you\AppData\Local\Temp\aba-test-41822.exe
 Reads bait    C:\Users\you\Desktop\passwords.txt

 ✓ Detected: critical (unsigned program running from a user-writable folder)
 ✓ Frozen 4 ms after the read
 ✓ Popup shown on your desktop
 ✓ Phone alert sent via ntfy
```

Despite the name, it doesn't replace your antivirus: **keep Windows Defender on.** Antivirus tries to stop malware from running; ABA is the tripwire for when something gets past it, and that's the part antivirus is bad at.

## Why this works

Infostealers (Lumma, RedLine, Vidar, StealC…) are the most common malware on personal PCs. They don't wait around: they sweep your browsers, wallets, Discord/Telegram sessions and documents, zip it all up and upload it, usually within seconds. Most of them **collect first and upload at the end**, and collecting means opening files in known places. ABA puts tripwires in exactly those places.

- **Fake files** where file grabbers look: `passwords.txt` on the Desktop, in Documents and in your home folder, a wallet recovery phrase, 2FA backup codes, a KeePass database.
- **Fake app data for apps you don't use**: Opera, Vivaldi and Yandex browser profiles (with saved passwords and cookies), MetaMask, Exodus, Electrum and Atomic wallets, Telegram sessions, Discord tokens, FileZilla servers, AWS keys. Nothing legitimate ever reads these, because the app isn't installed, so the signal is extremely clean. ABA checks what you actually have installed and never fakes data for those apps. If you install one later, ABA notices and quietly retires that decoy.
- **Canary tokens** (optional): the fake AWS keys and a link in `passwords.txt` are real [canarytokens.org](https://canarytokens.org) tokens. If a stealer gets your data and someone *uses* them later, you get an email, even if your PC was never online to tell you.

## How it works

```
 stealer opens a bait
        │
        ▼
 NTFS audit rule ──► Security event 4663 ──► ABA service (SYSTEM) gets it in <1 ms
                                                │
           1. instant verdict from path/name ───┤ unsigned + Temp/AppData/Downloads? script host?
           2. freeze the process tree ──────────┤ (before it can upload)
           3. verify the code signature ────────┤ signed legit app? → unfreeze, just note it
           4. collect forensics while frozen ───┤ command line, parents, hash, connections
           5. block / kill / isolate ───────────┤ as configured
           6. alert ────────────────────────────┘ desktop popup + toast + phone
```

- **Detection** uses Windows' own file auditing (an audit rule on each bait, read through the Security event log). No kernel driver, no background scanning, no CPU use while idle. Malware running as you can neither see nor remove the audit rules.
- **Severity** is automatic. Malware without admin rights can't write to `Program Files` or `Windows`, and stealers are almost always unsigned binaries in user-writable folders or abuse script hosts like PowerShell or mshta. So:

  | Reader | Severity |
  |---|---|
  | Unsigned program in Temp, AppData, Downloads, Desktop… | **critical** |
  | PowerShell, cmd, mshta, rundll32, wscript and similar | **critical** |
  | Signed app in a user folder, scripting runtimes (Python, Node), network share reads | **warn** |
  | Signed, installed software (Program Files, Windows) | **info** |
  | Defender, Windows Search, your ignore rules | ignored |

- **Responses** per severity. Presets:

  | Preset | Critical | Warn |
  |---|---|---|
  | Alert only | notify | notify |
  | **Balanced** (default) | freeze + block that program's internet | notify |
  | Strict | freeze + block + isolate the PC | freeze |

  Isolation uses the Windows Filtering Platform (the same engine enterprise "isolate device" uses). It survives reboots so malware can't wait it out, and it still lets ABA's own phone alert through. `aba release` undoes everything.

## Install

1. Download `aba_<version>_windows_amd64.exe` from [Releases](../../releases) and check its SHA-256 against `SHA256SUMS.txt`.
2. Double-click it (or run `aba install`). Approve the admin prompt and follow the setup.

Releases aren't code-signed yet, so SmartScreen will warn you. Verify the hash first, then use *More info → Run anyway*.

> We deliberately don't offer a `irm … | iex` one-liner: pasting commands into PowerShell is exactly how many stealers get installed.

## Everyday use

```
aba                  live dashboard
aba test         simulate a stealer safely and watch it get caught
aba alerts       what touched your baits (aba alerts show <id> for everything)
aba doctor       check everything is armed (--fix to repair)
aba learn        review what tripped during learning mode and ignore legit apps
```

When something trips:

```
aba kill <id>    it's malware: kill what's frozen (it stays blocked)
aba resume <id>  it's yours: unfreeze it, restore its internet, optionally ignore it
aba release      undo all responses: network back, everything unfrozen/unblocked
```

Setup:

```
aba configure    change baits, response, learning mode, phone alerts, canary tokens
aba bait list | show <id> | add <path> | remove <id> | catalog
aba ignore list | add <pattern> [--signer X] | remove <n>
aba phone test
aba uninstall [--purge]
```

**Don't open your bait files**: that's a read. Use `aba bait show <id>` instead; it prints the content without touching the file. If you do open one, Windows adds it to *Recent files*, and apps like Copilot then read it (that's how we found out). ABA removes those shortcuts automatically.

## Learning mode

New installs start with 3 days of learning mode: you get alerts, but nothing is frozen or blocked. Backup tools, sync clients and indexers sometimes read files, and `aba learn` turns what they did into ignore rules (pinned to the program's path *and* its code-signing publisher, so malware can't impersonate them).

## Phone alerts

ntfy (free, no account), Discord webhook, Pushover or email (SMTP with TLS). Secrets are stored DPAPI-encrypted in a file only SYSTEM and Administrators can read. ABA remembers the alert server's IP addresses, so alerts still get out when the PC is isolated and DNS is blocked.

## Honest limitations

- **It's a tripwire, not a shield.** It catches stealers that go looking for files. A stealer that only grabs your real browser data and never touches a bait won't trip it.
- **Speed.** Detection takes about a millisecond, but a stealer that uploads each item the moment it reads it may get something out first. Freezing stops whatever it hasn't sent yet.
- **Admin malware.** Malware running as administrator can stop the service, clear the audit policy or remove filters. ABA alerts if auditing is switched off, but it can't defend against an attacker who already owns the machine.
- **Desktop popups need you to be signed in.** Detections are always logged and phone alerts always go out, and responses happen either way.
- **Some legit software reads files** (backup, sync, search tools). Learning mode and ignore rules handle that.
- **Low profile, not hidden.** The service is called "File Access Monitor" so it doesn't advertise itself to malware that checks for honeypots, but it's fully visible to you.

## What gets changed on your PC

| What | Where | Undone by uninstall |
|---|---|---|
| Program | `C:\Program Files\File Access Monitor` | ✓ |
| Service | `FileAccessMonitor` (LocalSystem, auto-start) | ✓ |
| Data, alerts, logs | `C:\ProgramData\FileAccessMonitor` | alerts kept unless `--purge` |
| Audit policy | "Audit File System: Success" | ✓ restored to what it was |
| Baits | your folders + fake app folders | ✓ (files you made yourself are kept) |
| Firewall filters | WFP provider "A Better Antivirus" (only while responding) | ✓ |
| PATH | adds the program folder | ✓ |

Nothing leaves your PC except phone alerts you set up and, if you opt in, canary token creation (your email is sent to canarytokens.org).

## Building

```
go test ./...
go build -o dist/aba.exe ./cmd/aba
```

Admin-only integration tests (real audit rules, Security log, WFP) run in CI, or locally from an elevated shell with `ABA_INTEGRATION=1 go test ./internal/integration/`.

## License

MIT
