<div align="center">

# A Better Antivirus

**It's not an antivirus. It's a better one.**

Catch infostealers in the act. ABA plants fake passwords, wallets and app data<br>
that only malware would ever read, and freezes whatever touches them.

[![Release](https://img.shields.io/github/v/release/vulnix0x4/a-better-antivirus?style=flat-square&color=30d158)](https://github.com/vulnix0x4/a-better-antivirus/releases/latest)
[![Tests](https://img.shields.io/github/actions/workflow/status/vulnix0x4/a-better-antivirus/ci.yml?branch=main&style=flat-square&label=tests)](https://github.com/vulnix0x4/a-better-antivirus/actions/workflows/ci.yml)
[![Downloads](https://img.shields.io/github/downloads/vulnix0x4/a-better-antivirus/total?style=flat-square&color=blue)](https://github.com/vulnix0x4/a-better-antivirus/releases)
[![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=flat-square)](#install)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)](LICENSE)
[![GitGem](https://gitgem.org/api/badge/github/vulnix0x4/a-better-antivirus.svg)](https://gitgem.org/github/vulnix0x4/a-better-antivirus)

<a href="docs/demo.mp4"><img src="docs/demo.gif" alt="A real Discord token stealer, Windows Defender off: ABA freezes it the moment it opens a bait" width="800"></a>

<sub>A real Discord token stealer with Windows Defender off. It went for a fake Discord token and was frozen 158 ms later.<br><a href="docs/demo.mp4">Watch the full video with sound (47 s)</a></sub>

</div>

Despite the name, **keep Windows Defender on.** Antivirus tries to stop malware from running; ABA is the tripwire for when something gets past it, and that's the part antivirus is bad at.

## Install

### Installer (Windows 10/11, 64-bit)

Download **[ABA-Setup.exe](https://github.com/vulnix0x4/a-better-antivirus/releases/latest/download/ABA-Setup.exe)** and double-click it. It carries both the x64 and Arm64 builds of `aba.exe`, asks two questions (phone alerts and automatic updates), sets up the recommended baits with Balanced protection, and offers a **safe test** at the end. Running it again on an existing install updates or repairs ABA without changing your settings.

> Releases aren't code-signed yet, so Windows SmartScreen may warn you. Check the file's SHA-256 against `SHA256SUMS.txt` on [Releases](https://github.com/vulnix0x4/a-better-antivirus/releases/latest) first:
> ```powershell
> (Get-FileHash .\ABA-Setup.exe -Algorithm SHA256).Hash
> ```
> If it matches, click **More info → Run anyway**.

### PowerShell

Prefer the terminal (or want to pick every bait and response yourself)? In PowerShell:

```powershell
irm https://raw.githubusercontent.com/vulnix0x4/a-better-antivirus/main/install.ps1 | iex
```

It downloads the latest release for your PC, checks its SHA-256 against `SHA256SUMS.txt`, and starts the guided setup ([read the script first](install.ps1) if you like). Setup takes about a minute:

- **Recommended** asks just two things — phone alerts and automatic updates — and uses sensible defaults for the rest. **Customize** lets you pick every bait and response.
- If you set up phone alerts, it sends a test notification so you know they work.
- It ends by offering a **safe test**: a harmless fake stealer reads a bait and you watch ABA freeze it.
- Afterwards `aba` works in the same PowerShell window.

<p align="center"><img src="docs/setup.png" alt="The end of setup: every step ticked, then a summary card saying you're protected" width="720"></p>

<details>
<summary><b>Other ways to install (silent flags, test VMs, by hand)</b></summary>

**Silent installer** (same defaults as clicking Next all the way — recommended baits, Balanced response, no phone alerts, automatic updates on):

```powershell
.\ABA-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
```

Optional flags (first install only; an existing install keeps its settings):

| Flag | Meaning |
|---|---|
| `/NTFYTOPIC=my-topic` | Send phone alerts to this [ntfy](https://ntfy.sh) topic (letters, digits, `-`, `_`) |
| `/AUTOUPDATE=0` | Don't update automatically (`1`, the default, does) |
| `/PRESET=alert\|balanced\|strict` | Response preset (default `balanced`) |
| `/LEARNING=3` | Days of learning mode; only changes something with `strict` (default `0`) |
| `/CANARYEMAIL=me@example.com` | Create canary tokens that email this address |
| `/BAITS=id,id` | Plant specific baits instead of the recommended set (`aba bait catalog` lists them) |
| `/LOG=setup.log` | Write Inno Setup's log, including ABA's output (keep it private: it records your command line and user folder) |

**Test VM, no questions asked** (strict mode, no learning period):

```powershell
$env:ABA_ARGS = 'install --yes --preset strict --learning 0'; irm https://raw.githubusercontent.com/vulnix0x4/a-better-antivirus/main/install.ps1 | iex
```

**By hand:** download `aba_<version>_windows_amd64.exe` (or `arm64`) from [Releases](https://github.com/vulnix0x4/a-better-antivirus/releases/latest), verify its SHA-256 against `SHA256SUMS.txt`, and run it with `install`.

> Only ever paste `irm … | iex` commands from sources you trust: it's also how many infostealers get installed ("paste this to fix your PC"). This script is open, short, and refuses to run a download whose checksum doesn't match.

</details>

## Why this works

Infostealers (Lumma, RedLine, Vidar, StealC…) are the most common malware on personal PCs. They sweep your browsers, wallets, Discord and Telegram sessions, and documents, zip it all up and upload it — usually within seconds. Most **collect first and upload at the end**, and collecting means opening files in known places. ABA puts tripwires in those exact places.

- **Fake files** where file grabbers look: a password list on the Desktop, in Documents and in your home folder, a wallet recovery phrase, 2FA backup codes, and a KeePass database. Every install names them differently (from what grabbers search for), so they can't be skipped by name.
- **Fake app data for apps you don't use:** Opera, Vivaldi, Yandex and Brave browser profiles (real SQLite databases with saved logins and cookies), MetaMask, Exodus, Electrum and Atomic wallets, Telegram sessions, Discord tokens, FileZilla servers, and AWS keys. Nothing legitimate reads these when the app isn't installed, so the signal is clean. ABA checks what you actually have installed and never fakes data for those apps. If you install one later, ABA notices, retires that decoy and tells you — it has to be the real thing, signed by its publisher in its install folder; a file that merely looks like the real app is reported instead.
- **A fake profile inside the browsers you do use:** a `Profile 23` (or similar) folder next to your real profiles in Chrome, Edge and Brave, with saved logins and cookies. Stealers take every profile folder; the browser itself only opens the ones it knows, so it never touches this one. Checking whether the browser is installed doesn't help a stealer dodge it.
- **Canary tokens** (optional): the fake AWS keys and a link in `passwords.txt` are real [canarytokens.org](https://canarytokens.org) tokens. If an infostealer gets your data and someone *uses* them later, you get an email — even if your PC was never online to tell you.

ABA catches infostealers by **what they do**, not by recognising the file, so it works on brand-new ones no antivirus has a signature for yet.

```
> aba test

 A harmless copy of ABA in your Temp folder is about to read passwords.txt on the Desktop,
 exactly the way a stealer would. Nothing leaves your PC and your network isn't touched.

 ✓ Caught      critical: unsigned program running from a user-writable folder: typical of stealers
 ✓ Frozen      72 ms after it opened the bait, before it could read a byte
 ✓ Alerted     popup on your desktop, and your phone (ntfy)
 ✓ Cleaned up  the fake stealer was killed and deleted
```

## How it works

```
 stealer opens a bait
        │
        ├──► instant freeze: oplock breaks immediately (~0.1 s to freeze) ──┐
        │                                                                    ▼
        └──► backup: NTFS audit rule ──► Security event 4663 ──► ABA service (SYSTEM)
             (Windows delivers these in a few ms to ~1 s)                    │
               1. instant verdict from path/name ───┤ unsigned + Temp/AppData/Downloads? script host?
               2. freeze the process tree ──────────┤ (already frozen on the instant path)
               3. verify the code signature ────────┤ signed legit app? → unfreeze, just note it
               4. collect forensics while frozen ───┤ command line, parents, hash, connections
               5. block / kill / isolate ───────────┤ as configured
               6. alert ────────────────────────────┘ desktop popup + toast + phone
```

- **Instant freeze** (on by default, `aba instant on|off`): ABA holds an exclusive *opportunistic lock* on every bait so Windows tells it the moment one is opened. If the opener is suspicious, ABA freezes it right away — typically ~0.1 s after the open (72–151 ms in CI) — instead of waiting for the event log. To stay safe, it only acts on ordinary non-admin programs running as you (never system processes or ABA itself), and if it can't pinpoint the opener with certainty it doesn't guess.
- **Event-log backup** uses Windows' own file auditing (an NTFS audit rule on each bait, read through the Security event log). No kernel driver, no background scanning, no CPU use while idle. Malware running as you can neither see nor remove the audit rules, and can't read ABA's files to find out where the baits are.

<details>
<summary><b>Under the hood: oplocks, non-blocking opens, execute-only mappings and hard links</b></summary>

- **Finding the opener from an oplock:** When a program opens a guarded bait, Windows pauses it inside its open call and notifies ABA, without naming the PID. ABA snapshots the threads that entered a kernel wait at that moment and are still stuck a few milliseconds later, then releases the oplock. The opener wakes at that exact instant; an innocent thread waiting on something else (like a pipe) stays stuck. Identified precisely, never guessed — if more than one program wakes at once, ABA leaves it to the event log. (If a program already known to be sweeping is among the paused threads, ABA decides while its open is still held.)
- **Non-blocking ("ghost") opens:** A program can ask Windows *not* to pause it (`FILE_COMPLETE_IF_OPLOCKED`), so no thread is ever stuck. That open still leaves a handle behind, which ABA queries (`NtQueryInformationFile`) to find who newly holds the bait before it can read through the handle. Refusing to be paused is itself flagged as evasion (**critical**).
- **Execute-only mappings:** A program can open a bait for execute access only (`FILE_EXECUTE`) and map it into memory to read its bytes without ever asking for read access. Both ABA's oplock guard and its NTFS audit rule treat execute access on a bait as a read, so it's caught on both paths (and paired with a non-blocking open, it's also flagged as evasion).
- **Hard links:** Anything running as you can create a hard link to a bait and open it under a path ABA has never seen. The oplock and audit rule belong to the underlying file, so ABA matches audited opens by NTFS file ID — and if the link was deleted before the event arrived, correlates it with the oplock open it just saw. Reading a bait through a hard link is flagged as evasion (**critical**).

</details>

- **Severity** is automatic. Malware without admin rights can't write to `Program Files` or `Windows`, and infostealers are almost always unsigned binaries in user-writable folders or abuse script hosts like PowerShell or mshta:

  | Reader | Severity |
  |---|---|
  | Anything that goes through **several apps' data** within 2 minutes (a sweep), alone or split over several programs | **critical** |
  | Anything using a **trick to read unseen**: opening a bait so Windows doesn't pause it, a hard link, a copy of ABA as a disguise | **critical** |
  | A Windows program running **injected code** (code that isn't from any file on disk) | **critical** |
  | Unsigned program in Temp, AppData, Downloads, Desktop… or inside the Windows folder | **critical** |
  | Signed program in a user folder running an **unsigned DLL from its own folder** (sideloading) | **critical** |
  | PowerShell, cmd, mshta, rundll32, wscript, Windows tools that copy or upload a file for you (certutil, extrac32, certreq, scp…), and tools stealers hide in (RegAsm, AppLaunch, vbc, MSBuild, more.com…) | **critical** |
  | Java, Python, Node… running a script or `.jar` from your Desktop, Downloads or Temp (a "game" you double-clicked) | **critical** |
  | Signed app in a user folder, scripting runtimes (Python, Node, Java), other Windows programs in your session, network share reads | **warn** |
  | Signed, installed software (Program Files), Windows services, the preview pane | **info** |
  | Defender, Windows Search, your trust rules | ignored |

- **Behaviour beats identity.** Infostealers often hide inside a legitimate program (process injection / hollowing), so *who* opened a bait can lie. *What* it opened can't: a real app only touches its own data, while a stealer grabs everything it knows in seconds. A process that reads several different apps' baits (your password files count as one; browsers, Discord, wallets… each count on their own) is stopped as a stealer whatever it claims to be — signed, trusted by you, or part of Windows. Only Defender, Windows Search and programs you explicitly allow to read everything (such as a backup tool) are exempt. When a Windows program reads a bait, ABA also looks inside it for a whole program running from memory that isn't backed by any file, the footprint of injected code.

- **Responses** per severity:

  | Preset | Critical | Warn |
  |---|---|---|
  | Alert only | notify | notify |
  | **Balanced** (default) | freeze + block that program's internet | notify |
  | Strict | freeze + block + isolate the PC | freeze |

  Isolation uses the Windows Filtering Platform (the same engine enterprise "isolate device" uses). It survives reboots so malware can't wait it out, and still lets ABA's own phone alerts through. `aba release` undoes everything.

- **Frozen means frozen.** A stealer is rarely one process, and anything running as you can un-suspend a suspended process. ABA freezes the whole thing — the reader and what it started, the unsigned loader or script host that started *it*, and other running copies of the same file — and holds them in a frozen job object that only the ABA service can reach, so no accomplice can thaw them (`aba resume` and `aba release` ask the service to). Windows' own processes are never frozen, checked by the real file on disk: a stealer that calls itself `svchost.exe` is.

## Everyday use

```
aba              live dashboard
aba test         simulate a stealer safely and watch it get caught
aba alerts       what touched your baits (aba alerts show <id> for everything)
aba doctor       check everything is armed (--fix to repair)
aba learn        trust several of your own apps at once
```

When something trips:

```
aba trust <id>   it's yours: undo everything and stop alerting about it
aba kill <id>    it's malware: end what the alert froze (it stays cut off)
aba resume <id>  not sure: let it run again, without trusting it
aba release      undo all responses: network back, everything unfrozen/unblocked
```

Setup:

```
aba configure    change baits, response, learning mode, phone alerts, updates, canary tokens
aba update       check for a new version and install it (--check to only look)
aba bait list | show <id> | add <path or catalog id> | remove <id> | rename | catalog
aba ignore list | add <pattern> [--signer X] | remove <n>
aba instant [on|off]
aba phone test
aba uninstall [--purge]
```

Most commands ask for administrator rights (a Windows prompt): what touched which bait, and where the baits are, is exactly what an infostealer would like to read, so ABA's files are closed to everything not running as admin. Plain `aba` works without: it shows whether you're protected and whether anything is waiting for you.

**Don't open your bait files**: that's a read. Use `aba bait show <id>` instead; it prints the content without touching the file. If you do open one, Windows adds it to *Recent files*, and apps like Copilot then read it (that's how we found out). ABA removes those shortcuts automatically.

## When it's one of your apps

Every alert asks whether that program should be reading that bait. One click on *It's mine* undoes anything ABA did (unfreezes it, restores its internet) and stops alerting on it. Trust is kept as narrow as possible so malware can't reuse it:

- it covers **only the bait(s) the program was seen reading**: code injected into a trusted app that goes after anything else is still caught;
- a signed program is pinned to its folder **and** its code-signing publisher;
- an unsigned program is pinned to **that exact file** (its SHA-256), not its path, since anything can be dropped at the same path later;
- a script host or runtime (`python.exe`, `powershell.exe`, `java.exe`…) is pinned to **the exact command line**: trusting your script never trusts every script;
- a Windows program (or script host) that went through several apps' data is never trusted permanently, only unfrozen that once;
- nothing that used a trick to read unseen is trusted permanently from an alert, and a trick overrides trust you gave earlier. If a backup or security tool of yours really reads files that way, allow it as administrator with `aba ignore add "<path>" --signer <publisher> --allow-tricks`.

When something is **frozen**, the popup asks "Kill it?" and reminds you that games, mods, cheats and cracks never need to read this, rather than asking "is it yours?" (you *did* start that cracked game yourself). Only signed programs can be trusted in one click; anything else is unfrozen that once (`aba trust <id>` in a terminal still trusts it, pinned to the file). A program that keeps touching a bait without you answering only pops up once every 12 hours, except script hosts and anything critical; the rest goes to `aba alerts`.

**Learning mode** (Strict and custom setups, 3 days by default): critical threats are stopped from minute one, while merely suspicious programs only alert so you can mark your own apps before Strict starts freezing them. You get a notification when learning mode ends. `aba learn` lists everything that tripped so you can trust several at once.

## Phone alerts

ntfy (free, no account), Discord webhook, Pushover or email (SMTP with TLS). Secrets are stored DPAPI-encrypted in a file only SYSTEM and Administrators can read. ABA remembers the alert server's IP addresses, so alerts still get out when the PC is isolated and DNS is blocked.

## Updates

Setup asks whether to keep ABA up to date automatically (change it any time with `aba configure`, or run `aba update` yourself).

When it's on, the service checks GitHub about once a day. A new version is only installed if:

1. the release's `SHA256SUMS.txt` carries a valid **ed25519 signature** from ABA's release key (the public key is built into ABA), and
2. the downloaded `.exe` matches its hash in that signed list.

So a swapped release file, a compromised mirror or a proxy can't get code onto your PC. The update swaps the binaries, restarts the service, and **rolls back automatically** if the new version doesn't start. It never downgrades, ignores pre-releases, and never updates in the middle of an incident (while something is frozen or the PC is isolated).

## Honest limitations

- **It's a tripwire, not a shield.** It catches infostealers that go looking for files. A stealer that only grabs your real browser data and never touches a bait won't trip it. ABA is open source, so a stealer can be written to know it: what it can't do cheaply any more is tell which files are baits (their names differ per install, ABA's own records are closed to it, the fake apps hold up to a look, and checking that a browser is really installed doesn't help against a fake profile inside it). One that reads each browser's own list of profiles and takes only those, and nothing else on the PC, still stays under the wire.
- **Speed.** With instant freeze a stealer is frozen about 0.1 s after it opens a bait (it gets the fake bait contents, not your real data). Without it, ABA waits for the event log: a few ms to about 1 s. A stealer that uploads each item the moment it reads it may get something out first; freezing stops whatever it hasn't sent yet.
- **A reader that's already gone can't lead to its parent.** ABA freezes the program that started a critical reader by looking at it while it's alive (instant freeze does). A reader that exits before its event arrives, on a PC where instant freeze couldn't single it out, is reported and cut off, but whatever started it isn't known. Its file's internet stays cut either way.
- **Instant freeze is deliberately cautious.** It skips programs running as administrator and anything it can't pinpoint with certainty; those are still caught by the event-log path, just a little later.
- **Admin malware.** Malware running as administrator can stop the service, clear the audit policy or remove filters. ABA alerts if auditing is switched off, but it can't defend against an attacker who already owns the machine.
- **If the service is killed mid-incident, what it froze is ended.** A hold that nobody is left to release would otherwise stay frozen for good. That only happens if the service crashes or is killed; stopping, updating or reinstalling it releases holds properly (frozen programs stay suspended).
- **Injection is judged by its results, not watched as it happens.** Seeing one process write code into another needs a kernel driver or Microsoft's protected-antivirus signing, which ABA doesn't have. It catches injected stealers by what they read (sweeps) and, inside Windows programs, by the injected code they leave in memory. A stealer injected into an app you trusted that reads *only* the one bait you trusted that app with would get through; nothing real works that way, but it's possible. The memory check skips programs that legitimately generate code (.NET, Java, browsers), and newer tricks that disguise injected code as a file on disk (module stomping, process ghosting) aren't detected by it; the sweep rule still applies to them. Windows' own desktop processes (`explorer.exe` and a few others) are never frozen even with code injected into them: their internet is cut instead.
- **Desktop popups need you to be signed in.** Detections are always logged and phone alerts always go out, and responses happen either way.
- **Some legit software reads files** (backup, sync, search tools). One click on *It's mine* handles that. A backup tool that copies your whole AppData looks like a sweep; allow it to read everything with `aba ignore add "<path>" --signer <publisher>` (or *It's mine* on the sweep alert, for signed programs).
- **`~/.aws/credentials` is read by every AWS SDK** (OpenCode, Claude Code, VS Code, Terraform…), so a *signed* program reading it is only logged. Unsigned programs, script hosts and runtimes still trip it, and the other baits are unaffected.
- **Low profile, not hidden.** The service and program folder are called "File Access Monitor" so they don't advertise themselves to malware that checks for honeypots, while Windows' Installed apps list and Start menu show it as **A Better Antivirus** so you can always find it.

## What gets changed on your PC

| What | Where | Undone by uninstall |
|---|---|---|
| Program | `C:\Program Files\File Access Monitor` | ✓ |
| Service | `FileAccessMonitor` (LocalSystem, auto-start) | ✓ |
| Data, alerts, logs | `C:\ProgramData\FileAccessMonitor` (admins only; a status summary in `public\`) | alerts kept unless `--purge` |
| Audit policy | "Audit File System: Success" | ✓ restored to what it was |
| Baits | your folders + fake app folders | ✓ (files you made yourself are kept) |
| Firewall filters | WFP provider "A Better Antivirus" (only while responding) | ✓ |
| Installed apps & Start menu | **A Better Antivirus** entry in Windows' Installed apps and Start menu | ✓ |
| PATH | adds the program folder | ✓ |

**What goes over the network:** phone alerts you set up; if you opt in, canary token creation (your email is sent to canarytokens.org); and with automatic updates on, a daily request to `api.github.com` for the latest release. Nothing else, no telemetry.

## Linux and macOS (early)

Windows is the main platform today, but ABA's core protection also runs on Linux and macOS (tested end-to-end in CI on both). Neither has pre-built releases, packages or an installer script yet — install by hand from source for now:

```sh
go build -o aba ./cmd/aba
sudo ./aba install
```

### Linux

- **What works:** bait detection through kernel **fanotify** permission events (pauses the opener inside `open()` and names the process directly; hard links and renames are caught by inode); tamper-proof freezing in a root-owned **cgroup v2 freezer** (immune to `SIGCONT`; falls back to `SIGSTOP` on kernels older than 5.2); **package-ownership provenance** (`dpkg`, `rpm`, `pacman`, `apk`, snaps and system-wide flatpaks) plus process-chain classification and `LD_PRELOAD`/user-library checks; a **systemd** service (`file-access-monitor.service`); Linux baits (home/Documents files, decoy Vivaldi/Brave profiles, embedded profiles in Chrome/Chromium/Brave/Edge, Electrum, spare SSH key, `~/.git-credentials`, `~/.aws` backup, `~/.config/gcloud`); terminal freeze notices, phone alerts, and full `aba uninstall [--purge]`.
- **Not there yet:** network blocking and machine isolation, desktop popups/notifications (alerts go to `aba alerts`, your phone, and a terminal notice), machine-key secret encryption (root-only `600` file for now), and packages or an install script.

### macOS

- **What works:** macOS 14+ detection via Apple's Endpoint Security through **`eslogger`** (requires granting **File Access Monitor** Full Disk Access in *System Settings → Privacy & Security → Full Disk Access*, which `aba install` prompts for), including hard-link tracking and attributing copies made through Finder back to the script that drove it; tamper-proof freezing via root-only **`pid_suspend`**; **code-signature provenance** (Apple, Developer ID, Mac App Store) plus process-chain classification (`osascript`, shells, tools); closing a frozen program's open sockets (`pid_shutdown_sockets`) and whole-Mac **Strict-mode isolation via `pf`** (allowing ABA's phone alerts through); desktop notifications and alert popups; a **launchd** daemon (`com.fileaccessmonitor.service`); macOS baits (home password list, decoy browsers, embedded browser profiles, MetaMask, Exodus, Atomic, Electrum, Telegram, Discord, FileZilla, spare SSH key, `~/.git-credentials`, `~/.aws` backup; Desktop/Documents baits are opt-in via `aba bait add` to stay out of iCloud Drive); phone alerts, and full `aba uninstall [--purge]`.
- **Not there yet:** pre-open blocking (`eslogger` reports a few ms after the open; holding the opener requires an Apple Endpoint Security entitlement), persistent per-program firewall rules (needs a Network Extension entitlement), in-memory injection / library-sideloading checks, System Keychain secret encryption (root-only `600` file for now), and pre-built or notarized releases.

## Building

```
go test ./...
go build -o dist/aba.exe ./cmd/aba
```

Admin-only integration tests (real audit rules, Security log, WFP) run in CI, or locally from an elevated shell with `ABA_INTEGRATION=1 go test ./internal/integration/`. CI also runs full end-to-end suites (install → fake stealers → freeze/kill/isolate → uninstall) on real Windows, Linux and macOS machines for every push. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Found a way to bypass or abuse ABA? Please report it privately: see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
