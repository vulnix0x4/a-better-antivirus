# Changelog

## v0.10.2

**Releases are no longer code-signed**

- ABA's Windows and macOS files aren't code-signed any more. What protects ABA's downloads and updates is unchanged: every release's checksum list is signed with ABA's own release key, and the
  auto-updater refuses anything that doesn't match it.
- **Windows:** SmartScreen warns about `ABA-Setup.exe` again ("Unknown publisher"). Check its SHA-256 against
  `SHA256SUMS.txt`, then click **More info → Run anyway**. On a PC with Smart App Control on, Windows may block it.
- **macOS:** the first time, macOS won't open `ABA-macOS.pkg`. Click **Open Anyway** in *System Settings → Privacy &
  Security*, then open it again. After an update, macOS may stop File Access Monitor's Full Disk Access; ABA warns
  you when it does, and `sudo aba doctor --fix` opens the setting (switch it off and on again).
- Nothing else changed in ABA itself.

## v0.10.1

**ABA no longer looks like malware to antivirus programs (Windows)**

- ABA's Windows programs were code-signed in this version only (from v0.10.2 they aren't).

- Windows Defender and 13 of about 70 antivirus engines took version 0.10.0 for malware, and Defender could remove
  ABA from your PC. We tested which parts of ABA they reacted to and changed those parts, without changing what ABA
  catches or does. Measured on VirusTotal, ABA's Windows program went from 14 engines flagging it to 1, and Defender
  no longer flags it.
- **The miner trap's list of mining pools is now a file of its own** (`miner-pools.txt`, next to `aba.exe`) instead
  of being built into the program. Antivirus engines look for those pool names inside a program to spot crypto
  miners, so ABA looked like one. The list comes with ABA-Setup.exe and with every update, and it's checked against
  the release's signed checksum list just like the program. If it's ever missing (for example right after updating
  from 0.10.0), the trap keeps working with the pool names it already had, and ABA fetches the list for its own
  version from the release by itself.
- **Cutting a program off the internet no longer uses the Windows call that a tool for blinding antivirus programs
  is built around**, so Kaspersky no longer takes ABA for that tool. ABA works out the same firewall name for the
  program in another way; the result is exactly the same.
- **The popup notification no longer starts PowerShell with a scrambled (Base64) command**, which security tools
  rightly find suspicious. It's now a short, readable command that's the same every time, and the alert's text is
  passed to it separately, as plain text.

## v0.10.0

**The full report, one click from the popup, and every report in the Start menu**

- The popup that says what a caught program had already taken now has a **Show full report** button. It opens
  everything ABA found as a readable page in your web browser: the answer and what to do first, what it opened of
  yours (with times), where it sent things, what it left behind (like a hidden copy of itself that starts at
  sign-in), the stealer's own Discord webhook or Telegram bot (with how to report it so it's shut down), the
  program's details, and what ABA did, with what's left to do about it. Light and dark mode, and it prints.
- A new Start menu entry, **ABA reports**, lists every report, newest first; pick one to see it whole. It asks for
  the Windows admin approval first. Also `aba report <id>` and `aba reports`; the dashboard and `aba alerts` point to them.
- The reports stay in ABA's protected folder, where only administrators can read them, because they name ABA's
  bait files: a lasting copy you could read would tell a stealer running as you which files to leave alone. So the
  page is never saved anywhere: your browser gets it once, from this computer only, at an address with a random
  one-time key, and is told not to keep a copy. To keep a report, print it.
- On a Mac the popup has the same button; on Linux it's a button on the notification where the desktop shows
  buttons. There's no menu entry on a Mac or Linux yet: `sudo aba reports` in a terminal.

**Stealers that make themselves administrator are frozen instantly too (Windows)**

- Umbral and Blank Grabber, two real stealers, give themselves administrator rights before they start stealing
  (Umbral asks with the Windows admin prompt; Blank Grabber gets them without any prompt, through a known
  Windows trick). Instant freeze used to step aside for every program running as administrator, so these two
  were only caught by the backup check, about a second after their first bait, by which time they had opened
  several more baits and Umbral had read your real Edge data.
- Now a program running as administrator is judged the same way as any other: in the lab, Umbral was frozen
  98 ms after it opened its first bait and Blank Grabber 127 ms after (before: 884 ms and 968 ms). Blank Grabber
  no longer got to send anything at all, and Umbral never reached Edge.
- Nothing changes for ABA's own tools, signed admin tools (backup, system tools), or programs you trusted; and as
  before, an admin tool going through several apps' data doesn't count as a sweep. On Linux, programs running
  as root are still left to the regular check.

**The autopsy says whether anything left your PC (Windows)**

- ABA now keeps a **network record** on Windows: which programs send something over the network, where to, when
  and roughly how much, from Windows' own event tracing (no driver). It stays in memory, never alerts, and costs
  well under a tenth of a percent of one processor core.
- After a catch, the autopsy uses it to say whether your data got out before the freeze, with one of three
  answers: **nothing was sent** (then there's nothing to change, only the program to end), **it sent something**
  after opening your data (where to, roughly how much, and what to do now), or **ABA can't tell**, and why. A
  program it started counts as it; sends from before it opened anything of yours are only mentioned; traffic that
  stays on this PC never counts.
- In the lab, Phemedrone got "nothing left this PC". Umbral and Blank Grabber got "it sent something": each sent
  the Discord login it had just read to discord.com (to check it) about a tenth of a second after reading it,
  before the freeze landed. ABA can't see inside encrypted traffic, so it says to assume the login was taken.
- The popup, the phone alert and `aba autopsy` say so in plain words; the `aba` dashboard shows whether the
  network record is running. On Linux and macOS the autopsy says it can't tell yet.

**The autopsy, tested against real stealers**

- Tested in an isolated lab against three real stealers (Umbral, Phemedrone, Blank Grabber): each was frozen
  before it uploaded what it collected, and the autopsy found where it was sending (its Discord webhook or
  Telegram bot) in its memory or program file, and what real data it had opened first. (Two of them had already
  sent the Discord login they read to discord.com, to check it, in the second before the freeze: the network
  record below now shows that.)
- A stealer that unpacks itself (a Python one, for example) no longer floods "Files that appeared while it ran"
  with its own libraries: those are counted in one line per folder, and what it collected stays listed.
- A copy of itself that a stealer puts in a startup folder is now found, with a line saying to delete it.
- A folder named with invisible characters (to hide what a stealer collects) is shown with them marked.
- Shorter "Where it was sending": at most eight addresses found only in its memory are shown (all are kept in the
  evidence folder), and pieces of saved logins run together are no longer taken for web addresses.
- An empty file is no longer taken for a copy of a bait; the Credential Manager is listed once.

## v0.9.0

**Miner trap: hidden crypto miners are detected (Windows)**

- **A new trap for miners.** Hidden miners use your PC to make money for someone else, and to be paid they have
  to reach a mining pool. With the trap on, the names of the public pools miners use lead to a fake pool on this
  PC (a Windows name-resolution rule for those names only, and a small name server and fake pool in ABA's
  service, on the loopback address `127.97.98.97`). A program that logs in there to mine is frozen and cut off
  like a stealer at a bait, whatever it is: a miner hidden inside `conhost.exe`, a program Microsoft signed, is
  caught by its login, which no signature or trust rule changes. The alert names the wallet it mines for, the
  pool it wanted, what the miner calls itself and where the program came from. Nothing reaches the real pool
  and nothing is sent anywhere. Tested against a real SilentCryptoMiner (XMRig inside two hollowed `conhost.exe`)
  in an isolated lab.
- `aba miners on|off|test`. The test runs a harmless fake miner that looks up a real pool's name and logs in.
  Turning the trap off, or uninstalling, removes the rule at once. `aba doctor` and the dashboard show it.
- Someone who mines on purpose is told, in the alert, how to turn the trap off and let their miner go.
- The alert also says to run a full antivirus scan: whatever started the miner (often a hidden watchdog) may
  still be on the PC and start it again.

**Setup asks about clippers and miners**

- Both setups (terminal and ABA-Setup.exe) ask whether to detect clippers (the clipboard bait, which used to be
  off unless you knew to switch it on) and hidden miners, each with a sentence on what it does. Both are
  recommended; the miner trap unless you mine yourself. An install from before is asked once, the next time setup
  runs with "Keep my settings". The review and the "Saving your settings" line say what's on.
- A silent install, an update and `aba install --yes` never switch either on by themselves: `/CLIPPERS=1`,
  `/MINERS=1` and `--clippers`, `--miners` do.

**Fixed**

- **A stealer going through several apps' data is frozen again in every case.** Since v0.8.0, a program already
  caught sweeping other apps' data that then opened the fake Brave's `Local State` (on a PC without Brave) could
  leave ABA waiting on itself: ABA checked whether a real Brave had taken over the fake profile by reading that same
  bait while it was holding it. The program stayed paused but was never reported as critical, and that bait went
  unguarded. ABA no longer reads its own baits to decide.

## v0.8.0

After a catch, ABA answers the question it used to leave you with: did it already take my real passwords,
cookies or keys?

**Installing a browser is no longer taken for a stealer**

- **A browser looking for other browsers to import from is left alone.** Brave, installed the normal way,
  opened the fake Vivaldi, Opera and Yandex `Local State` files on its first start (it does on every start)
  and was frozen as a stealer going through three apps' data, its internet cut, with an autopsy saying to
  change your passwords. A genuine, installed browser opening another browser's `Local State` (the list of
  its profiles) is now a quiet note and never counts toward a sweep. The same browser going on to other
  browsers' saved passwords, cookies or card data is stopped as before.
- **A real app that moves into its decoy is at home there.** Its reads and writes of that folder, and of a
  bait living inside it (the MetaMask wallet in a fake browser), no longer count toward a sweep or turn an
  alert into "possible ransomware".
- **A browser that moves into its fake profile starts without "Profile error occurred".** The fake profile's
  Web Data claimed a version Brave then failed to upgrade; it now carries one old enough that the browser
  starts that file afresh. The decoy is retired once the browser has closed, not from under it; you're told
  once (not on every start in between), and the browser holding those files open meanwhile isn't reported
  as weakening ABA.
- **When the event log shows that a program caught as a stealer went to overwrite or delete the bait**, you're
  told again (it's ransomware or a wiper, and what to do differs), so the popup and `aba alerts show` say the
  same thing. A program frozen inside that open "went to" overwrite it: it never did.
- Alerts ABA raises itself (a decoy retired, a bait put back) name ABA, not "unknown process".

**A stealer running inside the genuine browser (Windows)**

- **The browser opening the fake profile inside it is critical now, not a warning.** Cookie stealers get past
  the browser's own encryption by starting the genuine browser themselves, suspended and without a window,
  and running their code inside it; that code goes through every profile, the fake one included.
- **Which browser it is decides what happens.** One that was started suspended and never ran, started
  hidden, has no window on your screen, or was started by a program ABA would stop itself is nobody's
  browser: it's frozen whole, from its main process, together with what started it (even a signed runtime
  like Python, when it created the browser suspended). The starter's internet is cut, never the browser's.
  A browser created suspended is frozen while its open of the fake profile is still held, so the code
  inside gets nothing.
- **The browser window you're using is never frozen or killed**, whatever the preset: ABA cuts the internet
  of every window of that browser and tells you so. The popup's *Yes* gives it back (`aba resume`); nothing
  gets trusted. ABA first gives it a moment, in case you just added a profile and it's taking the folder as
  its own, and skips the autopsy (your browser reads your real cookies all day).
- **One that had already exited when ABA looked** is reported as critical, with nothing left to freeze.
- **One alert and one freeze per browser**, however many of its processes open the fake profile. Such an
  alert is never trusted from the popup or `aba trust`: that would let every later stealer inside the same
  browser through.
- **A browser installed in your own folders** is no longer frozen for a moment on the first,
  unsigned-looking guess before its signature is checked.
- **Adding a profile in your browser no longer walks into the fake one.** Chrome, Edge and Brave name a new
  profile after how many they have ever made; when that count comes near the fake profile's number, ABA
  moves the fake further out. If the browser takes its folder all the same, ABA says so in plain words,
  cuts nothing, and puts a new fake profile under another name instead of retiring it.
- **A browser's fake-profile read no longer counts toward a sweep split over several programs.** Your own
  browser reading a bait once could be frozen as the "last member" of a stealer's team; and the autopsy no
  longer counts a genuine browser's opens of its own data as taken.
- **A read by a program that looks legitimate no longer interrupts you.** Edge, for one, opens the password
  list on your Desktop after every start; ABA rated that "looks legitimate" and still popped up a question,
  again every 12 hours. Such reads (signed, installed software, nothing done about them) are now noted quietly:
  in `aba alerts`, where you can trust them, but no popup, nothing waiting for an answer, and on the phone only
  if you asked for every alert there. If the same program goes on to change or delete a bait, or turns out to
  be part of a sweep, you hear about it as before.
- **After you resume or release an alert, the same program going for a bait again is a new alert** with a new
  response; it used to be added quietly to the old one for two minutes.
- **`aba alerts show`** prints when each bait was touched in local time, like the rest of the alert.
- **The autopsy no longer calls a browser's own work a theft.** When something in a browser that had been
  running normally (one you started, or one waiting in the background) opened the fake profile, the autopsy
  said "It opened your Brave. Act on it now." because the browser had opened its own profile, as it always
  does. Now it says it can't tell which of those opens were for the code inside it, and to treat what's saved
  in that browser as taken. A browser a stealer started suspended is judged as before, and a browser
  rewriting its own Local State is no longer reported as a copy of it.
- **`aba alerts`** says "left running" for the browser you're using, instead of an empty item in its line.
- **Your answer to an alert stays answered.** When you resumed or killed a program while its autopsy was still
  running, the autopsy's result put the alert back to "open"; what you did is now kept.

**The flight recorder**

- **ABA quietly notes who opens your real secrets**: the browser profiles, wallets, Telegram and Discord
  sessions, SSH and cloud keys, and the system's own password store, in the places the baits already know
  about. It keeps that in memory and never alerts on it; it's only read after ABA has caught something.
  `aba recorder on|off` (on by default).
- **On Windows** it's an audit rule on the folders those files are in, inherited only by the files directly
  in each folder and only for reading data, added beside any rules already there. Browsers replace some of
  these files all the time, which takes a rule on the file itself with it; a rule on the folder covers the
  new file at once. A folder that logs more than 600 opens in an hour is let go of for a day, so the
  Security log keeps room for the baits. The folders are listed in ABA's state and the rules come off on
  uninstall.
- **On Linux** it's fanotify marks on the same folders, reporting opens of the files in them (never reads,
  and nothing is held). **On macOS** it's the same eslogger stream the baits use, whose filter is now about
  ten times cheaper per line than before, with the recorder's paths included.

**The autopsy**

- **A moment after the alert, while the program is still frozen,** ABA looks into it: which real stores it,
  or something it started, opened and when (relative to the bait); the files it has open; files that
  appeared where stealers stage what they collect, and the names inside an archive it made (each marked as
  a bait, a byte-for-byte copy of your real file, or merely named like one); and where it was sending, from
  its open connections and from the shapes of a Telegram bot, a Discord webhook or a web address in its
  memory and its program file. Never per-family config parsing.
- **One of three answers, in the alert:** it read these real things (and what to do about each, now); no
  sign it read anything real, with what ABA was watching and since when; or ABA can't tell, and why (the
  recorder was off or started after the program, an opener it couldn't pin down, a store that wasn't
  watched the whole time). "It read" needs proof; "no sign" is never worded as "nothing was taken".
- **When it read real data, you're told again,** on the desktop and the phone, with the first thing to do.
- **`aba autopsy <id>`** shows everything found. **`aba export-ioc <id>`** writes a local file of what's safe
  to share: the program's fingerprint, the bot tokens, webhooks and addresses that are certainly the
  attacker's, the attacker's wallet for a clipper, and nothing of yours. Nothing is ever uploaded.
- **An evidence folder** (administrators only) is saved before anything can end the program: what was found,
  a copy of the program, copies of what it staged, and a copy of its memory. The last two may hold your own
  passwords and cookies, and say so. **`aba kill`** waits for it (or saves it itself), and a configured
  automatic kill waits for the autopsy.
- **Alerts say that only connections still open are known**: one the program had already closed isn't.

**Ransomware and wipers**

- **A program that destroys a bait is stopped like one that reads it.** Until now an open that couldn't
  read the bait was let through: opening it only to write, or deleting it, was at most reported. Now a
  program that would be stopped for reading a bait (unsigned in a user-writable folder, a script host) is
  stopped for going to overwrite or delete one, on Windows inside the open, before it can write. The alert
  says "Possible ransomware" or "Possible wiper or ransomware", and what it went to do.
- **Rewriting your documents in folder after folder is ransomware, whatever does it.** A program that goes
  to overwrite document baits in two different folders within two minutes is stopped even if it's signed
  or trusted by a rule: ransomware often runs inside a legitimate program. The system's own sync (OneDrive,
  iCloud) is exempt, and so is anything you've allowed to read everything.
- **A program that looks legitimate deleting a bait** (you in Explorer, a cleaner, a sync client) is still
  only reported, and the bait put back. So is PowerShell, cmd or another script host deleting one: that's
  you at a prompt. A script that deletes your documents in two folders within two minutes is stopped.
- **An alert made the instant a program opened a bait says what it went on to do.** Windows rarely says
  what an open asked for, so a wiper caught inside its open was first reported as a stealer; when the event
  log then says it overwrote or deleted the bait, the alert becomes one about ransomware or a wiper.
- **Windows** audits writes to a bait as well as reads and deletes (existing baits get the new rule when
  the service starts). **macOS** reports an open that only writes. **Linux** already held every open of a
  bait; a program that deletes one is now frozen when it's one that would be for reading it.
- ABA still doesn't bring back files ransomware reached before a bait: see *Honest limitations*.

**Baits**

- **A file of your own is never taken for a bait.** If the name ABA picked for a bait (say `Passwords.kdbx`
  in Documents) was already a file of yours, ABA used your file as the bait: it watched it, alerted when
  your own programs opened it, kept a text file's contents in its records, and put it back if you deleted
  it. Now the bait gets another name from its list, and if every one of them is taken, that bait isn't
  planted (`aba bait catalog` says why). A file you add yourself with `aba bait add <path>` is still used as
  it is. An install where this already happened isn't changed by updating: `aba bait remove <id>` takes
  ABA's hands off the file and leaves the file where it is.
- The licence names the project by its current name, and the one-line description no longer says "only
  malware would ever read" a bait: backup and sync tools do too, as the README has always said further down.

**macOS**

- Built with cgo (one package, for reading a frozen program's memory) for macOS 14 and later, signed with
  one hardened-runtime exception (`com.apple.security.cs.debugger`) that macOS requires for that.

**Installing (Windows)**

- **The one-line installer (`irm … | iex`) checks the release's signature**, like the Linux installer and the
  automatic updates already did. It only compared the download with the checksum list published next to it,
  which whoever could change the download could change too. Now that list has to be signed with ABA's
  release key, or nothing is run. (Windows PowerShell can't check this kind of signature itself, so the
  script carries the arithmetic; the tests run it against signatures that must and mustn't pass.)

## v0.7.1

The clipboard bait now works on real copies, and alerts say where a program came from.

**Clipboard bait**

- **Baits go out over what people really copy.** As SYSTEM, ABA's clipboard guard could read only the plain
  text of a copy, not the HTML a browser or editor puts next to it, nor what the new Notepad copies. It
  won't put a bait over what it can't put back, so it skipped nearly every real copy. Your clipboard is
  now saved and put back by a short-lived helper running as you; catching and freezing the clipper stays
  with SYSTEM.
- **`aba clipboard test` says why at once** when no bait went out (and what to do), instead of waiting
  30 seconds and saying ABA didn't catch it. It also says when the mouse or keyboard was used midway, and
  its own fake clipper no longer sets off a real alert.

**Alerts and baits**

- **Alerts say where the program came from.** ABA reads the mark browsers leave on what they download
  (Windows' Mark of the Web, macOS's quarantine and "where from" attributes, the address Linux browsers,
  curl and wget record) on the program, the script it ran, or what started it, and shows the address in
  `aba alerts show`, the popup and phone alerts. A program can fake that mark, so it's a lead, not proof.
- **Phone alerts name the computer**, for whoever gets alerts from more than one.
- **A fake profile inside your real Firefox** on Windows and macOS, as on Linux, and **saved git passwords**
  (`~/.git-credentials`) on Windows. Run `aba setup` to add them to an existing install.
- **The Windows SSH key bait gets its own name per install**, like the other files. Existing installs keep
  theirs until `aba bait rename`.
- **The after-a-detection checklist fits the computer:** no "reset Windows" on a Mac or Linux, and a clipper
  alert gets its own steps (check recent crypto transfers).

## v0.7.0

A click-through installer, ABA on macOS and Linux, a bait for clippers, and a website:
[abetterantivirus.com](https://abetterantivirus.com).

**Installing**

- **`ABA-Setup.exe`.** Download, double-click, answer two questions. It carries both the x64 and the Arm64
  program and installs the right one. Running it again repairs or upgrades ABA without touching your
  settings. It can also install silently with options (see `installer/README.md`). The PowerShell one-liner
  still works.
- **ABA shows up in Installed apps and the Start menu** as "A Better Antivirus", so you can find and
  uninstall it like any other program. The service keeps its low-profile name.

**macOS (early)**

- **ABA runs on macOS 14 or newer**, Apple silicon and Intel. It sees a program open a bait a few
  milliseconds after the open (through Apple's `eslogger`). It freezes the program with `pid_suspend`,
  which the program's own user can't undo, closes its connections, and in Strict mode cuts the whole Mac off
  the internet while ABA's own alerts still get out. It judges programs by their code signature and by what
  started them.
- **Copies made through Finder are traced back.** A script that has Finder copy a bait (Atomic's method)
  is found from Finder's own log and frozen. Finder's copy helper is frozen with it, but only then.
- **`ABA-macOS.pkg`** is signed and notarized by Apple, so it opens without a warning. ABA needs Full Disk
  Access: switch it on for "File Access Monitor" in System Settings. If iCloud syncs your Desktop and
  Documents, setup asks before planting decoys there, since they would show up on your other devices.
- **Not yet:** pausing a program inside its open before it reads (that needs an entitlement Apple hasn't
  granted yet), cutting just one program's internet, and the injected-code check.

**Linux (early)**

- **ABA runs on Linux with systemd.** The kernel (fanotify) stops a program inside its `open()` of a bait
  until ABA has judged it, so a stealer is frozen before it reads a byte. It's frozen in a control group its
  user can't thaw, cut off the internet (nftables), and in Strict mode the machine is isolated. Linux has no
  code signatures, so ABA goes by who installed the program (a package, in folders only root can write) and
  by what started it: `cat` typed in your terminal is a warning, the same `cat` run by a script from a
  download is a stealer.
- **Desktop popups** with the same choices as on Windows, a decoy put back within a second of being deleted
  (naming whoever did it), trust for a scheduled backup pinned to its exact command, and the full set of
  baits including a fake Firefox profile.
- **Install** with `curl -fsSL https://raw.githubusercontent.com/vulnix0x4/a-better-antivirus/main/install.sh | sh`
  (it checks the release's signature first), or with the `.deb`, `.rpm` or tarball. `aba update` works.

**Clipboard bait (Windows, off by default)**

- **`aba clipboard on`** catches clippers: malware that swaps a wallet address you copy for the
  attacker's. While nobody is using the PC, ABA puts a wallet address on the clipboard. A program that
  swaps it is frozen and your clipboard is put back. The addresses are real ones whose keys ABA holds
  (`aba clipboard key`). `aba clipboard test` shows it catching a harmless fake clipper.
- **A frozen program no longer makes every copy wait.** While a frozen program owned the clipboard, copying
  anything took about 5 seconds. ABA now takes the clipboard back from it.

**Fixes**

- **The service could crash at the moment it cut a frozen program's internet.** The program stayed frozen,
  but its internet block (and in Strict mode the PC's isolation) didn't happen. The cause was the Windows
  firewall library ABA uses, which put data at addresses Go's memory manager doesn't allow; ABA now carries
  a fixed copy of it.
- **A bait added a moment ago could be read without an alert,** if the read arrived before the service had
  taken in the new bait.
- **Removing a bait could leave its file behind for good,** where ABA no longer knew about it: when a
  program that had just read it still had it open, or when the service's regular check was running at that
  moment and put it back. `aba bait remove` now also says when it leaves a file in place, and why.
- **Messages no longer talk about Windows on macOS and Linux.**

## v0.6.0

Closing the ways around it. Every item here was a working bypass, found by going through ABA the way a
stealer's author would. The fixes come with tests that replay the bypasses.

**Finding the baits without touching them**

- **ABA's own files no longer give the baits away.** `C:\ProgramData\FileAccessMonitor` was readable by
  every program: `state.json` lists every bait, `config.json` every program you trusted and for which bait,
  the alerts and the log name baits too. One file read, and a stealer could walk around every tripwire. The
  folder is now for SYSTEM and administrators only (existing installs are tightened when the new service
  first starts). `aba` without admin rights still shows whether you're protected, from a small summary the
  service publishes (health and counts; no paths, names or alerts). `aba alerts`, `aba bait list`,
  `aba doctor` and the like now ask for admin. Alert popups get their alert handed over directly by the
  service instead of reading a file.
- **A fake "app installed" file no longer retires a decoy.** Decoys are retired when the real app turns up,
  and most of those apps install into your own profile, where no admin rights are needed: an empty
  `Discord\Update.exe` made ABA delete its Discord decoy within five minutes. Eight empty files and a short
  wait removed most of the tripwires. Now only a file signed by the app's publisher counts (or one in Program
  Files); anything else is reported as an attempt to switch a bait off, and the decoy stays. A real
  retirement is a warning you hear about, not a quiet note, and a second one within a day is refused.
- **"The real app read its own decoy" needs the real install.** The genuine, signed `Discord.exe` copied to
  another folder (or run with a DLL of the attacker's next to it) counted as Discord and retired the decoy.
- **Baits pass for ordinary files.** A folder listing shows a file's properties without opening it. Planted
  baits had all three timestamps identical to the tick, sat in folders created a minute ago, belonged to
  "Administrators", and were the only files in Documents marked "don't index". All four are fixed (owner and
  indexing on existing installs too).
- **Fake browser databases look used.** `Login Data`, `Cookies`, `Web Data`, `key4.db` were empty databases
  of exactly 4096 bytes on every install. They're now real SQLite files with the browser's tables and a few
  rows, of a size that differs per install (existing installs are upgraded in place).
- **Every install names its baits differently.** ABA is open source, so "skip `wallet recovery phrase.txt`"
  was a one-line bypass. New installs pick each file's name from a pool of what grabbers look for (and their
  own Firefox profile and LevelDB file names). Existing installs keep their names until you run
  `aba bait rename`, which picks a new set and replants the baits under it.
- **Baits inside the browsers you do use.** Decoys are fake data for apps you *don't* have, so a stealer
  that first checks the app is really installed never opens one. ABA now also plants a fake extra profile
  (`Profile 23` or so, next to `Default`) inside your real Chrome, Edge and Brave: stealers take every
  profile folder they find, and there "is it installed?" says yes. The browser only opens profiles it has
  listed, so it never touches the folder; if it ever takes it as a profile of its own, the bait is retired.
  The real browser reading a profile it doesn't know is a warning (something inside it is going through its
  data). On by default for new installs; existing ones get it the next time you run `aba install` or
  `aba configure`, or right away with `aba bait add chrome-profile` (`edge-profile`, `brave-profile`).
- `aba bait add` takes a catalog ID as well as a path, to switch on one bait without going through setup.

**Reading a bait without being seen**

- **Opening a bait "without waiting" no longer blinds instant freeze.** A program can ask Windows not to
  pause its open (`FILE_COMPLETE_IF_OPLOCKED`); then no thread is ever stuck and ABA found no one. Windows
  will say which programs hold a file open, though, and that open can't read until ABA lets go: the opener is
  now identified from that and frozen before it reads. Opening a bait that way is treated as what it is.
- **Reading through an execute-only mapping is logged.** A file opened for "execute" only can be mapped into
  memory and read there without read access ever being requested, which the audit rule didn't cover. It does
  now (existing baits get the new rule at the next start).
- **Reading through a hard link is recognised.** A hard link gives a bait a second name; the event then
  shows a path ABA had never heard of. Baits are now recognised by the file's identity, also when the link
  was deleted again right after.
- Any of these tricks makes the reader **critical whatever it is**: signed, part of Windows, or trusted by
  you. *It's mine* on such an alert never trusts it permanently. For the rare backup or security tool that
  really reads files that way, an administrator can allow it by name: `aba ignore add "<path>" --signer
  <publisher> --allow-tricks`.

**Escaping the response**

- **A frozen stealer stays frozen.** Any program running as you can resume a suspended process with one
  call, so a stealer with a second process un-froze itself. Frozen processes are now also held in a frozen
  job object that only the service can reach; `aba resume` and `aba release` have the service let go of it.
- **The whole stealer is frozen, not just the process that touched the bait:** the unsigned loader or script
  host that started it, and other running copies of the same file. A sweep split over several programs
  freezes all of them.
- **A stealer called `svchost.exe` can be frozen.** "Windows processes ABA never touches" went by name, so
  naming your malware `svchost.exe`, `explorer.exe` or `conhost.exe` made it untouchable from any folder. It
  now takes the real file in the folder Windows keeps it in.
- **Sweeps split over several processes are sweeps.** Reading three apps' data counted per process: one
  process (or one Windows tool) per app never reached three. Reads are now also counted across programs.
- **A program is judged by the file that's running.** A running program can rename its own file and put a
  signed one at the old path; ABA then verified the wrong file. Signature results are also no longer reused
  after the file at that path changed.
- **A copy of ABA is not a disguise.** A reader with ABA's own fingerprint was ignored completely: start a
  copy of `aba.exe`, inject into it, read everything. Now only ABA running as administrator is.
- **Sideloading is critical at the first bait.** A signed program in a user folder running an unsigned DLL
  from that same folder used to be a warning, like any signed program.
- **Running as you from a scheduled task isn't "a Windows service".** Such a task runs in session 0, which
  ABA treated as services: no sweep detection, no injection check, and Windows programs counted as harmless.
- Unsigned programs inside the Windows folder are critical (parts of it are writable without admin rights),
  and Windows tools that copy or upload a file for you (`extrac32`, `replace`, `print`, `certreq`, `scp`,
  `ftp`, `clip`…) count as script hosts, as do `more.com` and `choice.exe`, which loaders run inside.

**Also**

- **Fix: `aba test` could be used to run a program as administrator.** It wrote the fake stealer into your
  Temp folder under a guessable name and started it elevated, so anything running as you could swap the
  file in between. The file now has a random name, is locked and checked until it runs, and runs without
  admin rights (as a real stealer would). If the fake stealer itself fails to run, `aba test` now says that
  instead of reporting that ABA missed it.
- **Only administrators can send the service commands.** Windows lets every signed-in user send a service
  custom commands, and one of ABA's starts a full health check: any program could keep the service busy
  checking itself instead of watching. Existing installs are tightened when the new service first starts.
- The service's description no longer says it watches decoy files, and the status summary anyone can read no
  longer says how ABA is set to respond ("alerts only" or "still learning" told a stealer nothing would stop
  it). `aba` without admin rights shows health and counts; the response settings need admin.
- ABA says so when something keeps a bait open (which stops instant freeze from guarding it), and can no
  longer be locked out of a bait by changing the file's permissions.
- After a program lets go of a bait, instant freeze guards it again within a tenth of a second. It could
  take a full second, and an open in that gap wasn't paused (only logged).
- If the service is killed while something is frozen, what it froze is ended rather than left frozen with
  no way to thaw it.

## v0.5.4

- **A sweeping program is frozen before it gets the third app's data.** Instant freeze identifies who opened a
  bait by letting the open finish and seeing who wakes, so a program going through several apps' data was
  frozen just *after* opening the third, and a quick one (`find.exe` in a test) could read it and exit first.
  Now, when a program that already read two other apps' data is among those paused inside the open, it's
  frozen while still paused: it never gets the file.

## v0.5.3

- **Fix: instant freeze could blame the wrong program.** When ABA itself read one of its baits (its health
  check does, a second after the service starts), instant freeze looked for whichever program woke at that
  moment but left ABA's own threads out, so a program that happened to wake then could be reported as the
  opener and frozen for a read it never made. ABA's own reads are now recognised and blamed on no one.
  Found through an intermittent end-to-end test failure.

## v0.5.2

- **Stealers that run on Java, Python or Node are stopped at the first bait.** A `.jar` "game" double-clicked
  on the Desktop runs as `javaw.exe`, which is signed, so its first reads only counted as suspicious and it was
  stopped by sweep detection at the third app's data. Now a signed runtime running a script or `.jar` from your
  Desktop, Downloads or Temp folder is critical, like an unsigned program there: frozen the moment it opens
  the first bait. Scripts elsewhere (your projects, tools installed with npm or pip) are unchanged. Found by
  running a real Java stealer against v0.5.1.

## v0.5.1

- **Fix: the frozen popup's question was back to front.** It asked "Did you expect it to read this?" with
  *Yes = Kill it*, so answering honestly that you expected it killed the program. It now asks "Kill it?"
  (*Yes* kills it, *No* means it's yours), with the same reminder that games, mods, cheats and cracks never
  need to read your data.

## v0.5.0

A new look, and a setup that takes a minute.

- **Setup, rethought.** *Recommended* asks two things (phone alerts, automatic updates) and uses the
  recommended baits and response; *Customize* asks everything. A review screen shows what's about to
  happen before anything is installed. Running setup again offers *Keep my settings* (repair/upgrade in
  place) or *Change settings*; `aba configure` goes straight to changing them.
- **It ends with proof.** Setup sends a test to your phone when you've just set phone alerts up, then
  offers the safe test: a harmless fake stealer reads a bait and you watch ABA freeze it.
- **Clearer progress and a summary.** Install steps show what each one did, and the summary card shows
  what you're protected with and the three commands worth knowing.
- **One design everywhere.** A new wordmark, one colour palette (adapts to light terminals), and a
  status line at the top of the dashboard: *Protected*, *Needs attention*, *Not protected* or
  *Responding to a threat*. Alert lists show plain words ("frozen · internet cut") and short IDs, alert
  details wrap to the window, the network section groups connections by destination and hides local
  ones, and "What now" lists `trust`, `kill` and `resume` for that alert.
- **`aba --help`** groups commands by when you need them, most useful first.
- **The one-line installer** downloads quickly (no PowerShell progress bar), uses a fresh folder each time
  and removes it afterwards, explains what went wrong instead of dumping a PowerShell error, and makes
  `aba` work in the same window right away.
- Windows paths in setup no longer lose their backslashes.
- **Fix: a stealer could be frozen twice.** When Windows logged the read faster than instant freeze finished
  checking the program's signature, both detection paths froze it and raised an alert each; one "unfreeze"
  then left it suspended. Now only one path ever freezes a process: the event log waits for an instant
  decision in progress, and instant freeze stands down for a process the event log already froze.

## v0.4.0

Catching stealers that hide inside other programs, and trust that malware can't reuse.

- **Sweep detection.** A process that reads several different apps' baits within 2 minutes (your password
  files count as one; browsers, Discord, wallets… each count on their own) is stopped as a stealer, whatever
  it is: signed, trusted by you, or part of Windows. This catches stealers injected into a legitimate
  program, which look like that program to every identity check. With instant freeze it's frozen before it
  can open the third.
- **Injected-code check.** When a Windows program reads a bait, ABA looks inside it for a whole program
  running from memory that isn't backed by any file on disk, the footprint of process injection/hollowing.
  Found: critical, even if you trusted that program.
- **Windows programs are no longer trusted by default.** Before, any Microsoft-signed program under
  `C:\Windows` reading a bait was only noted, so a stealer hollowed into `AppLaunch.exe` or injected into
  `explorer.exe` raised no popup. Now Windows programs in your session are *suspicious* (Windows services and
  the preview pane stay quiet), and the .NET tools stealers hollow out most (AppLaunch, vbc, csc, jsc,
  aspnet_compiler, AddInProcess, cvtres, CasPol, ilasm) are critical, like RegAsm and MSBuild already were.
- **Trust is now as narrow as possible:**
  - covers only the bait(s) the program was seen reading;
  - unsigned programs are pinned to that exact file (SHA-256), not just its path;
  - script hosts and runtimes (`python.exe`, `powershell.exe`, `java.exe`…) are pinned to the exact command
    line, so trusting one script no longer trusts every script that runtime ever runs.
  Existing rules keep working as before (all baits).
- **The frozen popup asks the right question.** "Did you expect it to read this? Games, mods, cheats, cracks
  and "free" tools never need to, even ones you started yourself." Only signed programs can be trusted
  permanently in one click from it; anything else is unfrozen that once.
- **Repeat suppression no longer hides attacks:** script hosts/runtimes and critical alerts always notify.
- `aba ignore list` and `aba learn` show exactly what each rule covers.

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
