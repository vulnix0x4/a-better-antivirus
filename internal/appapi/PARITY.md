# The app does what the CLI does

The owner's requirement: everything a person can do with `aba` they can do
in the desktop app. The CLI stays (the app runs it for every action).

Each row is a user-facing command, subcommand, flag or `aba configure`
step, with what the app reads it from (a bridge method, see CONTRACT.md)
and the `Act(kind, id, arg)` that does it. Every Act runs the installed
`aba.exe … --json --yes`; secrets go to it on standard input, never on its
command line (where any program on the PC can read them).

## Everyday

| CLI | App reads | App does (Act) | Notes |
|---|---|---|---|
| `aba`, `aba status`, `status --once` | `Snapshot()` | | the Home screen is the dashboard |
| `aba alerts`, `alerts --all` | `History()` (the newest 500) | | |
| `aba alerts show <id>` | `Alert(id)` | | |
| `aba alerts json <id>` | | `alert-json` (id) | details: the alert file as is (for "Copy raw") |
| `aba test` | | `test` | progress via `Progress()` |
| `aba doctor` | | `doctor` | details: `{checks}`; a check, so an Act (it looks at the service, Windows auditing, every bait file's metadata) rather than a read on every refresh |
| `aba doctor --fix` | | `doctor-fix` | details: `{fixed, checks}` |
| `aba learn` (list) | `Trusted().suggestions`, `.learning` | | |
| `aba learn` (tick several, trust them) | | `learn-trust` (arg: suggestion IDs, comma-separated) | new flag `aba learn --trust <id,…>` |
| `aba learn --extend N`, `--stop`, setup's "learning mode N days" | `Settings().learningUntil`, `Trusted().learning` | `learn-days` (arg `0`–`30`) | new flag `aba learn --days N` (N days from now; 0 ends it). `--extend` adds to the current end; the app sets it from now, as setup does |

## When something trips

| CLI | App reads | App does (Act) | Notes |
|---|---|---|---|
| `aba trust <id>` | `Alert(id).buttons`, `trustForGood` | `trust` (id) | |
| `aba kill <id>` | | `kill` (id) | |
| `aba resume <id>` | | `resume` (id) | |
| `aba resume <id> --ignore` | | `trust` (id) | the same thing ("It's mine") |
| `aba release` | | `release` ("") | |
| `aba release <id>` | | `release` (id) | |
| `aba report <id>`, `aba reports` | `Alert(id).report`, `History()` | | the app is the report now: no browser page |
| `aba autopsy <id>` | `Alert(id).report` (`sections` = what it prints) | | |
| `aba autopsy <id> --now` | | `autopsy-now` (id) | then read `Alert(id)` again |
| `aba export-ioc <id>` (`-o file`) | | `export-ioc` (id) | see "Where export-ioc writes" below; details `{path, ioc}` |

## Setup

| CLI | App reads | App does (Act) | Notes |
|---|---|---|---|
| `aba bait list` | `Baits()` | | |
| `aba bait catalog` | `Catalog()` | | |
| `aba bait show <id>` | | `bait-show` (id) | |
| `aba bait add <catalog id>`, setup's bait list (tick) | `Catalog()` | `bait-add` (id) | |
| `aba bait add <path>` | | `bait-add-file` (arg: the path) | new flag `aba bait add --file` (the argument is a path even if it looks like an ID); paths are checked (below) |
| `aba bait remove <id>`, setup's bait list (untick) | | `bait-remove` (id) | catalog or custom |
| `aba bait rename` | | `bait-rename` | |
| `aba ignore list` | `Trusted().rules` | | each rule has an `id` |
| `aba ignore add <pattern> [--signer S] [--note N] [--allow-tricks]` | | `ignore-add` (arg: JSON `{path, signer, note, allowTricks}`) | pattern checked (below) |
| `aba ignore remove <number>` | | `ignore-remove` (id: the rule's ID) | new: `ignore remove` also takes the rule's ID, which can't come to mean another rule the way a number can |
| `aba preset`, `preset alert/balanced/strict`, setup's "What should happen" | `Settings().preset`, `.presets` | `preset` (arg) | |
| setup's "Custom" response (per tier) | `Settings().responses`, `.actions` | `responses` (arg: JSON `{warn, critical}`) | new: `aba preset custom --warn a,b --critical a,b` |
| `aba instant on/off` | `Settings().instant` | `instant` | |
| `aba recorder on/off` | `Settings().recorder` | `recorder` | |
| `aba clipboard on/off`, setup's "Detect clippers?" | `Settings().clipboard` | `clipboard` | |
| `aba clipboard test` | | `clipboard-test` | |
| `aba clipboard key <address>` | | `clipboard-key` (id: the address) | the key is shown in a window of the app's own (not the page); see "Secrets" |
| `aba miners on/off`, setup's "Detect hidden crypto miners?" | `Settings().miners` | `miners` | |
| `aba miners test` | | `miners-test` | |
| `aba update` | `Settings().update` | `update` | |
| `aba update --check` | | `update-check` | |
| `aba update auto on/off`, setup's "Keep it up to date" | `Settings().update.auto` | `auto-update` | |
| `aba phone test` | | `phone-test` | |
| setup's phone alerts: ntfy (topic, server, token) | `Settings().phone.ntfy` (topic masked) | `phone-set` (arg: JSON, see CONTRACT.md) | new: `aba phone set` reads the same JSON on standard input |
| setup's phone alerts: Discord webhook | `Settings().phone.discord` (only that it's set) | `phone-set` | |
| setup's phone alerts: Pushover (app token, user key) | `Settings().phone.pushover` | `phone-set` | |
| setup's phone alerts: email (SMTP host, port, TLS, username, password, to) | `Settings().phone.email` (no password) | `phone-set` | `implicitTls` true = TLS from the start (465), false = STARTTLS (587) |
| setup's "Get alerts on your phone too?" → Not now | `Settings().phone.on` | `phone-off` | new: `aba phone off` |
| setup's "Which alerts should reach your phone?" | `Settings().phone.minTier` | `phone-tier` (arg `info`/`warn`/`critical`) | new: `aba phone tier` |
| (see the ntfy topic you set) | | `phone-reveal` | shown in a window of the app's own |
| setup's "Add canary tokens?" + email | `Settings().canary` | `canary-on` (arg: JSON `{email}`) | new: `aba canary` (status), `aba canary on` (email on standard input, or `--email` in a terminal) |
| setup's "Keep baits out of your Recent files?" | `Settings().cleanRecent` | `recent` (`on`/`off`) | new: `aba recent on/off` |
| setup's "Learning mode?" | see `learn-days` | | |
| `aba configure` (the whole wizard) | all of the above | each step on its own | the app changes one thing at a time, as the CLI commands above do; nothing is reinstalled |
| `aba uninstall` | | `uninstall` ("") | the app closes once it's done |
| `aba uninstall --purge` | | `uninstall` (`purge`) | |

## Not in the app

| CLI | Why |
|---|---|
| `aba install` (all its flags) | The app is installed by it (or by ABA-Setup.exe); there's no app before ABA is installed. Repairing an install is `doctor-fix`; every setting it takes is above. |
| `aba configure`'s "Keep my settings" (repair/upgrade in place) | That's `aba install --yes --keep-settings`, the setup program's job (it replaces the program files the app runs from). `doctor-fix` repairs what can be repaired while running. |
| `aba service run` | the service itself |
| `aba notify` | the service's popup and toast, run in your session |
| `aba test-reader`, `test-clipper`, `test-miner` | the harmless fake stealer, clipper and miner the tests start |
| `aba clipboard-guard`, `clipboard-free`, `clipboard-keeper` | the clipboard bait's helpers, started by the service |
| `aba window-check` | the service's helper for the instant freeze |
| `aba update apply` | the second half of an update, run by `aba update` |
| `aba notify --demo`, the hidden preview commands | for developers |
| `--json`, `--yes`, `--pause` | how the app runs the CLI |
| canary tokens off | not in the CLI either: once made, a token is in your baits and can only be switched off at canarytokens.org (the management links are in ABA's secrets file; uninstalling prints them) |

## Where export-ioc writes

The app is elevated, so writing a file is writing it as an administrator.
A path from the page (or a Save dialog the page opens) would let anything
that can drive the page choose where an administrator writes. So the app
asks for `aba export-ioc --downloads <id>`, which writes
`aba-ioc-<id>.json` into the protected person's own Downloads folder
(`config.User.Downloads`), never overwriting anything (it creates a new
file, `aba-ioc-<id> (2).json` and so on if the name is taken). The result
has the path (to show) and the file's contents (`details.ioc`, so the page
can offer Copy as well). Nothing is uploaded.

## What the app checks before the CLI runs

On top of the CLI's own checks (Command in act.go):

- IDs: alert IDs and bait IDs as before; a catalog bait must be in the
  catalog; a rule ID and a suggestion ID are 12 lowercase hex digits; an
  alert, planted bait or rule must exist.
- Custom bait paths: an absolute local path (`C:\…`), no `..`, no
  `\\?\` or network paths, no wildcards or control characters, at most 260
  characters, a file name at the end, and not in Windows, Program Files,
  ProgramData or ABA's own folders.
- Ignore patterns: an absolute local path pattern (or `**\…`), no control
  characters or quotes, at most 400 characters, and the file name part
  must name something (`*.exe`, `*`, `**` refused). Signer and note: plain
  text, at most 200 characters.
- Phone settings: ntfy server a plain `https://` (or `http://`) address,
  topic `A–Z a–z 0–9 _ -` up to 64; Discord a `https://discord.com/api/webhooks/<id>/<token>`
  address; Pushover keys 30 letters and digits; email host a host name,
  port 1–65535, addresses plain `name@domain`, no line breaks anywhere.
- Canary email: a plain address. Clipboard key: a Bitcoin, Ethereum or Tron
  address's shape.
- Responses: only the five actions, no repeats.

## Secrets

- The page never gets a stored secret back: not the ntfy topic (masked)
  or token, the Discord webhook, Pushover's keys, the SMTP password, the
  canary management links, or a clipboard bait's private key. (The page's
  WebView2 processes run with the person's ordinary rights: see
  docs/app-phase0.md.)
- The two things a person may need to see whole (their ntfy topic, to
  subscribe on the phone; a bait address's private key, should money ever
  be sent to it) are shown by the app itself in a native window
  (`phone-reveal`, `clipboard-key`); the page only learns it was shown.
- Secrets the page sends (`phone-set`, `canary-on`) reach the CLI on
  standard input, as JSON, never on its command line.
- `phone-set` with a secret field left empty keeps the stored one, when
  the channel is the same kind as now (so the form can be saved without
  typing the password again).
