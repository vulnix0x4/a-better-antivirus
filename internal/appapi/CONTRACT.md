# appapi: the contract between the app's page and Go

Schema 1. The Go types are in `types.go` (each field commented); the
fixtures in `testdata/*.json` are real output of the builders for realistic
scenarios (`scenarios_test.go`) and are checked by `go test`. Build and test
the page against them.

**Every string may come from a caught program** (its file name, command
line, download address, the webhook it sends to, file names in its zip).
Show strings with `textContent` / text nodes only, never `innerHTML`,
attributes built by concatenation, or URLs you navigate to.
`alert-hostile.json` is full of such strings: it must render as plain text.

Times are RFC 3339 (UTC in the fixtures; show them in local time). Sizes
are bytes. Optional times are left out when unknown. Lists are always
present (`[]`, never `null`).

`absent` (on every model that has it) lists parts of the design the
Phase 1 app does not have data for. Hide those parts:

| absent value | hide |
|---|---|
| `touchChart` | Home: "Bait touches, last 30 days" |
| `checklistTicks` | Full report: "0 of 3 done" and the ticks |
| `webhookShutdown` | Full report: "Shut down this webhook" (keep "Copy") |
| `blockedSends` | Full report: "3 sends blocked", "194 KB never left", the blue "stopped by the freeze" flow |
| `programSize` | Full report: the program's Size row |
| `replant` | Baits: "Replant" |
| `heartbeatTrace` | Baits: the heartbeat line (show "Armed, checked N min ago" from `lastCheck`) |

## Bridge (window.go.main.API)

All methods return promises. IDs are checked in Go; anything not on disk is
an error.

| method | returns | notes |
|---|---|---|
| `Info()` | `{mode, elevated, version, alert, runtime, guard, selftest, probe}` | `mode` "full" or "locked"; `alert` is the alert the app was opened for (`--alert`), or "" |
| `Snapshot()` | Snapshot | Home + the frame (title bar state, version) |
| `Alert(id)` | Alert | Caught screen + Full report |
| `History()` | History | |
| `Baits()` | Baits | |
| `Settings()` | Settings | |
| `Locked()` | Locked | the only data method that works in locked mode |
| `Act(kind, id, arg)` | Result `{ok, message, details?}` | see Actions |
| `Progress()` | `{running, kind, events: [Event]}` | events of the running `test` / `update` (poll every ~300 ms while Act is pending) |
| `OpenElevated()` | string | locked view's "Open ABA": "" or why it didn't happen |
| `Copy(text)` | bool | puts text (max 256 KB) on the clipboard (the page can't) |
| `Pending()` | string | an alert ID to show now ("" if none): set when ABA catches something while the app is open (poll every ~2 s) |

In full mode the data methods read the files fresh on every call: call
them again after an action and every few seconds on the Caught screen (the
report fills in as `report.pending` turns false).

## Snapshot (`home-protected.json`, `home-frozen.json`)

- `protection.state`: `protected` | `frozen` | `isolated` | `attention` | `stopped`;
  `headline` the words for it ("Protected", "Something is frozen", "Offline:
  something was caught", "Needs a look", "Not running"); `problems` what's
  wrong in sentences; `serviceRunning`, `heartbeat`, `health[]` ({name, ok,
  detail}) the service's checks; `isolatedSince`; `learning`, `learningUntil`.
- `baits`: `total` planted, `healthy`, `lastCheck`, `byKind[]` ({category,
  total, healthy}; categories Files, Browsers, Wallets, Apps, Credentials,
  Custom), `tags[]` ({id, label, icon, health}) most tempting first: the
  labels in the scene.
- `quietDays`: whole days since the last catch (or install); -1 unknown.
  `lastCatch`: time of the last catch.
- `preset`: {id `alert|balanced|strict|custom`, name "Balanced", says "On a
  catch: freeze it, cut its internet"}.
- `traps`: {baits (count), instant, recorder, clipboard {on, supported},
  miners {on, supported}}. Hide an unsupported trap.
- `update`: see UpdateView below.
- `waiting[]`: AlertRows waiting for an answer, newest first. When the app
  opens without an alert and this isn't empty, go to the Caught screen of
  `waiting[0]`.
- `frozen[]`: {alertId, program, pid, since} what's frozen now.
- `recentQuiet[]`: the last ≤10 harmless touches (AlertRows).

UpdateView: `version` running, `latest` newest seen, `available` (latest is
newer), `auto` (updates install themselves), `updatable` (false for a dev
build), `lastCheck`, `lastResult` (words), `updatedAt`.

## AlertRow (in History.items, Snapshot.waiting/recentQuiet)

`id`, `shortId` (the last part: what `aba kill` takes), `time`,
`category` (`stealer|miner|clipper|tamper|bait|test`), `tier`
(`info|warn|critical`), `outcome` (below), `program` (file name, "" for an
alert about ABA itself), `title` (ABA's full title), `line` (one short
sentence: "Stealer. Opened the Discord login bait."), `bait` (first bait's
label), `icon` (`stealer|miner|clipper|trusted|quiet|test|system`), `test`.

`outcome`: `frozen` (frozen now, waiting), `cut-off` (internet cut, not
frozen, waiting), `killed`, `trusted` ("It's mine"), `resumed` (let run once,
nothing trusted), `stopped` (was frozen; ended or released since),
`alerted` (told you, did nothing), `noted` (harmless, noted quietly),
`answered` (other).

## History (`history.json`)

`counts`: {total, caught (stopped or critical, not tests), frozen (now),
killed, trusted, quiet, tests}; `items[]` every alert newest first. The
12-week calendar is drawn from `items[].time` and `outcome`/`icon`.

## Alert (`alert-*.json`)

- Same as AlertRow: `id`, `shortId`, `time`, `category`, `tier`, `outcome`,
  `title`, `test`; plus `status` (`open|resolved|noted`), `note` (how it was
  answered), `summary`, `learning`.
- `frozenNow`, `frozenSince` ("Held in ice for 0:50" counts from here),
  `cutOff` (its internet is cut now), `isolated` (the PC is offline for this
  alert), `instant` (caught the moment it opened the bait), `latencyMs`
  ("froze it 0.12 s later"; 0 = unknown).
- `program` (absent for alerts about ABA itself): `name`, `path`, `pid`,
  `signed`, `signer`, `signature` (a sentence: "None. Nobody vouches for this
  file."), `sha256`, `folder` ("your Downloads folder", or ""), `startedBy`,
  `commandLine`, `user`, `exited`, `origin` {url, referrer, via, line}
  (where the browser said it was downloaded from: a lead, not proof).
- `baits[]`: {id, label, icon, name, path, access (`read|delete|write|swap|mine`), time}.
- `reasons[]`: why ABA rated it so.
- `did[]`: {action, ok, words ("Froze it", "Cut its internet", "Couldn't
  kill it: …"), time}.
- `buttons[]`: the answers it takes, in order: `kill` ("Kill it",
  recommended), `resume` ("Unfreeze once"), `trust` ("It's mine"), `release`
  ("Reconnect this PC"). Empty: nothing to answer (show what happened).
- `trustForGood`: "It's mine" trusts it from now on (for the baits it
  read); false: it lets it run this once and trusts nothing (say so).
- `checklist[]`: what to do after a critical catch (sentences; no ticks).
- `mine` {pool, wallet, agent} for a miner; `clipper` {wallet, note} for a
  clipper.
- `report`: the full report, absent when ABA didn't look into the program.

### report

- `pending` (still looking: show a spinner, poll), `started`, `finished`.
- `answer` to "did it take my real data?": `read` | `no-sign` | `cannot-tell`;
  `tone` `bad|warn|good`; `headline`; `summary[]`.
- `steps[]` "Do these now" (urgent when `stepsUrgent`, else "To be safe").
- `unsure[]` why ABA can't be sure; `leads[]` hints without proof.
- `dataLeft`: `sent` (assume taken) | `nothing` (proved nothing left once it
  had your data) | `cannot-tell` (with `dataLeftWhy[]`) | "" (not looked at).
- `baitAt` (the timeline's zero), `processStart`, `frozenAt`.
- `timeline[]`: {at, offsetMs (from baitAt; negative = before), kind
  `start|read|send|bait|frozen`, label ("Read your real Chrome cookies",
  "Sent 4.1 KB to discord.com", "Opened the Discord login bait", "Frozen"),
  detail, bad}. "Ran free for 1.9 s" = frozen.offsetMs − start.offsetMs.
- `reads[]`: {store, name ("your Chrome"), kind, path, at, offsetMs, count,
  pid, image, how (how ABA knows)}.
- `sends[]`: {to (address:port), host (name it looked up), bytes,
  bytesAfter, after (sent after it had your data), first, last, offsetMs,
  conns, lan, udp, pid, image, via}. "What left your PC" draws these.
- `addresses[]`: {kind `discord-webhook|telegram-bot|url|connection`, label,
  value, where `memory|file|memory+file|connection`, shareable}. "Where it
  was sending": show the first webhook/bot; Copy uses `Copy(value)`.
- `staged[]`: {path, name, folder, size, appeared, heldOpen (certainly
  its), what, archive, entries[] {name, size, tag, what}, more (not listed),
  saved (copy in evidence), baits, real}. `tag`: `bait` (fake, nothing lost),
  `real-copy` (the same bytes as your real file: "Real"), `named-like`
  (named like one, contents differ), "" (unknown).
- `unpacked[]` {dir, files, size}: its own code, unpacked while it ran.
- `watched[]` {name, state `watched|absent|not-seen`, why, since}.
- `openFiles[]` {path, pid, what}; `left[]` what will start it again.
- `attackerWallet`, `walletNote`.
- `evidence`: {saved, folder (admin-only), memoryImage, memoryScanned}.
- `notes[]` what couldn't be looked at.
- `sections[]` {key, title, lines[]}: the whole report as text (what `aba
  autopsy` prints; keys: answer, steps, unsure, leads, sent, reads, watched,
  open, staged, left, addresses, program, did, evidence, notes). "Copy" /
  "Save a shareable summary" copy these; show any section the layout
  doesn't cover as plain lines.

## Baits (`baits.json`)

`total`, `healthy`, `lastCheck`, `serviceRunning`, `checks[]` (= health:
"Instant freeze armed", "Backup watcher on", …), `items[]`:
{id, label, icon, name (catalog name), description ("Fake token, next to
the real one"), category, kind (`file|decoy|canary`), health
(`ok|missing|error`), healthNote, custom, createdAt, lastCheck, files[]
{path, tripwire, size}, hasText ("See what's inside" has text: Act
`bait-show`), touchedBy[] {alertId, program, time, outcome, access}}.

Icons (baits): `doc grid hashi vault globe chrome firefox wallet telegram
discord server cloud key git`.

## Settings (`settings.json`)

`preset` (`alert|balanced|strict|custom`), `presets[]` {id, name, says,
does[] of `alert|freeze|cut|offline`}, `instant`, `recorder`, `clipboard`
{on, supported}, `miners` {on, supported}, `phone` {on, via
(`ntfy|pushover|discord|email`)}, `update` (UpdateView), `learning`.

## Locked (`locked.json`, `locked-frozen.json`)

For a person without administrator rights: `mode` "locked", `version`,
`state`/`headline` (as Protection), `somethingFrozen` ("An administrator
needs to decide"), `isolated`, `baits`, `baitsHealthy`, `openAlerts`,
`heartbeat`, `health[]`, `alert` (the ID the app was opened for, nothing
else about it). One button: "Open ABA" → `OpenElevated()`.

## Actions: `Act(kind, id, arg)` → `{ok, message, details}`

`message` is one or a few plain sentences to show. `ok` false: show the
message as the error. Unknown kinds, bad IDs and bad args are refused
before anything runs.

| kind | id | arg | does | details |
|---|---|---|---|---|
| `kill` | alert | | "Kill it" (saves the evidence first; may take up to ~90 s) | |
| `resume` | alert | | "Unfreeze once", trusts nothing | |
| `trust` | alert | | "It's mine" | |
| `release` | alert or "" | | reconnect / unfreeze / unblock everything (for that alert) | |
| `instant` `clipboard` `miners` `recorder` | | `on`/`off` | switch a trap | |
| `auto-update` | | `on`/`off` | updates install themselves | |
| `preset` | | `alert`/`balanced`/`strict` | protection level | |
| `bait-show` | bait | | "See what's inside" (never opens the bait: the text ABA kept) | `{"files":[{"path","size","text","binary"}]}` |
| `test` | | | the safe test; progress via `Progress()` | `{"alertId": "…"}` |
| `update-check` | | | check for a new version | `{"current","latest","available","url"}` |
| `update` | | | install it; progress via `Progress()` | |
| `phone-test` | | | send a test phone alert | |

Events: `{event: "step"|"done", text, time}`.
