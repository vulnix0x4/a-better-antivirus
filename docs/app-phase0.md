# Desktop app, phase 0: what the spike proved (2026-11-28)

Branch `app-phase0`. Code: `cmd/aba-app` (its own Go module, so Wails and
its dependencies stay out of the CLI's build), `internal/appsec`,
`internal/session` (`LaunchApp`, `apptoken.go`), `scripts/applaunch`,
`scripts/app-probe.ps1`, `.github/workflows/app-spike.yml`.

## The finding that changes the plan

**WebView2 never runs web content elevated.** When the app hosting it is
elevated, WebView2 (runtime 158 in the VM; Microsoft documents this as by
design and recommends keeping WebView2 hosts de-elevated) starts its
browser, GPU and renderer processes with the person's *filtered* token, at
medium integrity. Measured in the Arm VM (`scripts/app-probe.ps1`, run as an
ordinary medium-integrity program against the app open elevated):

| What a program running as the person tried | Result |
|---|---|
| OpenProcess(PROCESS_VM_READ) on `aba-app.exe` (elevated host) | denied (error 5) |
| OpenProcess + ReadProcessMemory on WebView2 browser, GPU, renderer | **succeeded** (the renderer holds the whole page) |
| UI Automation: find the page's button and Invoke it | **succeeded** (click reached the page) |
| SendInput: click the button, type keys | blocked (0 reached; an elevated control got 1 click + 3 keys) |
| Answer the host's native Yes/No box (UIA Invoke, click, `y` key) | blocked (box stayed open; elevated control's click answered it) |

So the plan's reason for an elevated UI ("UIPI: no SendInput/UIA, no memory
reads") holds only for SendInput and for the host process. Anything the page
shows can be read, and its buttons pressed, by same-user malware. Worse, the
medium-integrity browser process talks to the elevated host: every bridge
message is a lower program asking an administrator's process to act.

What still holds: the host process itself, its native dialogs, and the UAC
prompt are out of reach. So the design that survives is:

- the WebView shows only what may be seen by programs running as the person
  (no bait paths, no evidence content);
- every decision that matters ("It's mine", alert-only, traps or baits off)
  is confirmed outside the WebView: a native dialog owned by the elevated
  host (tested above), or a UAC prompt;
- the bridge stays a tiny allowlist with validated IDs, as planned, and is
  treated as untrusted input.

Whether the app then needs to run elevated at all (Microsoft's
recommendation is a de-elevated UI plus a separate elevated helper) is the
main design question for phase 1.

## Elevation model and launch from the service

- Manifest `asInvoker` (go-winres, `cmd/aba-app/winres`). Elevated: full
  view; not elevated: locked view whose "Open ABA" asks Windows to start it
  again elevated (UAC prompt appeared in the VM). Screenshots below.
- `session.LaunchApp` (from SYSTEM): WTSQueryUserToken, then the linked
  elevated token for a UAC-filtered admin, the token itself for a full
  admin (UAC off), the person's own token for a standard user (locked view).
  Run as SYSTEM through a scheduled task (`scripts/applaunch`): the app came
  up elevated in session 1 with `--alert <id>`, **no UAC prompt**
  (consent.exe never ran), self-test passed.

## Hardening, implemented and checked

- `WEBVIEW2_*` scrubbed from the app's environment (and from the
  environment block the service hands it). go-webview2's own init already
  blanks the five documented variables; the scrub catches the rest
  (verified with two undocumented names). Planted
  `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER`, `..._ADDITIONAL_BROWSER_ARGUMENTS
  =--remote-debugging-port=9222`, `..._USER_DATA_FOLDER`: all ignored (pinned
  runtime used, profile not redirected, port 9222 never opened).
- Runtime pinned: machine-wide Evergreen from HKLM, path checked
  (`<Program Files>\Microsoft\EdgeWebView\Application\<version>`), and every
  folder down to it plus `msedgewebview2.exe` and the
  `EmbeddedBrowserWebView.dll` loaded into the app checked admin-owned and
  not writable by anyone else.
- WebView2 profile: **cannot** be in the admin-only data folder (the
  de-elevated browser can't write there; WebView2 then stops at a "can't
  read and write to its data directory" box). It's in the person's
  LocalAppData; nothing in it is trusted by the host.
- Guard (`cmd/aba-app/guard_windows.go`): cancels every navigation away from
  the app's page, every new window and download; denies all permissions
  (Wails v2 grants all by default); filters Wails' IPC to what the app uses
  (drops BrowserOpenURL, events, drops...); DevTools, context menu, host
  objects, autofill, swipe, external drop off. If any part fails, the app
  shows nothing (fail closed).
- CSP: `default-src 'none'; script-src 'self' 'sha256-<import map>'; ...;
  connect-src 'none'; frame-src 'none'`, plus nosniff, no-referrer, COOP.
  Embedded assets only (no socket); vendored three.js 0.187.0 and fonts with
  a SHA-256 manifest checked by tests (npm tarballs checked against the
  registry's sha512).
- Single instance: a mutex in a private namespace bounded by the
  Administrators SID (a non-elevated caller gets access denied creating it).
- `--selftest` checks all of the above from inside the page each run.

## Wails v2 (v2.17.1)

Works as a library (`-tags desktop,production`, CGO off, `-H=windowsgui`),
cross-built from the Mac for amd64 and arm64. But it gives no access to the
WebView2 object or the UI thread, grants every permission, cancels no
navigation/new window/download, and its JS runtime exposes BrowserOpenURL.
The guard reaches its `*edge.Chromium` by reflection and runs on the UI
thread by subclassing the window: it works, it's pinned to v2.17.1, and the
self-test catches a break, but it is the riskiest code in the spike. Two
traps found: Wails/go-webview2 lock the main thread as a COM STA before
`main`, and `SHGetKnownFolderPath` never returned there (now read from
HKLM).

Wails v3: still nightlies only (v3.2.0-nightly.20261123 on 2026-11-28).

## Numbers

See the results section of the phase 0 report (sizes, CI, VirusTotal,
Defender) in the PR description.
