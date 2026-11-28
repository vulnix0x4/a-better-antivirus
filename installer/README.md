# ABA-Setup.exe

The click-through installer: download one file, double-click, Next, Next, Finish.

It is a front end for ABA's own installer, not a second one. It carries the x64 and the Arm64 `aba.exe` (and
the same two builds of the ABA app, `aba-app.exe`), asks
the questions of the terminal setup's "Recommended" path (phone alerts, the clipper and miner traps, automatic
updates), and then runs

```
aba.exe install --yes --keep-settings --preset balanced --learning 0 --auto-update=... [--ntfy-topic ...] [--clippers=...] [--miners=...]
```

from the copy for this PC. ABA does the rest itself, exactly as it does when installed from PowerShell or by
hand: it copies itself to `C:\Program Files\File Access Monitor`, creates the service, plants the baits, and
adds its own entry to Windows' "Installed apps" list and a Start menu shortcut. It also puts the app that Setup
unpacked next to it (`aba-app.exe`) into the program folder, with a Start menu entry "ABA". `aba uninstall`
takes all of it away again, and the app's WebView2 profile (`%LocalAppData%\ABA\webview`) too. So Setup puts
no files on the PC and registers no uninstaller of its own.

The one thing Setup does itself: when this PC has no machine-wide Microsoft Edge WebView2 runtime (the app's
window needs it; a runtime installed for one person doesn't count, the app only uses the one in Program Files),
it offers to download Microsoft's Evergreen bootstrapper from `go.microsoft.com` and run it. Without WebView2 ABA
protects the PC the same; what it catches shows in a small window instead of the app.

| File | What it is |
|---|---|
| `aba.iss` | The Inno Setup script: pages, wording, and the call to `aba.exe install`. |
| `build/` | `go run ./installer/build`: compiles `aba.iss`. GoReleaser calls it once per built `aba.exe` and `aba-app.exe` (`-app`). |
| `get-inno.ps1` | Fetches the Inno Setup compiler (one fixed version, SHA-256 checked, no admin rights). |
| `verify.ps1` | Checks a GoReleaser `dist\` folder: the installer is in `SHA256SUMS.txt` and holds the published `aba.exe` files. |
| `test.ps1` | Installs, checks and uninstalls for real. **CI runners only.** |

## What Setup does when ABA is already there

| On the PC | Setup |
|---|---|
| No ABA | Asks its questions and installs. |
| An older version | Updates it. Asks nothing; every setting is kept. |
| The same version | Repairs it (program files, service, Windows setting, baits). Every setting is kept. |
| A newer version | Says so and stops. Nothing is changed. |
| A version it can't compare (a development build) | Asks whether to replace it. A silent install stops instead. |

"Already there" means ABA's settings file exists, the same test ABA uses. Settings can't be reset even if that
check were wrong: `--keep-settings` is always passed, and ABA itself then keeps what it has.

## Silent installs

```
ABA-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
```

installs with the same defaults as clicking Next all the way (recommended baits, Balanced response, no phone
alerts, automatic updates on), except the two traps: they stay off unless asked for, so a silent install never
turns on something that touches the clipboard or name lookups. Options (all optional):

| Option | Meaning |
|---|---|
| `/NTFYTOPIC=my-topic` | Send phone alerts to this [ntfy](https://ntfy.sh) topic. Letters, digits, `-` and `_`. |
| `/AUTOUPDATE=0` | Don't update automatically (`1`, the default, does). |
| `/CLIPPERS=1` | Detect clippers with the clipboard bait (`0` or not given: off). |
| `/WEBVIEW2=0` | Don't download Microsoft Edge WebView2 for the app if it's missing (`1`, the default, does). |
| `/MINERS=1` | Detect hidden crypto miners with the miner trap (`0` or not given: off). |
| `/PRESET=alert\|balanced\|strict` | What happens when something takes a bait. Default `balanced`. |
| `/LEARNING=3` | Days of learning mode. Only changes something with `strict`. Default `0`. |
| `/CANARYEMAIL=me@example.com` | Create canary tokens that email this address. |
| `/BAITS=id,id` | Plant these baits instead of the recommended set (`aba bait catalog` lists them). |
| `/LOG=setup.log` | Inno Setup's log, including every line ABA printed. Keep it private: it records Setup's command line, so it holds the ntfy topic if you passed one, and it names your user folder. Without `/LOG` nothing is written. |

These only count on a first install. If ABA is already set up, its settings are kept and the options are ignored.

Exit codes: `0` ABA is installed and running. `7` one of ABA's install steps failed (the log names it). `1`
Setup stopped before changing anything: a newer version is installed, or an option couldn't be used. Other
codes are [Inno Setup's](https://jrsoftware.org/ishelp/topic_setupexitcodes.htm).

To uninstall without questions: `aba uninstall --yes` (that is also the entry's `QuietUninstallString`).

## Building

A release builds it: GoReleaser's build hook (`.goreleaser.yaml`) gives each finished `aba.exe` to
`installer/build`, and the second one to arrive compiles `dist\installer\ABA-Setup.exe`. The checksum list is
written after that, so the installer's hash is in the signed `SHA256SUMS.txt`.

Locally, the same thing without signing or publishing:

```powershell
$env:ISCC = ./installer/get-inno.ps1      # once; unpacks Inno Setup into your temp folder
goreleaser release --snapshot --clean --skip=sign
./installer/verify.ps1
```

**Don't run the result on your own PC unless you mean to install ABA.** To look at the pages, build the
look-only version instead. It has no `aba.exe` inside, needs no administrator rights and can't install
anything; it plays back sample output where the real one runs ABA:

```powershell
go run ./installer/build -preview
dist\installer\ABA-Setup-preview.exe                         # a first install
dist\installer\ABA-Setup-preview.exe /PREVIEWSTATE=upgrade   # or repair, newer, unknown
dist\installer\ABA-Setup-preview.exe /PREVIEWRESULT=fail     # or warn
dist\installer\ABA-Setup-preview.exe /PREVIEWWEBVIEW2=missing  # the WebView2 page
```

## Changing things

- **Wording** is in `aba.iss`. Same rules as everywhere (CONTRIBUTING.md): plain words, short sentences, say
  what happened and what to do next. The "What Setup changes on your PC" page mirrors the README's table of
  the same name: change them together.
- **A new question** needs a flag on `aba install` first. Setup only passes answers on.
- **Anything that reaches `aba.exe`'s command line** must go through `OnlyChars` in `aba.iss`, so that nothing
  typed into Setup or passed to it can add an option.
- **The name in Installed apps and the Start menu** is `install.AppName` in the Go code, not here.
- **A newer Inno Setup:** change the version, URL and SHA-256 at the top of `get-inno.ps1`, in one commit.
