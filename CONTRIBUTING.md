# Contributing

Thanks for helping make stealers' lives harder. Bug reports, new bait ideas and fixes are all welcome.

## Reporting

- **Security issues:** privately, see [SECURITY.md](SECURITY.md). Not in public issues.
- **Bugs:** open an issue with `aba --version`, your Windows version, what you expected and what happened.
  `aba doctor` output and the end of `C:\ProgramData\FileAccessMonitor\service.log` help a lot.
- **False positives:** say which program tripped which bait (`aba alerts show <id>`), and whether it's a
  well-known app. These usually become a built-in rule.
- **New baits:** tell us which stealer families look where. Links to public malware analyses are perfect.

## Developing

You need Go (see `go.mod`). ABA itself only runs on Windows so far (see [Platforms](#platforms)).

```
go vet ./...
go test ./...
go build -o dist/aba.exe ./cmd/aba
```

Some tests touch real Windows security features (audit rules, the Security log, WFP filters) and need an
elevated shell:

```
$env:ABA_INTEGRATION = "1"; go test -count=1 -v ./internal/integration/
```

CI runs those plus `scripts/e2e.ps1`, a full end-to-end run on a throwaway Windows machine: install, fake
stealers, freeze/block/kill, isolation with a phone alert sent while isolated, bait repair, uninstall. Please
don't run the end-to-end script on your own PC: it isolates the network and plants baits. Use a VM.

## Platforms

ABA runs on Windows. Linux and macOS are being added, and the code is split so that a new system doesn't
touch the shared logic:

- **The core** is every file without a system in its name: the engine, the severity logic, alerts,
  configuration, the CLI, the service's main loop, the install plan. It makes no system calls, and it must
  build and pass its tests everywhere.
- **A backend** is the files named `*_windows.go`, `*_linux.go` or `*_darwin.go`, next to the core code that
  calls them. Go picks the file by its name, so there is nothing to register. Tests of one system's
  behaviour are named `*_<os>_test.go` the same way.

Linux and macOS have a stub for every such file today. Each returns `platform.ErrUnsupported` ("not
supported on Linux yet"), so everything builds there and nothing pretends to work. Porting is replacing
the stubs, keeping the same functions. What a system has to provide:

| Package | In its `_<os>.go` file |
|---|---|
| `service` | Running under the service manager, and noticing a bait being opened. Package `detect` says how to report one: `decideOpen` while the opener is held, `detect.Access` after the fact |
| `procinfo` | List and inspect processes, suspend, resume, kill, and `Hold`: keep one frozen so that nothing else running as the user can thaw it |
| `netguard` | Cut one program's network access; isolate the PC |
| `provenance` | `Verify`: who made a program, and does the system vouch for it (a code signature, or a package that owns the file) |
| `classify` | `rules_<os>.go`: script hosts and runtimes, the folders only administrators can write to, path patterns, the wording of a verdict |
| `baits` | The `Catalog` (where each app keeps its data there), making a planted file look used, and a tripwire on the file if the system needs one |
| `paths`, `config` | Where ABA lives and how names compare; encrypting the secrets, closing the data folder to non-admins, the state lock |
| `svcctl`, `install`, `doctor` | Registering, starting and signalling the service; the install steps and user lookup that differ; the system's own health check |
| `session`, `notify`, `cli` | Showing a popup to whoever is logged in; asking for administrator rights; the fake stealer of `aba test` |

Two rules keep the systems out of each other's way. Work in your system's files; if the core needs
something new from the system, add it to all three (a stub that returns `platform.Unsupported(...)` is
fine for the ones you can't write). And helpers only one system needs go in their own package, like
`winsec`, `evtlog` and `instant` for Windows.

CI vets and tests on Windows, Linux and macOS. To check the others from one machine:

```
GOOS=linux go vet ./...
GOOS=darwin go vet ./...
```

## Guidelines

- Keep the SYSTEM service boring and safe: never act on system processes or on ABA itself, never trust paths
  or data a non-admin user can write, and fail closed.
- Anything that changes Windows settings must be undone by `aba uninstall`.
- User-facing text: plain words, short sentences, say what happened and what to do next.
- Add a test for anything that decides whether something is malicious.

## Releasing (maintainers)

Push a `vX.Y.Z` tag. GitHub Actions runs the tests, builds with GoReleaser and signs `SHA256SUMS.txt` with the
release key (secret `ABA_SIGNING_KEY`). Installed copies with automatic updates on pick it up within a day.
