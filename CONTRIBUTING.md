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

You need Go (see `go.mod`) on Windows.

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

## Guidelines

- Keep the SYSTEM service boring and safe: never act on system processes or on ABA itself, never trust paths
  or data a non-admin user can write, and fail closed.
- Anything that changes Windows settings must be undone by `aba uninstall`.
- User-facing text: plain words, short sentences, say what happened and what to do next.
- Add a test for anything that decides whether something is malicious.

## Releasing (maintainers)

Push a `vX.Y.Z` tag. GitHub Actions runs the tests, builds with GoReleaser and signs `SHA256SUMS.txt` with the
release key (secret `ABA_SIGNING_KEY`). Installed copies with automatic updates on pick it up within a day.
