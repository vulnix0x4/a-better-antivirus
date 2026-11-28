// Command aba catches infostealers in the act: it plants decoy files and
// fake app data, watches them with Windows file auditing, and freezes and
// cuts off anything suspicious that reads them.
package main

import (
	"os"

	"github.com/vulnix0x4/a-better-antivirus/internal/cli"
	"github.com/vulnix0x4/a-better-antivirus/internal/sysenv"
)

// Set by the release build: -ldflags "-X main.version=v0.1.0"
var version = "dev"

func main() {
	// Run as administrator by a person (an admin terminal, the app,
	// install.ps1), the environment is still theirs to have set: replace
	// what says where Windows, Program Files and ProgramData are, and what
	// loads code, before anything reads it (package sysenv).
	sysenv.CleanProcessIfElevated()
	cli.Version = version
	os.Exit(cli.Execute())
}
