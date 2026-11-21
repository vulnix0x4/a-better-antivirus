package config

// macOS isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a macOS backend has to provide.

import "github.com/vulnix0x4/a-better-antivirus/internal/platform"

// protect encrypts the secrets with a key the operating system keeps for this
// machine, so the file is useless when copied elsewhere; unprotect undoes it.
func protect(b []byte) ([]byte, error) {
	return nil, platform.Unsupported("storing secrets")
}

func unprotect(b []byte) ([]byte, error) {
	return nil, platform.Unsupported("storing secrets")
}

// restrictSecrets leaves the secrets file to the system and administrators
// only, whatever the folder it's in allows.
func restrictSecrets(path string) error {
	return platform.Unsupported("storing secrets")
}

// lockDir makes dir (and everything already in it) private to the system and
// administrators, except for its public subfolder, which anyone may read.
func lockDir(dir, public string) error {
	return platform.Unsupported("restricting ABA's data folder")
}

// lockState takes the machine-wide lock that the service and the CLI share
// while one of them changes the state file, and returns how to let go of it.
func lockState() (func(), error) {
	return nil, platform.Unsupported("ABA's state file")
}

// readableByAll opens the published status file to everyone. Not written for macOS yet.
func readableByAll(path string) error { return nil }
