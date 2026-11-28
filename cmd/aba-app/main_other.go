//go:build !windows

// Command aba-app is ABA's desktop app. Only Windows for now (phase 0);
// macOS and Linux need a security design of their own.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "aba-app: Windows only for now")
	os.Exit(1)
}
