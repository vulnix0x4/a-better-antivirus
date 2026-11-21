// Package netguard cuts network access: for one program, or for the whole PC
// except ABA's own alerts ("isolation").
//
// What it puts in place is persistent: it survives reboots and a stopped
// service, so a stealer can't wait out the isolation. `aba release` removes it.
//
// How is up to the operating system, in netguard_<os>.go: the Windows
// Filtering Platform on Windows; nftables and pf are the natural fits on
// Linux and macOS.
package netguard

// Status reports what ABA currently enforces.
type Status struct {
	Isolated bool
	Rules    int
}
