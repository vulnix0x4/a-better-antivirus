// Package session starts a process on the desktop of every logged-in user.
// The service runs as the system, without a desktop of its own, so popups
// must be launched into the users' sessions, as those users.
//
// How is up to the operating system, in session_<os>.go.
package session
