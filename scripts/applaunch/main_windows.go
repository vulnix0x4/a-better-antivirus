// Command applaunch starts the desktop app the way the service will on a
// catch: run it as SYSTEM (a scheduled task, say) and it starts
// <app.exe> <args...> in every active session with session.LaunchApp, the
// person's elevated token and no UAC prompt. It prints what it did as JSON.
//
//	applaunch.exe "C:\Program Files\File Access Monitor\aba-app.exe" --alert <id>
//
// Test helper for the app's launch path (VM and CI); not part of ABA.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/vulnix0x4/a-better-antivirus/internal/session"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: applaunch <app.exe> [args...]")
		os.Exit(2)
	}
	launched, err := session.LaunchApp(os.Args[1], os.Args[2:]...)
	type row struct {
		Session  uint32 `json:"session"`
		PID      uint32 `json:"pid"`
		Token    string `json:"token"`
		Elevated bool   `json:"elevated"`
	}
	out := struct {
		Launched []row  `json:"launched"`
		Error    string `json:"error,omitempty"`
	}{Launched: []row{}}
	for _, l := range launched {
		out.Launched = append(out.Launched, row{l.Session, l.PID, l.Pick.String(), l.Pick.Elevated()})
	}
	if err != nil {
		out.Error = err.Error()
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	if err != nil || len(launched) == 0 {
		os.Exit(1)
	}
}
