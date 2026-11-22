// Command notifyd is the stand-in desktop of the Linux end-to-end test
// (scripts/e2e-linux.sh): a notification service on the session bus
// (org.freedesktop.Notifications) that writes down every notification it's
// asked to show, and can press one of its buttons, the way a person would.
//
//	notifyd -out FILE [-press LABEL] [-no-actions]
//
// FILE gets one line per notification: "NOTIFY id | title | body | button,
// button…" (the body on one line), and "PRESSED id label" when it pressed
// one. With -press it presses the first button whose label contains LABEL, a
// second after the notification appears. With -no-actions it says it can't
// show buttons.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

type server struct {
	conn    *dbus.Conn
	out     string
	press   string
	actions bool
	mu      sync.Mutex
	next    uint32
}

func (s *server) note(format string, a ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	fmt.Fprintf(f, format+"\n", a...)
	f.Close()
}

func (s *server) GetCapabilities() ([]string, *dbus.Error) {
	caps := []string{"body"}
	if s.actions {
		caps = append(caps, "actions")
	}
	return caps, nil
}

func (s *server) GetServerInformation() (string, string, string, string, *dbus.Error) {
	return "aba-e2e-notifyd", "ABA", "1", "1.2", nil
}

func (s *server) CloseNotification(id uint32) *dbus.Error {
	s.note("CLOSED %d", id)
	s.conn.Emit("/org/freedesktop/Notifications", "org.freedesktop.Notifications.NotificationClosed", id, uint32(3))
	return nil
}

func (s *server) Notify(app string, replaces uint32, icon, title, body string, actions []string, hints map[string]dbus.Variant, timeout int32) (uint32, *dbus.Error) {
	s.mu.Lock()
	id := replaces
	if id == 0 {
		s.next++
		id = s.next
	}
	s.mu.Unlock()
	var labels []string
	for i := 1; i < len(actions); i += 2 {
		labels = append(labels, actions[i])
	}
	s.note("NOTIFY %d | %s | %s | %s", id, title, strings.ReplaceAll(body, "\n", " / "), strings.Join(labels, ", "))
	if s.press != "" {
		for i := 1; i < len(actions); i += 2 {
			if strings.Contains(actions[i], s.press) {
				key, label := actions[i-1], actions[i]
				go func() {
					time.Sleep(time.Second)
					s.note("PRESSED %d %s", id, label)
					s.conn.Emit("/org/freedesktop/Notifications", "org.freedesktop.Notifications.ActionInvoked", id, key)
				}()
				break
			}
		}
	}
	return id, nil
}

func main() {
	out := flag.String("out", "", "where to write the notifications")
	press := flag.String("press", "", "press the button whose label contains this")
	noActions := flag.Bool("no-actions", false, "say this desktop shows no buttons")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "notifyd: -out is required")
		os.Exit(2)
	}
	addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if addr == "" {
		addr = "unix:path=" + os.Getenv("XDG_RUNTIME_DIR") + "/bus"
	}
	conn, err := dbus.Connect(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "notifyd:", err)
		os.Exit(1)
	}
	s := &server{conn: conn, out: *out, press: *press, actions: !*noActions}
	if err := conn.Export(s, "/org/freedesktop/Notifications", "org.freedesktop.Notifications"); err != nil {
		fmt.Fprintln(os.Stderr, "notifyd:", err)
		os.Exit(1)
	}
	reply, err := conn.RequestName("org.freedesktop.Notifications", dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		fmt.Fprintln(os.Stderr, "notifyd: couldn't take the name:", err, reply)
		os.Exit(1)
	}
	s.note("READY")
	select {}
}
