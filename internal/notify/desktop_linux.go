package notify

// Desktop alerts on Linux are notifications, through the desktop's
// notification service on the session bus (org.freedesktop.Notifications:
// GNOME, KDE, Xfce, Cinnamon, MATE, sway's mako and dunst all have one). This
// runs as you, started by the service into your session (see session).
//
// A question becomes a notification with a button per answer, where the
// desktop shows buttons ("actions"); it stays up until it's answered or
// closed. A desktop without buttons gets the notification with the commands
// to type instead. Running aba as root for an answer goes through pkexec:
// the desktop asks for an administrator's password, which is the proof that a
// person, not malware, asked for it.
//
// D-Bus is spoken with github.com/godbus/dbus, the pure-Go implementation the
// Go container and systemd tooling uses: the wire protocol and its
// authentication are easy to get subtly wrong by hand, and ABA builds
// without cgo.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	notifyName  = "org.freedesktop.Notifications"
	notifyPath  = "/org/freedesktop/Notifications"
	notifyIface = "org.freedesktop.Notifications"
	appName     = "A Better Antivirus"
)

var (
	lastToastErr string
	lastID       uint32 // the toast a question replaces, so they don't stack up
)

type desktop struct {
	conn    *dbus.Conn
	actions bool // shows buttons
	markup  bool // reads the body as markup: <, > and & must be escaped
}

// sessionBus connects to this user's session bus, the one the service named
// (never one started on the fly).
func sessionBus() (*dbus.Conn, error) {
	addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if addr == "" {
		rt := os.Getenv("XDG_RUNTIME_DIR")
		if rt == "" {
			return nil, errors.New("no session bus")
		}
		addr = "unix:path=" + filepath.Join(rt, "bus")
	}
	return dbus.Connect(addr)
}

func openDesktop() (*desktop, error) {
	c, err := sessionBus()
	if err != nil {
		return nil, err
	}
	d := &desktop{conn: c}
	var caps []string
	if err := c.Object(notifyName, notifyPath).Call(notifyIface+".GetCapabilities", 0).Store(&caps); err != nil {
		c.Close()
		return nil, fmt.Errorf("no notification service on this desktop: %w", err)
	}
	for _, cp := range caps {
		d.actions = d.actions || cp == "actions"
		d.markup = d.markup || cp == "body-markup"
	}
	return d, nil
}

func (d *desktop) text(s string) string {
	if !d.markup {
		return s
	}
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// show puts a notification up and returns its ID. urgency: 0 low, 1 normal,
// 2 critical (stays until dismissed); timeout in ms, -1 for the desktop's
// default, 0 for never.
func (d *desktop) show(replaces uint32, icon, title, body string, actions []string, urgency byte, timeout int32) (uint32, error) {
	hints := map[string]dbus.Variant{"urgency": dbus.MakeVariant(urgency)}
	if len(actions) > 0 {
		hints["resident"] = dbus.MakeVariant(true)
	}
	var id uint32
	err := d.conn.Object(notifyName, notifyPath).Call(notifyIface+".Notify", 0,
		appName, replaces, icon, title, d.text(body), actions, hints, timeout).Store(&id)
	return id, err
}

// Toast shows a desktop notification (best effort, non-blocking).
func Toast(title, body string) {
	d, err := openDesktop()
	if err != nil {
		lastToastErr = err.Error()
		return
	}
	defer d.conn.Close()
	id, err := d.show(0, "dialog-information", title, body, nil, 1, -1)
	if err != nil {
		lastToastErr = err.Error()
		return
	}
	lastID = id
}

// answer is one button: what messageBox returns for it, and its label.
type answer struct {
	key   string
	id    int32
	label string
}

// buttons turns the "Yes = …" lines the shared code writes for a Windows
// message box into buttons with those words on them, and the lines into a
// plain list.
func buttons(text string, flags uint32) (string, []answer) {
	var all []answer
	switch flags & 0xf {
	case mbYesNoCancel:
		all = []answer{{"yes", idYes, "Yes"}, {"no", idNo, "No"}, {"cancel", 2, "Cancel"}}
	case mbYesNo:
		all = []answer{{"yes", idYes, "Yes"}, {"no", idNo, "No"}}
	default:
		return text, nil
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		for j := range all {
			prefix := all[j].label + " = "
			if !strings.HasPrefix(l, prefix) {
				continue
			}
			what := strings.TrimPrefix(l, prefix)
			lines[i] = "• " + what
			// The button gets the words before any explanation:
			// "It's mine: unfreeze it…" → "It's mine".
			if k := strings.IndexAny(what, ":("); k > 3 {
				what = strings.TrimSpace(what[:k])
			}
			all[j].label = what
		}
	}
	return strings.Join(lines, "\n"), all
}

// messageBox puts a question on the screen and waits for the answer. flags
// say which buttons and icon (mbYesNo, mbIconError…); the answer is idYes,
// idNo, or anything else for "closed without choosing".
func messageBox(title, text string, flags uint32) int32 {
	d, err := openDesktop()
	if err != nil {
		lastToastErr = err.Error()
		return 0
	}
	defer d.conn.Close()
	icon, urgency := "dialog-information", byte(1)
	switch {
	case flags&0xf0 == mbIconError:
		icon, urgency = "dialog-error", 2
	case flags&0xf0 == mbIconWarning:
		icon = "dialog-warning"
	}
	body, answers := buttons(text, flags)
	if len(answers) == 0 || !d.actions {
		if len(answers) > 0 {
			body += "\n\nThis desktop doesn't show buttons on notifications: answer in a terminal (sudo aba alerts)."
		}
		d.show(lastID, icon, title, body, nil, urgency, 0)
		return 0
	}
	var acts []string
	for _, a := range answers {
		acts = append(acts, a.key, a.label)
	}
	if err := d.conn.AddMatchSignal(dbus.WithMatchObjectPath(notifyPath), dbus.WithMatchInterface(notifyIface)); err != nil {
		lastToastErr = err.Error()
		return 0
	}
	sig := make(chan *dbus.Signal, 16)
	d.conn.Signal(sig)
	id, err := d.show(lastID, icon, title, body, acts, urgency, 0)
	if err != nil {
		lastToastErr = err.Error()
		return 0
	}
	// Like a message box, it waits for you; not forever (a desktop that
	// forgets to say a notification went away would keep this here).
	limit := time.After(24 * time.Hour)
	for {
		select {
		case s, ok := <-sig:
			if !ok {
				return 0
			}
			if len(s.Body) < 2 {
				continue
			}
			if got, _ := s.Body[0].(uint32); got != id {
				continue
			}
			switch s.Name {
			case notifyIface + ".ActionInvoked":
				key, _ := s.Body[1].(string)
				for _, a := range answers {
					if a.key == key {
						d.close(id)
						return a.id
					}
				}
			case notifyIface + ".NotificationClosed":
				return 0
			}
		case <-limit:
			d.close(id)
			return 0
		}
	}
}

func (d *desktop) close(id uint32) {
	d.conn.Object(notifyName, notifyPath).Call(notifyIface+".CloseNotification", 0, id)
}

// RunElevated starts aba with args as root, after the desktop has asked for
// an administrator's password (pkexec). Where that can't be done, a
// notification says what to type instead.
func RunElevated(exe string, args ...string) error {
	typed := "sudo aba " + strings.Join(args, " ")
	pk := ""
	for _, p := range []string{"/usr/bin/pkexec", "/bin/pkexec"} {
		if _, err := os.Stat(p); err == nil {
			pk = p
			break
		}
	}
	var err error
	if pk == "" {
		err = errors.New("pkexec isn't installed")
	} else {
		cmd := exec.Command(pk, append([]string{exe}, args...)...)
		out, rerr := cmd.CombinedOutput()
		if rerr == nil {
			return nil
		}
		err = fmt.Errorf("%v: %s", rerr, strings.TrimSpace(string(out)))
		var ee *exec.ExitError
		if errors.As(rerr, &ee) && ee.ExitCode() == 126 {
			return err // you said no to the password prompt
		}
	}
	if d, derr := openDesktop(); derr == nil {
		d.show(0, "dialog-warning", "ABA: that needs administrator rights",
			"ABA couldn't ask for them here ("+err.Error()+"). In a terminal, run:\n"+typed, nil, 1, 0)
		d.conn.Close()
	}
	return err
}

// vouchLabel names what vouches for a program, in an alert's details: on
// Linux, a package ("Package: part of the git package", "Package: no package
// owns it").
const vouchLabel = "Package"
