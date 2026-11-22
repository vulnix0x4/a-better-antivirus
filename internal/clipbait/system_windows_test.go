package clipbait

// The guard the way ABA really runs it: started by a service, as SYSTEM, in
// the session of whoever is logged on (session.StartSystem), against fake
// clippers running as that person, at their (lower) integrity level. Needs
// administrator rights, so it only runs when asked:
//
//	set ABA_CLIPBAIT_SYSTEM=1, then run the test binary elevated with
//	-test.run TestSystemGuard
//
// It installs a temporary service (ABAClipbaitTest) running this test binary,
// and removes it again. Still nothing touches the real clipboard: the guard,
// once running as SYSTEM in the session, moves into a private window station
// that it lets the person's account join, and starts the fakes in there.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/session"
)

const testService = "ABAClipbaitTest"

// systemReport is one line the SYSTEM guard writes.
type systemReport struct {
	Error    string `json:"error,omitempty"`
	Log      string `json:"log,omitempty"`
	Identity *struct {
		User      string `json:"user"`
		Session   uint32 `json:"session"`
		Integrity uint32 `json:"integrity"`
	} `json:"identity,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	Clipper   uint32   `json:"clipper,omitempty"`
	ClipperIL uint32   `json:"clipperIntegrity,omitempty"`
	Reader    uint32   `json:"reader,omitempty"`
	Found     *Finding `json:"found,omitempty"`
	Restored  string   `json:"restored,omitempty"`
	Done      bool     `json:"done,omitempty"`
}

func TestSystemGuard(t *testing.T) {
	if os.Getenv("ABA_CLIPBAIT_SYSTEM") != "1" {
		t.Skip("set ABA_CLIPBAIT_SYSTEM=1 and run elevated")
	}
	ids, _ := session.ActiveSessions()
	if len(ids) == 0 {
		t.Skip("nobody is logged on to a desktop")
	}
	sid := ids[0]
	exe, _ := os.Executable()
	logPath := filepath.Join(filepath.Dir(exe), "system-guard.log")
	os.Remove(logPath)

	m, err := mgr.Connect()
	if err != nil {
		t.Fatalf("service manager (run this elevated): %v", err)
	}
	defer m.Disconnect()
	if old, err := m.OpenService(testService); err == nil { // left over from a run that died
		old.Control(svc.Stop)
		old.Delete()
		old.Close()
		time.Sleep(2 * time.Second)
	}
	s, err := m.CreateService(testService, exe, mgr.Config{StartType: mgr.StartManual, DisplayName: "ABA clipboard bait test (temporary)"},
		"clipbait-service", strconv.Itoa(int(sid)), logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		s.Control(svc.Stop)
		s.Delete()
		s.Close()
	}()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}

	// Follow the log until the guard says it's done.
	deadline := time.Now().Add(5 * time.Minute)
	var reports []systemReport
	offset := int64(0)
	for done := false; !done && time.Now().Before(deadline); {
		time.Sleep(time.Second)
		f, err := os.Open(logPath)
		if err != nil {
			continue
		}
		f.Seek(offset, io.SeekStart)
		r := bufio.NewReader(f)
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				break
			}
			offset += int64(len(line))
			var rep systemReport
			if json.Unmarshal(line, &rep) != nil {
				t.Logf("guard: %s", line)
				continue
			}
			if rep.Log != "" {
				t.Logf("guard: %s", rep.Log)
			}
			reports = append(reports, rep)
			done = done || rep.Done || rep.Error != ""
		}
		f.Close()
	}

	identified, kinds := false, map[string]bool{}
	for _, r := range reports {
		switch {
		case r.Error != "":
			t.Fatalf("the SYSTEM guard: %s", r.Error)
		case r.Identity != nil:
			identified = true
			t.Logf("the guard ran as %s in session %d at integrity %#x", r.Identity.User, r.Identity.Session, r.Identity.Integrity)
			if r.Identity.User != "S-1-5-18" || r.Identity.Session != sid || r.Identity.Integrity < 0x4000 /* system integrity */ {
				t.Errorf("want SYSTEM (S-1-5-18) at system integrity in session %d", sid)
			}
		case r.Kind != "":
			kinds[r.Kind] = true
			f := r.Found
			if f == nil {
				t.Errorf("%s clipper (integrity %#x): no finding", r.Kind, r.ClipperIL)
				continue
			}
			t.Logf("%s clipper (pid %d, integrity %#x): %s -> %s in %v; blamed pid %d (%s), suspects %v; clipboard put back: %q",
				r.Kind, r.Clipper, r.ClipperIL, f.Bait, f.Replacement, f.Latency, f.PID, f.How, f.Suspects, r.Restored)
			if f.PID != r.Clipper {
				t.Errorf("%s: blamed pid %d, want the clipper %d (the reader is %d)", r.Kind, f.PID, r.Clipper, r.Reader)
			}
			if r.Restored != "a shopping list" {
				t.Errorf("%s: clipboard not put back: %q", r.Kind, r.Restored)
			}
		}
	}
	if !identified {
		t.Fatal("the guard never reported in (see the log above)")
	}
	for _, k := range []string{"window", "nowindow", "hitrun"} {
		if !kinds[k] {
			t.Errorf("no result for the %s clipper", k)
		}
	}
}

// systemSide runs the parts of TestSystemGuard that aren't the test itself,
// when the test binary is started as one of them. It reports whether it did.
func systemSide(args []string) bool {
	switch args[0] {
	case "clipbait-service": // as the temporary service: start the guard the way ABA does
		if len(args) < 3 {
			return true
		}
		id, _ := strconv.Atoi(args[1])
		svc.Run(testService, &testSvc{session: uint32(id), log: args[2]})
		return true
	case "clipbait-helper": // as SYSTEM, in the person's session
		runSystemGuard(os.Stdout)
		return true
	}
	return false
}

type testSvc struct {
	session uint32
	log     string
}

func (h *testSvc) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}
	f, err := os.Create(h.log)
	if err != nil {
		return false, 1
	}
	defer f.Close()
	exe, _ := os.Executable()
	hp, err := session.StartSystem(h.session, exe, "clipbait-helper")
	if err != nil {
		json.NewEncoder(f).Encode(systemReport{Error: "session.StartSystem: " + err.Error()})
		return false, 1
	}
	copied := make(chan struct{})
	go func() { io.Copy(f, hp.Out); close(copied) }()
	select {
	case <-copied:
	case <-time.After(4 * time.Minute):
	case <-req: // stop
	}
	hp.Stop()
	return false, 0
}

// runSystemGuard is the guard, running as SYSTEM in the person's session.
func runSystemGuard(out io.Writer) {
	enc := json.NewEncoder(out)
	say := func(r systemReport) { enc.Encode(r) }
	fail := func(format string, a ...any) { say(systemReport{Error: fmt.Sprintf(format, a...)}) }

	// Who are we?
	var me systemReport
	me.Identity = &struct {
		User      string `json:"user"`
		Session   uint32 `json:"session"`
		Integrity uint32 `json:"integrity"`
	}{}
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		me.Identity.User = u.User.Sid.String()
	}
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &me.Identity.Session)
	me.Identity.Integrity, _ = procinfo.IntegrityLevel(windows.GetCurrentProcessId())
	say(me)

	// The person, whose programs the fakes will be.
	var user windows.Token
	if err := windows.WTSQueryUserToken(me.Identity.Session, &user); err != nil {
		fail("WTSQueryUserToken: %v", err)
		return
	}
	defer user.Close()
	tu, err := user.GetTokenUser()
	if err != nil {
		fail("the person's account: %v", err)
		return
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;SY)(A;;GA;;;" + tu.User.Sid.String() + ")")
	if err != nil {
		fail("security descriptor: %v", err)
		return
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := privateStation(sa); err != nil {
		fail("private window station: %v", err)
		return
	}

	for _, kind := range []string{"window", "nowindow", "hitrun"} {
		rep := systemReport{Kind: kind}
		func() {
			g := &Guard{LastInput: func() uint32 { return 1 }, Window: 6 * time.Second, Confirm: 3 * time.Second,
				Logf: func(f string, a ...any) { say(systemReport{Log: fmt.Sprintf(kind+": "+f, a...)}) }}
			g.onThread = func() error {
				if r, _, e := pSetThreadDesktop.Call(testDesk); r == 0 {
					return fmt.Errorf("SetThreadDesktop: %v", e)
				}
				return nil
			}
			if err := g.Start(); err != nil {
				say(systemReport{Log: kind + ": starting the guard: " + err.Error()})
				return
			}
			defer g.Stop()
			job, cs, err := startAs(user, "reader", kind)
			if err != nil {
				say(systemReport{Log: kind + ": starting the fakes as the person: " + err.Error()})
				return
			}
			defer windows.CloseHandle(job)
			time.Sleep(time.Second)
			rep.Reader, rep.Clipper = cs[0], cs[1]
			rep.ClipperIL, _ = procinfo.IntegrityLevel(cs[1])
			g.Candidates = func() []uint32 { return cs }
			ok := false
			g.do(func() {
				if !openClip(g.hwnd) {
					return
				}
				defer closeClip()
				pEmptyClipboard.Call()
				u, _ := windows.UTF16FromString("a shopping list")
				ok = setFormat(cfUnicodeText, unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2))
			})
			if !ok {
				say(systemReport{Log: kind + ": couldn't set up the clipboard"})
				return
			}
			f, err := g.Cycle(Bitcoin)
			if err != nil {
				say(systemReport{Log: kind + ": cycle: " + err.Error()})
			}
			rep.Found = f
			g.Finish()
			g.do(func() {
				if openClip(g.hwnd) {
					rep.Restored = readText()
					closeClip()
				}
			})
		}()
		say(rep)
	}
	say(systemReport{Done: true})
}

// startAs starts fake programs (see fake) as the account of tok, inside the
// private window station, in a job that kills them when it's closed.
func startAs(tok windows.Token, roles ...string) (windows.Handle, []uint32, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, nil, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	exe, _ := os.Executable()
	var pids []uint32
	for _, role := range roles {
		block, _ := envBlock(append(os.Environ(), fakeEnv+"="+role))
		cl, _ := windows.UTF16PtrFromString(windows.EscapeArg(exe))
		si := &windows.StartupInfo{}
		si.Cb = uint32(unsafe.Sizeof(*si))
		si.Desktop, _ = windows.UTF16PtrFromString(testDeskPath)
		var pi windows.ProcessInformation
		flags := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT)
		if err := windows.CreateProcessAsUser(tok, nil, cl, nil, nil, false, flags, &block[0], nil, si, &pi); err != nil {
			windows.CloseHandle(job)
			return 0, nil, err
		}
		windows.AssignProcessToJobObject(job, pi.Process)
		windows.ResumeThread(pi.Thread)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
		pids = append(pids, pi.ProcessId)
	}
	return job, pids, nil
}
