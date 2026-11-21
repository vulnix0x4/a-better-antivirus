package svcctl

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// Status works without admin rights.
func Status() (State, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return Unknown, err
	}
	defer windows.CloseServiceHandle(h)
	name, _ := windows.UTF16PtrFromString(paths.ServiceName)
	s, err := windows.OpenService(h, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return NotInstalled, nil
		}
		return Unknown, err
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &st); err != nil {
		return Unknown, err
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		return Running, nil
	case windows.SERVICE_STOPPED:
		return Stopped, nil
	case windows.SERVICE_START_PENDING:
		return Starting, nil
	case windows.SERVICE_STOP_PENDING:
		return Stopping, nil
	}
	return Unknown, nil
}

// InstallOrUpdate registers the service to run exe at boot, as LocalSystem,
// restarting automatically if it ever dies.
func InstallOrUpdate(exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(paths.ServiceName)
	if err == nil {
		defer s.Close()
		c, err := s.Config()
		if err != nil {
			return err
		}
		c.BinaryPathName = fmt.Sprintf(`"%s" service run`, exe)
		c.DisplayName, c.Description, c.StartType = paths.ServiceDisplayName, paths.ServiceDescription, mgr.StartAutomatic
		if err := s.UpdateConfig(c); err != nil {
			return err
		}
	} else {
		s, err = m.CreateService(paths.ServiceName, exe, mgr.Config{
			DisplayName: paths.ServiceDisplayName,
			Description: paths.ServiceDescription,
			StartType:   mgr.StartAutomatic,
		}, "service", "run")
		if err != nil {
			return err
		}
		defer s.Close()
	}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 3600); err != nil {
		return err
	}
	_, err = Harden()
	return err
}

// Who may do what with the service. Windows' default lets every signed-in
// user send a service custom commands ("user-defined control"), and ABA has
// two: "check yourself now" and "a hold was released". So any program running
// as you could keep the service busy checking itself, which delays what it's
// there for. Now only SYSTEM and administrators may; everyone else can still
// see that the service exists and whether it's running (the dashboard needs
// that). Every ABA command that sends one already runs as administrator.
const lockedSDDL = "D:(A;;CCDCLCSWRPWPDTLOCRRCWD;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;IU)(A;;CCLCSWLORC;;;SU)"

// Harden restricts who may send the service commands (see lockedSDDL) and
// sets its description. Setup calls it as an administrator. The service calls
// it on itself at every start, as SYSTEM: that's how an install made by an
// older version gets it, on its first automatic update. changed reports
// whether anything had to be put right.
func Harden() (changed bool, err error) { return harden(paths.ServiceName, paths.ServiceDescription) }

func harden(name, description string) (changed bool, err error) {
	want, err := windows.SecurityDescriptorFromString(lockedSDDL)
	if err != nil {
		return false, err
	}
	dacl, _, err := want.DACL()
	if err != nil {
		return false, err
	}
	have, err := windows.GetNamedSecurityInfo(name, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("read the service's permissions: %w", err)
	}
	if aces(have.String()) != aces(want.String()) {
		set := func() error {
			return windows.SetNamedSecurityInfo(name, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
		}
		err := set()
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			// SYSTEM normally owns the service and an owner may always change
			// permissions. Should something else own it: take it over, then retry.
			if e := takeOwnership(name); e == nil {
				err = set()
			}
		}
		if err != nil {
			return false, fmt.Errorf("restrict the service's permissions: %w", err)
		}
		changed = true
	}

	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return changed, err
	}
	defer windows.CloseServiceHandle(m)
	n, _ := windows.UTF16PtrFromString(name)
	h, err := windows.OpenService(m, n, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_CHANGE_CONFIG)
	if err != nil {
		return changed, fmt.Errorf("open the service to set its description: %w", err)
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()
	if c, err := s.Config(); err == nil && c.Description == description {
		return changed, nil
	}
	d, _ := windows.UTF16PtrFromString(description)
	info := windows.SERVICE_DESCRIPTION{Description: d}
	if err := windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_DESCRIPTION, (*byte)(unsafe.Pointer(&info))); err != nil {
		return changed, fmt.Errorf("set the service's description: %w", err)
	}
	return true, nil
}

// aces is the part of a security descriptor's text that lists who may do
// what, without the flags in front of it (which Windows adds as it sees fit).
func aces(sddl string) string {
	if i := strings.Index(sddl, "("); i >= 0 {
		return sddl[i:]
	}
	return sddl
}

// takeOwnership makes the account this runs as the owner of the service.
func takeOwnership(name string) error {
	if err := winsec.EnablePrivilege("SeTakeOwnershipPrivilege"); err != nil {
		return err
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(name, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION, u.User.Sid, nil, nil, nil)
}

func open() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.OpenService(paths.ServiceName)
	if err != nil {
		m.Disconnect()
		return nil, nil, err
	}
	return m, s, nil
}

func Start() error {
	m, s, err := open()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	if st, _ := Status(); st == Running {
		return nil
	}
	if err := s.Start(); err != nil {
		return err
	}
	return waitFor(svc.Running, 20*time.Second)
}

func Stop() error {
	m, s, err := open()
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	if st, _ := Status(); st == Stopped || st == NotInstalled {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	return waitFor(svc.Stopped, 30*time.Second)
}

func Delete() error {
	Stop()
	m, s, err := open()
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	return s.Delete()
}

// How each Signal travels to the service: as a service control code. (Custom
// codes are 128-255.)
const (
	ControlCheckNow svc.Cmd = 128
	ControlReleased svc.Cmd = 129
)

// Send tells the running service something (see Signal).
func Send(sig Signal) error {
	switch sig {
	case Reload:
		return Control(svc.ParamChange)
	case CheckNow:
		return Control(ControlCheckNow)
	case Released:
		return Control(ControlReleased)
	}
	return fmt.Errorf("unknown signal %d", sig)
}

// Control sends a control code (e.g. svc.ParamChange to reload config).
func Control(c svc.Cmd) error {
	m, s, err := open()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	_, err = s.Control(c)
	return err
}

func waitFor(want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m, s, err := open()
		if err != nil {
			return err
		}
		q, err := s.Query()
		s.Close()
		m.Disconnect()
		if err != nil {
			return err
		}
		if q.State == want {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("service did not reach the expected state within %v (see %s)", timeout, paths.LogFile())
}
