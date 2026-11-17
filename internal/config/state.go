package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// State is runtime state owned by the service, also updated by the elevated
// CLI (release/kill/resume). Always modify it through UpdateState.
type State struct {
	Baits            map[string]*BaitState `json:"baits"`
	AuditOriginal    *uint32               `json:"auditOriginal,omitempty"` // File System audit flags before install
	Bookmark         string                `json:"bookmark,omitempty"`      // event log position
	Isolation        *Isolation            `json:"isolation,omitempty"`
	Blocked          []BlockedProgram      `json:"blocked,omitempty"`
	Frozen           []FrozenProcess       `json:"frozen,omitempty"`
	DisabledAdapters []string              `json:"disabledAdapters,omitempty"`
	DialCache        map[string][]string   `json:"dialCache,omitempty"` // host -> IPs, for alerts while isolated
	Heartbeat        time.Time             `json:"heartbeat"`
	ServiceVersion   string                `json:"serviceVersion,omitempty"`
	Health           []HealthItem          `json:"health,omitempty"`
	Persona          map[string]string     `json:"persona,omitempty"` // fake identity shared by all baits
}

type BaitState struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"` // "file" | "decoy" | "canary"
	Files       []BaitFile `json:"files"`
	CreatedDirs []string   `json:"createdDirs,omitempty"` // dirs ABA created (removed on uninstall/retire)
	Status      string     `json:"status"`                // ok | missing | retired | error
	StatusNote  string     `json:"statusNote,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastCheck   time.Time  `json:"lastCheck,omitempty"`
}

type BaitFile struct {
	Path    string    `json:"path"`
	Audit   bool      `json:"audit"`          // has the read/delete audit rule
	Text    string    `json:"text,omitempty"` // content for `bait show` (text baits only), so viewing never reads the file
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
	Created bool      `json:"created"` // ABA created it (vs adopted an existing file)
}

type Isolation struct {
	Since   time.Time `json:"since"`
	AlertID string    `json:"alertId"`
	Method  string    `json:"method"` // "wfp" | "adapters"
}

type BlockedProgram struct {
	Path    string    `json:"path"`
	AlertID string    `json:"alertId"`
	Since   time.Time `json:"since"`
}

type FrozenProcess struct {
	PID        uint32    `json:"pid"`
	CreateTime int64     `json:"createTime"` // FILETIME as int64; guards against PID reuse
	Image      string    `json:"image"`
	AlertID    string    `json:"alertId"`
	Since      time.Time `json:"since"`
}

type HealthItem struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

func NewState() *State {
	return &State{Baits: map[string]*BaitState{}, DialCache: map[string][]string{}}
}

// LoadState reads state without locking (safe: writes are atomic renames).
func LoadState() (*State, error) {
	b, err := os.ReadFile(paths.StateFile())
	if errors.Is(err, os.ErrNotExist) {
		return NewState(), nil
	}
	if err != nil {
		return nil, err
	}
	s := NewState()
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	if s.Baits == nil {
		s.Baits = map[string]*BaitState{}
	}
	if s.DialCache == nil {
		s.DialCache = map[string][]string{}
	}
	return s, nil
}

// UpdateState runs fn on the current state under a machine-wide mutex and
// saves the result. Requires admin (the data dir is admin-write-only).
// SlowLock, if set, is told whenever the state lock is held for more than 2 s
// (the service logs it). Long holds block `aba release` and friends.
var SlowLock func(held time.Duration, caller string)

func UpdateState(fn func(*State) error) error {
	unlock, err := lockState()
	if err != nil {
		return err
	}
	start := time.Now()
	defer func() {
		unlock()
		if d := time.Since(start); d > 2*time.Second && SlowLock != nil {
			_, file, line, _ := runtime.Caller(2)
			SlowLock(d, fmt.Sprintf("%s:%d", filepath.Base(file), line))
		}
	}()
	s, err := LoadState()
	if err != nil {
		return err
	}
	if err := fn(s); err != nil {
		return err
	}
	return writeJSONAtomic(paths.StateFile(), s)
}

func lockState() (func(), error) {
	name, _ := windows.UTF16PtrFromString(`Global\ABAStateLock`)
	// Explicit DACL: whichever of SYSTEM (service) or an elevated admin (CLI)
	// creates the mutex first, the other must be able to open it.
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateMutex(sa, false, name)
	if err != nil && h == 0 {
		return nil, fmt.Errorf("state lock: %w", err)
	}
	ev, err := windows.WaitForSingleObject(h, 30_000)
	if err != nil || (ev != windows.WAIT_OBJECT_0 && ev != windows.WAIT_ABANDONED) {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("state lock: timed out")
	}
	return func() {
		windows.ReleaseMutex(h)
		windows.CloseHandle(h)
	}, nil
}

func (s *State) IsFrozen(alertID string) bool {
	for _, f := range s.Frozen {
		if f.AlertID == alertID {
			return true
		}
	}
	return false
}

func (s *State) IsBlocked(path string) bool {
	for _, b := range s.Blocked {
		if paths.Same(b.Path, path) {
			return true
		}
	}
	return false
}
