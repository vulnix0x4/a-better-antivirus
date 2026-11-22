package netguard

// On Linux the network is cut with nftables, the kernel's firewall, spoken to
// directly over netlink (no `nft` program needed).
//
// The firewall can't tell programs apart by their file, the way the Windows
// Filtering Platform does, but it can tell which control group a connection
// was made in. So cutting a program off is two halves:
//
//   - its running processes are moved into a control group of their own,
//     file-access-monitor.blocked (see procinfo.Disconnect), and so is every
//     process that starts the program later: the service watches the file
//     with fanotify and moves whoever executes it, inside its execve(), before
//     it runs an instruction of it. Whatever they start is born in the group.
//   - one table, inet file_access_monitor, drops every packet sent or received
//     through a connection made in that group. Loopback included: a stealer
//     can't hand its loot to a local proxy either.
//
// Isolating the machine adds rules to the same table that drop every new
// connection, in or out, and forwarded traffic (containers, VMs), except:
// loopback; connections made by ABA's service (its control group,
// system.slice/file-access-monitor.service), so the phone alert still gets
// out; the DHCP and IPv6 neighbour traffic that keeps the machine's address,
// so that the service still can. Like Windows' filters, it leaves connections
// that were open before alone: an administrator's SSH session to a server
// survives isolating it, so they can still run `aba release` on it. DNS goes
// through the system's resolver, which is cut off too; ABA reaches the alert
// server by the addresses it remembered (see notify.Dialer).
//
// What is in force is also written down, in a root-only file, so it comes
// back however the rules went away: the service puts it in place again when
// it starts (after a reboot too) and checks every second that the table is
// still there. The rules themselves live in the kernel: they stay when the
// service stops or crashes. Only root can change them; nothing running as
// you can (that takes CAP_NET_ADMIN, which "root" inside a container or a
// user namespace of its own doesn't have over this machine's firewall).
//
// No nftables (an old or stripped-down kernel, or a container that isn't
// allowed to touch the firewall): ABA says so, in the alert and in `aba
// doctor`, and doesn't fall back to iptables. The legacy iptables interface
// can only be driven by its own program and matches control groups only on
// some kernels; on such a machine, a frozen program still can't send
// anything, and "turn off the network adapters" still isolates.
//
// A program the system vouches for (a package owns it, in a folder only root
// can write to) is never cut off as a whole: bash, python3 or cat is every
// program's, and cutting the file off would cut off the system's own
// services. What ABA froze of it stays frozen, and isolation still applies.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

// TableName is the nftables table ABA keeps its rules in (family inet).
const TableName = "file_access_monitor"

const (
	tagCut     = "aba:cut-off"
	tagIsolate = "aba:isolate"
)

// ---- what is in force, on record ----

type record struct {
	Isolated bool      `json:"isolated,omitempty"`
	Permit   string    `json:"permit,omitempty"` // control group isolation lets through: the service's
	Programs []program `json:"programs,omitempty"`
}

type program struct {
	Path string `json:"path"`
	File string `json:"file,omitempty"` // paths.FileID of the file when it was cut off
}

func (r *record) empty() bool { return !r.Isolated && len(r.Programs) == 0 }

func (r *record) has(path string) bool {
	for _, p := range r.Programs {
		if p.Path == path {
			return true
		}
	}
	return false
}

func recordFile() string { return filepath.Join(paths.DataDir(), "network.json") }
func lockFile() string   { return filepath.Join(paths.RunDir(), "network.lock") }

func load() (*record, error) {
	r := &record{}
	b, err := os.ReadFile(recordFile())
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, r); err != nil {
		return &record{}, fmt.Errorf("%s: %w", recordFile(), err)
	}
	return r, nil
}

func save(r *record) error {
	if r.empty() {
		if err := os.Remove(recordFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(paths.DataDir(), 0o711); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	tmp := recordFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, recordFile())
}

var procMu sync.Mutex // the service changes the record from several goroutines

// update changes the record and puts the result in force, under a lock the
// CLI and the service share. A change that adds something is only kept if it
// could be put in force; taking something away is kept either way.
func update(adds bool, change func(r *record)) (*record, error) {
	procMu.Lock()
	defer procMu.Unlock()
	if err := os.MkdirAll(paths.RunDir(), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockFile(), os.O_CREATE|os.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	r, err := load()
	if err != nil && adds {
		return nil, err
	}
	change(r)
	aerr := apply(r)
	if aerr != nil && adds {
		return r, aerr
	}
	if err := save(r); err != nil {
		return r, err
	}
	return r, aerr
}

// ---- the firewall ----

// errNoFirewall explains why nftables can't be used here.
func errNoFirewall(err error) error {
	why := "the kernel's firewall (nftables) isn't available here"
	if errors.Is(err, unix.EPERM) {
		why = "ABA isn't allowed to change this machine's firewall (inside a container?)"
	}
	return fmt.Errorf("%s, so ABA can't cut network access on this machine: %v", why, err)
}

func inetTable() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
}

func conn() (*nftables.Conn, bool, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, false, errNoFirewall(err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, false, errNoFirewall(err)
	}
	for _, t := range tables {
		if t.Name == TableName {
			return c, true, nil
		}
	}
	return c, false, nil
}

// Available says whether ABA can cut network access on this machine, and if
// not, why.
func Available() error {
	_, _, err := conn()
	return err
}

// apply makes the table say what r says, in one transaction: a packet never
// sees half of it.
func apply(r *record) error {
	c, exists, err := conn()
	if err != nil {
		if r.empty() {
			return nil // nothing to put in force, and nothing can be there
		}
		return err
	}
	t := inetTable()
	if r.empty() {
		if !exists {
			return nil
		}
		c.DelTable(t)
		return c.Flush()
	}
	var cutID uint64
	if len(r.Programs) > 0 {
		g, err := procinfo.CutOffGroup()
		if err == nil {
			cutID, err = procinfo.CgroupID(g)
		}
		if err != nil {
			return fmt.Errorf("the control group for cut-off programs: %w", err)
		}
	}
	c.AddTable(t)
	if exists {
		c.DelTable(t)
		c.AddTable(t)
	}
	chain := func(name string, hook *nftables.ChainHook) *nftables.Chain {
		return c.AddChain(&nftables.Chain{Name: name, Table: t, Type: nftables.ChainTypeFilter, Hooknum: hook, Priority: nftables.ChainPriorityFilter})
	}
	out, in := chain("out", nftables.ChainHookOutput), chain("in", nftables.ChainHookInput)
	add := func(ch *nftables.Chain, tag string, exprs ...expr.Any) {
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: exprs, UserData: []byte(tag)})
	}
	if cutID != 0 {
		add(out, tagCut, concat(cgroupIs(1, cutID), counted(drop()))...)
		add(in, tagCut, concat(cgroupIs(1, cutID), counted(drop()))...)
	}
	if r.Isolated {
		fwd := chain("fwd", nftables.ChainHookForward)
		add(out, tagIsolate, concat(ifname(expr.MetaKeyOIFNAME, "lo"), accept())...)
		add(in, tagIsolate, concat(ifname(expr.MetaKeyIIFNAME, "lo"), accept())...)
		for _, ch := range []*nftables.Chain{out, in, fwd} {
			add(ch, tagIsolate, concat(established(), accept())...)
		}
		if r.Permit != "" {
			if id, err := procinfo.CgroupID(r.Permit); err == nil {
				add(out, tagIsolate, concat(cgroupIs(depth(r.Permit), id), accept())...)
			}
		}
		// What keeps the machine's address: IPv6 router and neighbour
		// discovery, DHCP renewals (v4 and v6).
		for _, ch := range []*nftables.Chain{out, in} {
			add(ch, tagIsolate, concat(neighbourDiscovery(), accept())...)
		}
		add(out, tagIsolate, concat(udpPort(2, 67), accept())...)
		add(out, tagIsolate, concat(udpPort(2, 547), accept())...)
		add(in, tagIsolate, concat(udpPort(2, 68), accept())...)
		add(in, tagIsolate, concat(udpPort(2, 546), accept())...)
		for _, ch := range []*nftables.Chain{out, in, fwd} {
			add(ch, tagIsolate, counted(drop())...)
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("put the firewall rules in place: %w", err)
	}
	return nil
}

func concat(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func accept() []expr.Any { return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}} }
func drop() []expr.Any   { return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}} }
func counted(v []expr.Any) []expr.Any {
	return append([]expr.Any{&expr.Counter{}}, v...)
}

// cgroupIs: the packet's connection was made in the control group with this
// ID, level steps below the top of the tree, or in a group inside it.
func cgroupIs(level uint32, id uint64) []expr.Any {
	b := make([]byte, 8)
	binary.NativeEndian.PutUint64(b, id)
	return []expr.Any{
		&expr.Socket{Key: expr.SocketKeyCgroupv2, Level: level, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b},
	}
}

func depth(group string) uint32 {
	n := uint32(0)
	for _, part := range strings.Split(group, "/") {
		if part != "" {
			n++
		}
	}
	return n
}

func ifname(key expr.MetaKey, name string) []expr.Any {
	b := make([]byte, 16) // IFNAMSIZ, zero-padded
	copy(b, name)
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b},
	}
}

func established() []expr.Any {
	mask := make([]byte, 4)
	binary.NativeEndian.PutUint32(mask, expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED)
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
	}
}

// neighbourDiscovery: ICMPv6 router solicitation/advertisement, neighbour
// solicitation/advertisement (types 133 to 136).
func neighbourDiscovery() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
		&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{133}, ToData: []byte{136}},
	}
}

// udpPort: UDP with this destination port (offset 2 of the UDP header).
func udpPort(offset uint32, port uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, port)},
	}
}

// ---- the functions every system has ----

// Isolate blocks all new connections in and out except loopback and ABA's
// service (selfExe's control group, so phone alerts still get out).
func Isolate(selfExe string) error {
	_, err := update(true, func(r *record) {
		r.Isolated = true
		r.Permit = servicePermit()
	})
	return err
}

// servicePermit is the control group isolation lets through: the service's,
// when this is the service. Run any other way (in the foreground, to debug
// it), its group is the session it was started from, which holds programs of
// the user too: nothing is let through then.
func servicePermit() string {
	g := procinfo.Cgroup(uint32(os.Getpid()))
	if strings.HasSuffix(g, "/"+svcctl.Unit) && strings.HasPrefix(g, "/system.slice/") {
		return g
	}
	return ""
}

// Unisolate removes isolation.
func Unisolate() error {
	_, err := update(false, func(r *record) { r.Isolated, r.Permit = false, "" })
	return err
}

// BlockProgram cuts one program off the network: its running processes, and
// any that start it from now on (while the service runs; one started while it
// doesn't is cut off as soon as it's back).
func BlockProgram(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("no program to cut off (%q)", path)
	}
	if self, err := os.Executable(); err == nil && self == path {
		return errors.New("refusing to cut ABA itself off")
	}
	if v := provenance.Verify(path); v.Valid {
		return fmt.Errorf("not cut off as a whole: %s is the system's own (%s), and other programs use it too; what ABA froze of it stays frozen", path, v.Signer)
	}
	id, _ := paths.FileID(path)
	r, err := update(true, func(r *record) {
		if !r.has(path) {
			r.Programs = append(r.Programs, program{Path: path, File: id})
		}
	})
	if err != nil {
		return err
	}
	var errs []string
	for _, pid := range running(r) {
		if err := procinfo.Disconnect(pid); err != nil {
			errs = append(errs, err.Error())
		}
	}
	kick()
	if len(errs) > 0 {
		return fmt.Errorf("rules in place, but: %s", strings.Join(errs, "; "))
	}
	return nil
}

// UnblockProgram removes a program block, and lets its processes back on the
// network.
func UnblockProgram(path string) error {
	r, err := update(false, func(r *record) {
		var keep []program
		for _, p := range r.Programs {
			if p.Path != path {
				keep = append(keep, p)
			}
		}
		r.Programs = keep
	})
	if r == nil {
		return err
	}
	// Everything in the group that isn't running a program still cut off goes
	// back (what the program started, too).
	still := map[uint32]bool{}
	for _, pid := range running(r) {
		still[pid] = true
	}
	for _, pid := range procinfo.Disconnected() {
		if !still[pid] {
			if rerr := procinfo.Reconnect(pid); rerr != nil && err == nil {
				err = rerr
			}
		}
	}
	kick()
	return err
}

// GetStatus reports what is in place right now, in the kernel.
func GetStatus() (Status, error) {
	r, _ := load()
	c, exists, err := conn()
	if err != nil {
		return Status{}, err
	}
	if !exists {
		if !r.empty() {
			return Status{}, errors.New("ABA's network rules are missing (removed by something else?); the service puts them back")
		}
		return Status{}, nil
	}
	chains, err := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return Status{}, err
	}
	var st Status
	for _, ch := range chains {
		if ch.Table == nil || ch.Table.Name != TableName {
			continue
		}
		rules, err := c.GetRules(ch.Table, ch)
		if err != nil {
			return Status{}, err
		}
		for _, rl := range rules {
			st.Rules++
			st.Isolated = st.Isolated || string(rl.UserData) == tagIsolate
		}
	}
	return st, nil
}

// RemoveAll removes everything ABA ever put in place (uninstall): the table,
// the cut-off group (its processes go back where they came from), the record.
func RemoveAll() error {
	procMu.Lock()
	defer procMu.Unlock()
	var first error
	if c, exists, err := conn(); err == nil && exists {
		c.DelTable(inetTable())
		first = c.Flush()
	}
	if err := procinfo.RemoveCutOff(); err != nil && first == nil {
		first = err
	}
	if err := os.Remove(recordFile()); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
		first = err
	}
	os.Remove(recordFile() + ".tmp")
	os.Remove(lockFile())
	return first
}

// ---- which processes run a program that is cut off ----

type fileKey struct{ dev, ino uint64 }

func keyOf(st *unix.Stat_t) fileKey { return fileKey{uint64(st.Dev), uint64(st.Ino)} }

// targets are the files r cuts off: what is at each path now, and what was
// there when it was cut off (a stealer that replaced its own file).
func targets(r *record) map[fileKey]string {
	out := map[fileKey]string{}
	for _, p := range r.Programs {
		var st unix.Stat_t
		if unix.Stat(p.Path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG {
			out[keyOf(&st)] = p.Path
		}
		var dev, ino uint64
		if _, err := fmt.Sscanf(p.File, "%x:%x", &dev, &ino); err == nil {
			out[fileKey{dev, ino}] = p.Path
		}
	}
	return out
}

// running lists the processes running a program r cuts off.
func running(r *record) []uint32 {
	if len(r.Programs) == 0 {
		return nil
	}
	want := targets(r)
	snap, err := procinfo.Snapshot()
	if err != nil {
		return nil
	}
	self := uint32(os.Getpid())
	var out []uint32
	for pid := range snap {
		if pid == self || pid <= 2 {
			continue
		}
		var st unix.Stat_t
		if unix.Stat(fmt.Sprintf("/proc/%d/exe", pid), &st) != nil {
			continue
		}
		if _, ok := want[keyOf(&st)]; ok {
			out = append(out, pid)
		}
	}
	return out
}

// ---- the service's side ----

// Guard keeps what's on record in force while the service runs: it puts the
// rules back if they go, moves a process that starts a cut-off program into
// the cut-off group inside its execve(), and catches any that got going
// while the service wasn't watching.
type Guard struct {
	logf func(format string, args ...any)
	fd   int // fanotify group for execs (-1: none)
	held bool
	wake [2]int

	mu     sync.Mutex
	marked map[fileKey]string
	kick   chan struct{}
	stop   chan struct{}
	once   sync.Once
}

var (
	activeMu sync.Mutex
	active   *Guard
)

func kick() {
	activeMu.Lock()
	g := active
	activeMu.Unlock()
	if g != nil {
		g.Kick()
	}
}

// StartGuard puts what's on record in force again (the service's control
// group is new after every start, and after a reboot nothing is in place),
// and keeps it there until Close.
func StartGuard(logf func(format string, args ...any)) *Guard {
	g := &Guard{logf: logf, fd: -1, marked: map[fileKey]string{}, kick: make(chan struct{}, 1), stop: make(chan struct{})}
	r, err := update(false, func(r *record) {
		if r.Isolated {
			r.Permit = servicePermit()
		}
	})
	switch {
	case err != nil && r != nil && !r.empty():
		logf("network: couldn't put the cut-offs on record back in place: %v", err)
	case r != nil && r.Isolated:
		logf("network: this machine is isolated (since before the service started); the rules are in place")
	}
	if r != nil && len(r.Programs) > 0 {
		logf("network: %d program(s) cut off", len(r.Programs))
	}
	g.openExecWatch()
	go g.loop()
	if g.fd >= 0 {
		go g.run()
	}
	activeMu.Lock()
	active = g
	activeMu.Unlock()
	return g
}

func (g *Guard) openExecWatch() {
	const fflags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_LARGEFILE
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_UNLIMITED_QUEUE|unix.FAN_UNLIMITED_MARKS, fflags)
	if err == nil {
		if unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, "/proc/self/exe") == nil {
			unix.FanotifyMark(fd, unix.FAN_MARK_REMOVE, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, "/proc/self/exe")
			g.held = true
		} else {
			unix.Close(fd)
			fd, err = unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_UNLIMITED_QUEUE|unix.FAN_UNLIMITED_MARKS, fflags)
		}
	}
	if err != nil {
		g.logf("network: can't watch cut-off programs being started (%v); they're found by looking every second instead", err)
		return
	}
	if err := unix.Pipe2(g.wake[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		unix.Close(fd)
		return
	}
	g.fd = fd
}

func (g *Guard) mask() uint64 {
	if g.held {
		return unix.FAN_OPEN_EXEC_PERM
	}
	return unix.FAN_OPEN_EXEC
}

// Kick makes the guard look now: something was just cut off or let back.
func (g *Guard) Kick() {
	select {
	case g.kick <- struct{}{}:
	default:
	}
}

// Close stops the guard. What is in force stays in force.
func (g *Guard) Close() {
	g.once.Do(func() {
		close(g.stop)
		if g.fd >= 0 {
			unix.Write(g.wake[1], []byte{1})
		}
		activeMu.Lock()
		if active == g {
			active = nil
		}
		activeMu.Unlock()
	})
}

func (g *Guard) loop() {
	for {
		g.sync()
		wait := 5 * time.Second
		if r, _ := load(); !r.empty() {
			wait = time.Second
		}
		select {
		case <-g.stop:
			return
		case <-g.kick:
		case <-time.After(wait):
		}
	}
}

// sync checks once: the table is there, the programs' files are watched,
// and no process of theirs is outside the group.
func (g *Guard) sync() {
	defer func() {
		if p := recover(); p != nil {
			g.logf("PANIC in the network guard: %v", p)
		}
	}()
	r, err := load()
	if err != nil {
		g.logf("network: %v", err)
		return
	}
	if c, exists, err := conn(); err == nil {
		switch {
		case !r.empty() && !exists:
			g.logf("network: ABA's firewall rules had been removed by something else; putting them back")
			update(false, func(*record) {})
		case r.empty() && exists:
			c.DelTable(inetTable())
			c.Flush()
		}
	}
	g.syncMarks(r)
	for _, pid := range running(r) {
		if procinfo.CutOff(pid) || procinfo.Frozen(pid) {
			continue
		}
		img, _ := procinfo.ImagePath(pid)
		if err := procinfo.Disconnect(pid); err != nil {
			g.logf("network: cut off pid %d (%s): %v", pid, img, err)
		} else {
			g.logf("network: pid %d (%s) runs a program that is cut off; cut it off too", pid, img)
		}
	}
}

func (g *Guard) syncMarks(r *record) {
	if g.fd < 0 {
		return
	}
	want := map[string]bool{}
	for _, p := range r.Programs {
		want[p.Path] = true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, p := range g.marked {
		if want[p] {
			continue
		}
		delete(g.marked, k)
		if fd, err := unix.Open(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); err == nil {
			var st unix.Stat_t
			if unix.Fstat(fd, &st) == nil && keyOf(&st) == k {
				unix.FanotifyMark(g.fd, unix.FAN_MARK_REMOVE, g.mask(), unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd))
			}
			unix.Close(fd)
		}
	}
	for p := range want {
		fd, err := unix.Open(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG {
			if _, ok := g.marked[keyOf(&st)]; !ok {
				if err := unix.FanotifyMark(g.fd, unix.FAN_MARK_ADD, g.mask(), unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd)); err != nil {
					g.logf("network: watch %s being started: %v", p, err)
				} else {
					g.marked[keyOf(&st)] = p
				}
			}
		}
		unix.Close(fd)
	}
}

const metaLen = 24 // sizeof(struct fanotify_event_metadata)

func (g *Guard) run() {
	defer func() {
		unix.Close(g.fd)
		unix.Close(g.wake[0])
		unix.Close(g.wake[1])
	}()
	self := int32(os.Getpid())
	buf := make([]byte, 64*metaLen)
	fds := []unix.PollFd{{Fd: int32(g.fd), Events: unix.POLLIN}, {Fd: int32(g.wake[0]), Events: unix.POLLIN}}
	for {
		if _, err := unix.Poll(fds, -1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			g.logf("network: fanotify: poll: %v", err)
			return
		}
		if fds[1].Revents != 0 {
			return
		}
		n, err := unix.Read(g.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			g.logf("network: fanotify: read: %v", err)
			return
		}
		ne := binary.NativeEndian
		for off := 0; off+metaLen <= n; {
			evLen := int(ne.Uint32(buf[off:]))
			mask := ne.Uint64(buf[off+8:])
			fd := int32(ne.Uint32(buf[off+16:]))
			pid := int32(ne.Uint32(buf[off+20:]))
			if evLen < metaLen {
				break
			}
			off += evLen
			if fd < 0 {
				continue
			}
			g.started(fd, pid, mask, pid == self)
		}
	}
}

// started: pid is executing a file that is watched. It's held inside its
// execve() until this answers, so it never runs a single instruction of the
// program outside the group.
func (g *Guard) started(fd, pid int32, mask uint64, own bool) {
	defer unix.Close(int(fd))
	var st unix.Stat_t
	if !own && pid > 0 && unix.Fstat(int(fd), &st) == nil {
		g.mu.Lock()
		p, ok := g.marked[keyOf(&st)]
		g.mu.Unlock()
		if ok {
			if err := procinfo.Disconnect(uint32(pid)); err != nil {
				g.logf("network: pid %d started %s, which is cut off, and couldn't be cut off too: %v", pid, p, err)
			} else {
				g.logf("network: pid %d started %s, which is cut off: cut it off too", pid, p)
			}
		}
	}
	if mask&unix.FAN_OPEN_EXEC_PERM != 0 {
		var resp [8]byte
		binary.NativeEndian.PutUint32(resp[0:], uint32(fd))
		binary.NativeEndian.PutUint32(resp[4:], unix.FAN_ALLOW)
		unix.Write(g.fd, resp[:])
	}
}

// ---- Fallback: turn the network adapters off ----

// DisableAdapters turns off every network interface that is up, except
// loopback, and returns their names.
func DisableAdapters() ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var names []string
	var first error
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		if err := setUp(fd, i.Name, false); err != nil {
			if first == nil {
				first = fmt.Errorf("%s: %w", i.Name, err)
			}
			continue
		}
		names = append(names, i.Name)
	}
	return names, first
}

// EnableAdapters turns the named interfaces back on.
func EnableAdapters(names []string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var first error
	for _, n := range names {
		if err := setUp(fd, n, true); err != nil && first == nil {
			first = fmt.Errorf("%s: %w", n, err)
		}
	}
	return first
}

func setUp(fd int, name string, up bool) error {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	fl := ifr.Uint16()
	if up {
		fl |= unix.IFF_UP
	} else {
		fl &^= unix.IFF_UP
	}
	ifr.SetUint16(fl)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
