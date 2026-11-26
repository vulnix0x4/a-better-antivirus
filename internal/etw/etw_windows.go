// Package etw is the little of Event Tracing for Windows ABA needs: a
// private real-time session with a few providers enabled (only the events
// asked for, filtered by Windows before they're written), read as they come.
//
// Only one session per process: the callbacks Windows calls are global.
package etw

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32             = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW      = advapi32.NewProc("StartTraceW")
	procControlTraceW    = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2   = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW       = advapi32.NewProc("OpenTraceW")
	procProcessTrace     = advapi32.NewProc("ProcessTrace")
	procCloseTrace       = advapi32.NewProc("CloseTrace")
	invalidProcessHandle = ^uint64(0)
)

const (
	wnodeFlagTracedGUID     = 0x00020000
	eventTraceRealTimeMode  = 0x00000100
	processTraceRealTime    = 0x00000100
	processTraceEventRecord = 0x10000000
	controlQuery            = 0
	controlStop             = 1
	controlFlush            = 3
	enableProvider          = 1
	filterTypeEventID       = 0x80000200
	clientContextSystemTime = 2
)

type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

type traceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// propsBuf is a traceProperties with room after it for the session's name.
type propsBuf struct {
	p    traceProperties
	name [1024]uint16
	file [1024]uint16
}

func newProps() *propsBuf {
	b := &propsBuf{}
	b.p.Wnode.BufferSize = uint32(unsafe.Sizeof(*b))
	b.p.LoggerNameOffset = uint32(unsafe.Offsetof(b.name))
	b.p.LogFileNameOffset = uint32(unsafe.Offsetof(b.file))
	return b
}

type enableParameters struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceID         windows.GUID
	EnableFilterDesc *filterDescriptor
	FilterDescCount  uint32
}

type filterDescriptor struct {
	Ptr  uint64
	Size uint32
	Type uint32
}

type eventTraceHeader struct {
	Size          uint16
	FieldTypeFlag uint16
	Version       uint32
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	GUID          windows.GUID
	ProcessorTime uint64
}

type eventTrace struct {
	Header           eventTraceHeader
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGUID       windows.GUID
	MofData          uintptr
	MofLength        uint32
	ClientContext    uint32
}

type traceLogfileHeader struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	LogInstanceGUID    windows.GUID
	LoggerName         uintptr
	LogFileName        uintptr
	TimeZone           windows.Timezoneinformation
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

type eventTraceLogfile struct {
	LogFileName         uintptr
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        eventTrace
	LogfileHeader       traceLogfileHeader
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

// EventHeader is the header of an event, as Windows writes it.
type EventHeader struct {
	Size          uint16
	HeaderType    uint16
	Flags         uint16
	EventProperty uint16
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	ProviderID    windows.GUID
	ID            uint16
	Version       uint8
	Channel       uint8
	Level         uint8
	Opcode        uint8
	Task          uint16
	Keyword       uint64
	ProcessorTime uint64
	ActivityID    windows.GUID
}

// EventRecord is one event.
type EventRecord struct {
	Header            EventHeader
	ProcessorNumber   uint8
	Alignment         uint8
	LoggerID          uint16
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          unsafe.Pointer
	UserContext       uintptr
}

// Data is the event's payload. It's only valid during the callback.
func (e *EventRecord) Data() []byte {
	if e.UserData == nil || e.UserDataLength == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(e.UserData), int(e.UserDataLength))
}

// Time is when the event happened (the session runs on system time).
func (e *EventRecord) Time() time.Time { return FileTime(e.Header.TimeStamp) }

// FileTime converts a Windows FILETIME count to a time.
func FileTime(ft int64) time.Time {
	if ft <= 0 {
		return time.Time{}
	}
	return time.Unix(0, (ft-116444736000000000)*100)
}

// lostEventGUID is the "provider" of the notices Windows sends a real-time
// consumer when events were lost.
var lostEventGUID = windows.GUID{Data1: 0x6A399AE0, Data2: 0x4BC6, Data3: 0x4DE9, Data4: [8]byte{0x87, 0x0B, 0x36, 0x57, 0xF8, 0x94, 0x7E, 0x7E}}

// Provider is a provider to enable, and which of its events.
type Provider struct {
	GUID     windows.GUID
	Level    uint8
	Keywords uint64
	EventIDs []uint16 // only these (none: all)
}

// Session is a running real-time session.
type Session struct {
	name    string
	handle  uint64
	trace   uint64
	OnEvent func(e *EventRecord)
	// OnLost is told that Windows dropped events (a notice in the stream,
	// or a counter that went up).
	OnLost func(at time.Time, why string)

	buffers atomic.Uint64 // buffers delivered so far
	lost    struct {
		sync.Mutex
		events, buffers uint32
	}
}

var (
	current  atomic.Pointer[Session]
	onceCb   sync.Once
	eventCb  uintptr
	bufferCb uintptr
	errBusy  = errors.New("another ETW session is already being read in this process")
)

func callbacks() {
	onceCb.Do(func() {
		eventCb = syscall.NewCallback(func(e *EventRecord) uintptr {
			s := current.Load()
			if s == nil {
				return 0
			}
			if e.Header.ProviderID == lostEventGUID {
				if s.OnLost != nil {
					s.OnLost(e.Time(), "Windows dropped some of its reports (it was too busy)")
				}
				return 0
			}
			if s.OnEvent != nil {
				s.OnEvent(e)
			}
			return 0
		})
		bufferCb = syscall.NewCallback(func(l *eventTraceLogfile) uintptr {
			if s := current.Load(); s != nil {
				s.buffers.Add(1)
			}
			return 1
		})
	})
}

func control(handle uint64, name string, code uint32) (*propsBuf, error) {
	b := newProps()
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	r, _, _ := procControlTraceW.Call(uintptr(handle), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&b.p)), uintptr(code))
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	return b, nil
}

// StopByName stops a session left over from an earlier run (the service was
// killed before it could stop it): sessions outlive the process that started
// them.
func StopByName(name string) error {
	_, err := control(0, name, controlStop)
	if errors.Is(err, windows.ERROR_WMI_INSTANCE_NOT_FOUND) {
		return nil
	}
	return err
}

// Start starts a real-time session named name with providers enabled.
func Start(name string, providers []Provider) (*Session, error) {
	if current.Load() != nil {
		return nil, errBusy
	}
	callbacks()
	StopByName(name)
	b := newProps()
	b.p.Wnode.Flags = wnodeFlagTracedGUID
	b.p.Wnode.ClientContext = clientContextSystemTime
	b.p.BufferSize = 64 // KB
	b.p.MinimumBuffers = 4
	b.p.MaximumBuffers = 64
	b.p.LogFileMode = eventTraceRealTimeMode
	b.p.FlushTimer = 1 // seconds
	if g, err := windows.GenerateGUID(); err == nil {
		b.p.Wnode.GUID = g
	}
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	s := &Session{name: name}
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&s.handle)), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&b.p)))
	if r != 0 {
		return nil, fmt.Errorf("starting the trace session: %w", syscall.Errno(r))
	}
	for _, p := range providers {
		if err := s.enable(p); err != nil {
			s.Stop()
			return nil, err
		}
	}
	return s, nil
}

func (s *Session) enable(p Provider) error {
	params := enableParameters{Version: 2}
	var filter []byte
	if len(p.EventIDs) > 0 {
		// EVENT_FILTER_EVENT_ID: FilterIn, Reserved, Count, then the IDs.
		filter = make([]byte, 4+2*len(p.EventIDs))
		filter[0] = 1
		filter[2], filter[3] = byte(len(p.EventIDs)), byte(len(p.EventIDs)>>8)
		for i, id := range p.EventIDs {
			filter[4+2*i], filter[5+2*i] = byte(id), byte(id>>8)
		}
		desc := &filterDescriptor{Ptr: uint64(uintptr(unsafe.Pointer(&filter[0]))), Size: uint32(len(filter)), Type: filterTypeEventID}
		params.EnableFilterDesc, params.FilterDescCount = desc, 1
	}
	g := p.GUID
	r, _, _ := procEnableTraceEx2.Call(uintptr(s.handle), uintptr(unsafe.Pointer(&g)), enableProvider, uintptr(p.Level),
		uintptr(p.Keywords), 0, 0, uintptr(unsafe.Pointer(&params)))
	runtime.KeepAlive(filter)
	if r != 0 {
		return fmt.Errorf("enabling provider %s: %w", g.String(), syscall.Errno(r))
	}
	return nil
}

// Read reads the session's events until it's stopped, calling OnEvent for
// each. It blocks.
func (s *Session) Read() error {
	if !current.CompareAndSwap(nil, s) {
		return errBusy
	}
	defer current.CompareAndSwap(s, nil)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	n, err := windows.UTF16PtrFromString(s.name)
	if err != nil {
		return err
	}
	lf := &eventTraceLogfile{LoggerName: n, ProcessTraceMode: processTraceRealTime | processTraceEventRecord,
		EventRecordCallback: eventCb, BufferCallback: bufferCb}
	r, _, e := procOpenTraceW.Call(uintptr(unsafe.Pointer(lf)))
	h := uint64(r)
	if h == invalidProcessHandle {
		return fmt.Errorf("opening the trace session: %w", e)
	}
	atomic.StoreUint64(&s.trace, h)
	r, _, _ = procProcessTrace.Call(uintptr(unsafe.Pointer(&h)), 1, 0, 0)
	procCloseTrace.Call(uintptr(h))
	runtime.KeepAlive(lf)
	if r != 0 && syscall.Errno(r) != windows.ERROR_CANCELLED {
		return fmt.Errorf("reading the trace session: %w", syscall.Errno(r))
	}
	return nil
}

// Delivered is how many buffers of events have been handed to OnEvent so
// far.
func (s *Session) Delivered() uint64 { return s.buffers.Load() }

// Flush asks Windows to hand over what it has collected so far, now.
func (s *Session) Flush() error {
	_, err := control(s.handle, s.name, controlFlush)
	return err
}

// Losses says how many events and buffers Windows has dropped in this
// session so far.
func (s *Session) Losses() (events, buffers uint32, err error) {
	b, err := control(s.handle, s.name, controlQuery)
	if err != nil {
		return 0, 0, err
	}
	return b.p.EventsLost, b.p.RealTimeBuffersLost + b.p.LogBuffersLost, nil
}

// Stop stops the session; Read returns.
func (s *Session) Stop() error {
	_, err := control(s.handle, s.name, controlStop)
	return err
}
