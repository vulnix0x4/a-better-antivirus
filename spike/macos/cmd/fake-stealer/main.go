//go:build darwin

// fake-stealer is the harmless test program for the macOS spike.
//
// It does what an infostealer's file grabber does, to files the spike made up:
// open the bait, read it, then keep "collecting" (reading the loot files next
// to it, over and over). It never touches the network and never reads anything
// outside the folder it is given.
//
// So the watcher's speed can be measured from the outside, it writes down when
// it did each thing:
//
//	<stamp file>  16 bytes, rewritten after every loot file it reads:
//	              how many it has read, and the wall-clock time of the last one
//	<log file>    one JSON line per step with a wall-clock timestamp
//
// When the watcher freezes it, the stamp stops moving. The last stamp is how
// far it got.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	bait := flag.String("bait", "", "bait file to read")
	loot := flag.String("loot", "", "folder of made-up files to keep reading afterwards")
	stamp := flag.String("stamp", "", "file to write progress into")
	logPath := flag.String("log", "", "file to write the step log into")
	how := flag.String("how", "open", "open: open and read the bait; mmap: map it instead of read(); stat: only stat it")
	flag.Parse()
	if *bait == "" || *stamp == "" || *logPath == "" {
		fmt.Fprintln(os.Stderr, "usage: fake-stealer -bait FILE -loot DIR -stamp FILE -log FILE")
		os.Exit(2)
	}

	lf, err := os.Create(*logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	step := func(name string, extra map[string]any) {
		m := map[string]any{"step": name, "t_unix_nano": time.Now().UnixNano(), "pid": os.Getpid()}
		for k, v := range extra {
			m[k] = v
		}
		b, _ := json.Marshal(m)
		lf.Write(append(b, '\n'))
	}
	sf, err := os.Create(*stamp)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var buf [16]byte
	writeStamp := func(n uint64) {
		binary.LittleEndian.PutUint64(buf[0:], n)
		binary.LittleEndian.PutUint64(buf[8:], uint64(time.Now().UnixNano()))
		sf.WriteAt(buf[:], 0)
	}
	writeStamp(0)

	step("start", nil)
	switch *how {
	case "stat":
		_, err := os.Stat(*bait)
		step("stat_done", map[string]any{"err": fmt.Sprint(err)})
	case "mmap":
		step("pre_open", nil)
		f, err := os.Open(*bait)
		step("opened", map[string]any{"err": fmt.Sprint(err)})
		if err == nil {
			st, _ := f.Stat()
			data, err := syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ, syscall.MAP_PRIVATE)
			n := 0
			if err == nil && len(data) > 0 {
				n = int(data[0]) // touch the first page
				n = len(data)
			}
			step("read", map[string]any{"bytes": n, "err": fmt.Sprint(err)})
		}
	default:
		step("pre_open", nil)
		f, err := os.Open(*bait)
		step("opened", map[string]any{"err": fmt.Sprint(err)})
		if err == nil {
			b := make([]byte, 1<<16)
			n, _ := f.Read(b)
			step("read", map[string]any{"bytes": n})
			f.Close()
		}
	}

	// Keep collecting, the way a grabber moves on to the next file. Each pass
	// reads one loot file and bumps the stamp.
	var files []string
	if *loot != "" {
		files, _ = filepath.Glob(filepath.Join(*loot, "*"))
	}
	b := make([]byte, 1<<16)
	deadline := time.Now().Add(20 * time.Second)
	for n := uint64(1); time.Now().Before(deadline); n++ {
		if len(files) > 0 {
			if f, err := os.Open(files[int(n)%len(files)]); err == nil {
				f.Read(b)
				f.Close()
			}
		}
		writeStamp(n)
	}
	step("gave_up_nobody_stopped_me", nil)
}
