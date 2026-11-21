// Command grabber is the harmless fake stealer of the Linux end-to-end test
// (scripts/e2e-linux.sh): it opens the files it's given, the way a file
// grabber would, and writes down what it got. It sends nothing anywhere.
//
//	grabber [-child] [-link] [-wait ms] -out FILE file...
//
// FILE gets one line per file ("READ path bytes" or "ERR path error") and
// "DONE" at the end; FILE.pid holds its PID, and FILE.child the PID of the
// helper process it starts with -child (to check that ABA freezes what a
// stealer started, too). With -link each file is read through a hard link
// made next to FILE instead of by its own name.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

func main() {
	child := flag.Bool("child", false, "start a helper process first")
	link := flag.Bool("link", false, "read each file through a hard link")
	wait := flag.Int("wait", 300, "milliseconds to wait before opening anything")
	out := flag.String("out", "", "where to write what happened")
	idle := flag.Bool("idle", false, "do nothing (the helper process)")
	flag.Parse()
	if *idle {
		time.Sleep(10 * time.Minute)
		return
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "grabber: -out is required")
		os.Exit(2)
	}
	os.WriteFile(*out+".pid", []byte(strconv.Itoa(os.Getpid())), 0o644)
	if *child {
		self, _ := os.Executable()
		c := exec.Command(self, "-idle")
		if err := c.Start(); err == nil {
			os.WriteFile(*out+".child", []byte(strconv.Itoa(c.Process.Pid)), 0o644)
		}
	}
	note := func(format string, a ...any) {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		fmt.Fprintf(f, format+"\n", a...)
		f.Close()
	}
	time.Sleep(time.Duration(*wait) * time.Millisecond)
	for i, p := range flag.Args() {
		name := p
		if *link {
			name = filepath.Join(filepath.Dir(*out), fmt.Sprintf("grabbed-%d-%d.tmp", os.Getpid(), i))
			if err := os.Link(p, name); err != nil {
				note("ERR %s link: %v", p, err)
				continue
			}
		}
		b, err := os.ReadFile(name)
		if *link {
			os.Remove(name)
		}
		if err != nil {
			note("ERR %s %v", p, err)
			continue
		}
		note("READ %s %d", p, len(b))
	}
	note("DONE")
	time.Sleep(10 * time.Minute) // stay around: a freeze has to have something to freeze
}
