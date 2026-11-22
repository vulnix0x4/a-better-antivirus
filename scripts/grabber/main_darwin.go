// Command grabber is the harmless fake stealer of the macOS end-to-end test
// (scripts/e2e-macos.sh), the Linux one's (main_linux.go) with two more
// ways to get at a file: it opens the files it's given, the way a file
// grabber would, and writes down what it got. It sends nothing anywhere.
//
//	grabber [-child] [-link] [-finder] [-wait ms] -out FILE file...
//	grabber -serve 127.0.0.1:PORT -out FILE
//
// FILE gets one line per file ("READ path bytes" or "ERR path error") and
// "DONE" at the end; FILE.pid holds its PID, and FILE.child the PID of the
// helper process it starts with -child (to check that ABA freezes what a
// stealer started, too). With -link each file is read through a hard link
// made next to FILE instead of by its own name.
//
// With -finder each file is copied by Finder instead (an AppleScript asking
// Finder to duplicate it next to FILE), the way the Atomic stealer collects
// documents. After DONE it writes a line to FILE.tick every 100 ms, so that a
// test can see whether it's still running or frozen.
//
// With -serve it's the phone instead: a web server that takes what ABA would
// post to ntfy and writes each message to FILE as "POST path | title | text",
// so the test doesn't depend on a service on the internet.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	child := flag.Bool("child", false, "start a helper process first")
	link := flag.Bool("link", false, "read each file through a hard link")
	wait := flag.Int("wait", 300, "milliseconds to wait before opening anything")
	out := flag.String("out", "", "where to write what happened")
	idle := flag.Bool("idle", false, "do nothing (the helper process)")
	serve := flag.String("serve", "", "address to take phone alerts on, instead of grabbing")
	finder := flag.Bool("finder", false, "have Finder copy each file")
	flag.Parse()
	if *serve != "" && *out != "" {
		err := http.ListenAndServe(*serve, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
			if f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
				fmt.Fprintf(f, "%s %s | %s | %s\n", r.Method, r.URL.Path, r.Header.Get("Title"), strings.ReplaceAll(string(body), "\n", " / "))
				f.Close()
			}
			w.Write([]byte("{}"))
		}))
		fmt.Fprintln(os.Stderr, "grabber:", err)
		os.Exit(1)
	}
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
		if *finder {
			dir := filepath.Dir(*out)
			script := fmt.Sprintf(`tell application "Finder" to duplicate (POSIX file %q as alias) to folder (POSIX file %q as alias) with replacing`, p, dir)
			if o, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput(); err != nil {
				note("ERR %s finder: %v %s", p, err, strings.TrimSpace(string(o)))
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, filepath.Base(p)))
			if err != nil {
				note("ERR %s %v", p, err)
				continue
			}
			note("READ %s %d", p, len(b))
			continue
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
	// Stay around (a freeze has to have something to freeze), and show it's
	// running.
	for i := 0; i < 6000; i++ {
		if f, err := os.OpenFile(*out+".tick", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintln(f, i)
			f.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
}
