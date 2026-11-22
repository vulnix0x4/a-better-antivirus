// Command grabber is the harmless fake stealer of the Linux end-to-end test
// (scripts/e2e-linux.sh): it opens the files it's given, the way a file
// grabber would, and writes down what it got. It sends nothing anywhere.
//
//	grabber [-child] [-link] [-wait ms] [-connect HOST:PORT] -out FILE file...
//	grabber -serve 127.0.0.1:PORT -out FILE
//
// FILE gets one line per file ("READ path bytes" or "ERR path error") and
// "DONE" at the end; FILE.pid holds its PID, and FILE.child the PID of the
// helper process it starts with -child (to check that ABA freezes what a
// stealer started, too). With -link each file is read through a hard link
// made next to FILE instead of by its own name. With -connect it then tries to
// reach HOST:PORT every 200 ms, the way an upload would start, and FILE.net
// says how the latest try went: "NET OK n" or "NET FAIL n error".
// With -delete it deletes the files instead ("DELETED path").
//
// With -serve it's the phone instead: a web server that takes what ABA would
// post to ntfy and writes each message to FILE as "POST path | title | text",
// so the test doesn't depend on a service on the internet.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
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
	connect := flag.String("connect", "", "address to keep trying to reach after grabbing")
	del := flag.Bool("delete", false, "delete the files instead of reading them")
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
		if *del {
			if err := os.Remove(p); err != nil {
				note("ERR %s %v", p, err)
			} else {
				note("DELETED %s", p)
			}
			continue
		}
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
	if *connect != "" {
		for i := 0; ; i++ {
			line := fmt.Sprintf("NET OK %d", i)
			if c, err := net.DialTimeout("tcp", *connect, 500*time.Millisecond); err != nil {
				line = fmt.Sprintf("NET FAIL %d %v", i, err)
			} else {
				c.Close()
			}
			os.WriteFile(*out+".net.tmp", []byte(line+"\n"), 0o644)
			os.Rename(*out+".net.tmp", *out+".net")
			time.Sleep(200 * time.Millisecond)
		}
	}
	time.Sleep(10 * time.Minute) // stay around: a freeze has to have something to freeze
}
