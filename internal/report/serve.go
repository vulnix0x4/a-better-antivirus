package report

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// Once hands one page to the browser, one time, from this computer only.
//
// It listens on 127.0.0.1 (nothing on the network can reach it) at a
// random port, and answers only at a path made of 128 random bits: nothing
// on this computer can guess the address. The first time the page is
// fetched, it's sent and the server stops: a second fetch, by the browser
// reloading it or anything else, finds nothing there. The page is sent with
// no-store, so the browser doesn't keep a copy in its cache either.
type Once struct {
	URL string

	srv    *http.Server
	loaded chan struct{}
	once   sync.Once
	mu     sync.Mutex
	served bool
}

// Serve starts handing out page. Wait for it to be loaded, then Close.
func Serve(page []byte) (*Once, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		ln.Close()
		return nil, err
	}
	host := ln.Addr().String()
	path := "/" + hex.EncodeToString(key)
	o := &Once{URL: "http://" + host + path, loaded: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		// Only this address, by its own name (not a name some web page
		// pointed at 127.0.0.1), and only a plain GET.
		if r.URL.Path != path || r.Host != host || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		o.mu.Lock()
		first := !o.served
		o.served = true
		o.mu.Unlock()
		if !first {
			http.Error(w, "This report was already shown once and isn't kept here. To see it again, open it from ABA again.", http.StatusGone)
			return
		}
		h.Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
		o.once.Do(func() { close(o.loaded) })
	})
	o.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go o.srv.Serve(ln)
	return o, nil
}

// ErrNotOpened: nothing fetched the page in time.
var ErrNotOpened = errors.New("the page wasn't opened in time")

// Wait waits until the page has been sent, or for at most d.
func (o *Once) Wait(d time.Duration) error {
	select {
	case <-o.loaded:
		return nil
	case <-time.After(d):
		return ErrNotOpened
	}
}

// Close stops the server, letting a page that's still being sent finish.
func (o *Once) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o.srv.Shutdown(ctx)
}

// OpenTime is how long the browser gets to open the page.
const OpenTime = 3 * time.Minute

// Show opens page in the browser of the person at the screen (see Open),
// waits until it has loaded and stops serving it.
func Show(page []byte) error {
	o, err := Serve(page)
	if err != nil {
		return err
	}
	defer o.Close()
	if err := open(o.URL); err != nil {
		return err
	}
	return o.Wait(OpenTime)
}

// open is Open, swapped in tests.
var open = Open

// errNobody: run as root, with nobody at the screen to open it for.
var errNobody = errors.New("nobody is logged in at the screen to open it for: use --no-browser and open the address yourself")
