package service

import "time"

// appProcess is the desktop app the service started in one session.
type appProcess interface {
	Exited() (bool, uint32) // ended, and its exit code
	Terminate()
}

// appShowTimeout is how long the app has to show its window (WebView2's
// first start on a slow PC takes a few seconds) before the popup takes over.
const appShowTimeout = 30 * time.Second

// waitAppShown reports whether the app the service started for an alert got
// in front of the person: it said it showed its window (shown), or it ended
// with exit code 0 (handed the alert to the copy already open, or the person
// closed it). It ended any other way (it couldn't open: say its guard broke
// after a WebView2 update): no. An elevated app that's still silent at the
// deadline is stuck: it's ended, and no. An app in its locked view (a
// standard user) can't write where the service would see it, so still
// running at the deadline counts as showing.
func waitAppShown(p appProcess, shown func() bool, elevated bool, timeout, tick time.Duration, sleep func(time.Duration)) bool {
	for waited := time.Duration(0); ; waited += tick {
		if shown() {
			return true
		}
		if ended, code := p.Exited(); ended {
			return code == 0 || shown()
		}
		if waited >= timeout {
			break
		}
		sleep(tick)
	}
	if !elevated {
		return true
	}
	p.Terminate()
	return shown()
}
