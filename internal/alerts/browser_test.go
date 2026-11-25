package alerts

import "testing"

// Runs on every system: an alert can carry a Windows path anywhere.
func TestBrowserName(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`:                        "Chrome",
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`:                 "Edge",
		`C:\Users\bob\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe`: "Brave",
		`/usr/lib/firefox/firefox-bin`:                                                 "Firefox",
		`/opt/google/chrome/google-chrome`:                                             "Chrome",
		"chrome.exe":                                                                   "Chrome",
		`C:\Tools\other.exe`:                                                           "other.exe",
	} {
		if got := BrowserName(in); got != want {
			t.Errorf("BrowserName(%s) = %q, want %q", in, got, want)
		}
	}
}
