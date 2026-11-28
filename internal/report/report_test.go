package report

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/autopsy"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// hostile is what a stealer controls: its own file name, the names of the
// files it made, the addresses it sends to.
const hostile = `<script>alert(1)</script>"><img src=x onerror=alert(2)>`

func caught() *alerts.Alert {
	at := time.Date(2026, 11, 26, 18, 4, 31, 0, time.Local)
	a := &alerts.Alert{
		ID: "20261126-180431-2962", Time: at, Kind: alerts.KindRead, Tier: config.TierCritical, Status: "open",
		Title:   "Possible stealer: Umbral.exe opened your bait",
		Process: &alerts.Process{PID: 10608, Image: `C:\Users\bob\Downloads\Umbral.exe`, SHA256: strings.Repeat("ab", 32)},
		Instant: true, LatencyMS: 98,
		Autopsy: &alerts.Autopsy{
			Answer: alerts.AnswerRead, Sent: alerts.SentSome,
			Headline: "It opened your Discord token store and then connected to discord.com, so assume it was sent. Act on it now.",
			Summary:  []string{"Your Discord token store: 000005.ldb at 18:04:31."},
			Steps:    []string{"Your Discord token store: change your Discord password."},
			BaitAt:   at,
			Reads:    []alerts.StoreRead{{Name: "your Discord token store", Path: `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb`, At: at.Add(-58 * time.Millisecond), PID: 10608, How: "the flight recorder saw it open it"}},
			Sends:    []alerts.NetSend{{PID: 10608, To: "162.159.135.232:443", Name: "discord.com", First: at, Bytes: 814, After: true}},
			Left:     []string{`A copy of itself in your Startup folder: C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\RzPUk.scr`},
			Addresses: []alerts.Address{
				{Kind: autopsy.KindDiscord, Value: "https://discord.com/api/webhooks/123/abc", Where: "memory"},
			},
		},
	}
	a.AddAction(config.ActionFreeze, nil, "1 process(es) frozen the moment it opened the bait")
	a.AddAction(config.ActionBlockProgram, nil, a.Process.Image)
	return a
}

// text is the page with its markup taken out, for what it says.
func text(page []byte) string {
	s := regexp.MustCompile(`(?s)<style>.*?</style>`).ReplaceAllString(string(page), "")
	s = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(s, " ")
	return strings.Join(strings.Fields(html.UnescapeString(s)), " ")
}

func TestPageSaysWhatTheTerminalSays(t *testing.T) {
	a := caught()
	page := string(Page(a))
	txt := text([]byte(page))
	// Every line of the terminal's report is on the page, word for word.
	for _, s := range autopsy.Render(a) {
		if s.Key != autopsy.SecAnswer && !strings.Contains(txt, s.Title) {
			t.Errorf("section %q is missing", s.Title)
		}
		for _, l := range s.Lines {
			if s.Key == autopsy.SecProgram {
				if m := labelRe.FindStringSubmatch(l); m != nil {
					l = m[1] + " " + m[2]
				}
			}
			for _, part := range gap.Split(strings.TrimSpace(l), -1) {
				if want := strings.Join(strings.Fields(part), " "); !strings.Contains(txt, want) {
					t.Errorf("%s: %q is missing", s.Key, part)
				}
			}
		}
	}
	// The headline comes first, with its colour, then the steps.
	if !strings.Contains(page, `class="card answer bad"`) {
		t.Error("the answer isn't marked as bad (it read your data and sent it)")
	}
	h, st, rd := strings.Index(page, a.Autopsy.Headline), strings.Index(page, "Do this now"), strings.Index(page, "Real data it opened")
	if h < 0 || st < h || rd < st {
		t.Errorf("order: headline %d, steps %d, reads %d", h, st, rd)
	}
	for _, want := range []string{"aba kill 2962", "aba resume 2962", "dis.gd/request", "Fingerprint (SHA-256)", "isn't saved anywhere", Where()} {
		if !strings.Contains(txt, want) {
			t.Errorf("the page doesn't say %q", want)
		}
	}
}

// templateEscape is how html/template writes an apostrophe and the like.
func templateEscape(s string) string {
	return strings.NewReplacer("'", "&#39;", `"`, "&#34;", "&", "&amp;", "<", "&lt;", ">", "&gt;", "+", "&#43;").Replace(s)
}

func TestHostileNamesAreOnlyText(t *testing.T) {
	a := caught()
	a.Process.Image = `C:\Users\bob\Downloads\` + hostile + `.exe`
	a.Title = "Possible stealer: " + hostile
	ap := a.Autopsy
	ap.Headline = hostile
	ap.Reads[0].Path = `C:\x\` + hostile
	ap.Left = []string{hostile}
	ap.Addresses = append(ap.Addresses, alerts.Address{Kind: autopsy.KindURL, Value: `javascript:alert(3)//` + hostile, Where: "file"})
	ap.Staged = []alerts.Staged{{Path: `C:\Users\bob\AppData\Local\Temp\` + hostile + `.zip`, Size: 2048, Appeared: a.Time,
		Entries: []alerts.ArchiveEntry{{Name: hostile, What: "a bait"}}}}
	a.ID = `x"><script>alert(4)</script>`
	for name, page := range map[string][]byte{"report": Page(a), "list": Index([]*alerts.Alert{a})} {
		s := string(page)
		if bad := markupProblems(page); len(bad) > 0 {
			t.Errorf("%s: the caught program's names made it into the page as markup:\n%s", name, strings.Join(bad, "\n"))
		}
		if !strings.Contains(text(page), hostileText) {
			t.Errorf("%s: the hostile name should still be shown, as text", name)
		}
		// Nothing is loaded from anywhere, and no script runs.
		for _, bad := range []string{"http://", "https://fonts", "<link rel=\"stylesheet", "src=\"http", "@import"} {
			if strings.Contains(strings.ReplaceAll(s, "https://discord.com/api/webhooks/123/abc", ""), bad) {
				t.Errorf("%s: the page loads something from outside (%q)", name, bad)
			}
		}
		if !strings.Contains(s, "default-src 'none'") {
			t.Errorf("%s: no content security policy", name)
		}
	}
}

// hostileText is hostile as the page shows it: as text.
var hostileText = strings.Join(strings.Fields(hostile), " ")

// markupProblems parses the page the way a browser does and lists anything
// in it that could run or load something: a script, an image, an event
// handler, a link out of the page.
func markupProblems(page []byte) []string {
	var bad []string
	z := html.NewTokenizer(strings.NewReader(string(page)))
	styles := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return bad
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		switch tok.Data {
		case "script", "img", "iframe", "object", "embed", "form", "input", "base", "svg", "math", "video", "audio", "source":
			bad = append(bad, "element <"+tok.Data+">")
		case "style":
			if styles++; styles > 1 {
				bad = append(bad, "a second <style>")
			}
		}
		for _, at := range tok.Attr {
			k, v := strings.ToLower(at.Key), strings.ToLower(at.Val)
			switch {
			case strings.HasPrefix(k, "on"), k == "src", k == "style", k == "srcdoc", k == "action":
				bad = append(bad, "attribute "+at.Key+"="+at.Val+" on <"+tok.Data+">")
			case k == "href" && !strings.HasPrefix(v, "#") && v != "data:,":
				bad = append(bad, "link to "+at.Val)
			case k == "id" || k == "class":
				if strings.ContainsAny(v, "<>\"'") {
					bad = append(bad, k+"="+at.Val)
				}
			}
		}
	}
}

func TestLongPathsMayBreak(t *testing.T) {
	a := caught()
	long := `C:\Users\bob\AppData\Local\` + strings.Repeat(`VeryLongFolderNameWithoutSpaces\`, 12) + "file.dat"
	a.Autopsy.Reads[0].Path = long
	page := string(Page(a))
	if !strings.Contains(page, `<span class="c path">`+templateEscape(long)+`</span>`) {
		t.Error("a long path isn't shown whole in a path piece (which may break anywhere)")
	}
	if !strings.Contains(page, "overflow-wrap:anywhere") {
		t.Error("paths aren't allowed to break")
	}
}

func TestMissingSections(t *testing.T) {
	// The barest autopsy there is: an answer and nothing else.
	a := &alerts.Alert{ID: "20261126-120000-0001", Kind: alerts.KindRead, Title: "Possible stealer",
		Autopsy: &alerts.Autopsy{Answer: alerts.AnswerNoSign, Headline: "No sign it opened anything of yours."}}
	page := string(Page(a))
	if !strings.Contains(page, "No sign it opened anything of yours.") || !strings.Contains(page, `answer good`) {
		t.Error("the bare answer isn't shown, or not as good news")
	}
	for _, absent := range []string{"Do this now", "To be safe", "Real data it opened", "The program", "What ABA did"} {
		if strings.Contains(page, absent) {
			t.Errorf("empty section %q is shown", absent)
		}
	}
	// No autopsy at all: not a report, nothing on the list.
	if strings.Contains(string(Index([]*alerts.Alert{{ID: "x", Title: "Bait missing"}})), "Bait missing") {
		t.Error("an alert without an autopsy is listed as a report")
	}
	if !strings.Contains(string(Index(nil)), "No reports yet") {
		t.Error("an empty list should say so")
	}
}

func TestIndexListsNewestFirstAndLinksEachReport(t *testing.T) {
	older, newer := caught(), caught()
	older.ID = "20261120-100000-aaaa"
	newer.ID = "20261126-180431-2962"
	page := string(Index([]*alerts.Alert{newer, older}))
	n, o := strings.Index(page, `href="#r-20261126-180431-2962"`), strings.Index(page, `href="#r-20261120-100000-aaaa"`)
	if n < 0 || o < 0 || o < n {
		t.Errorf("list order: newer at %d, older at %d", n, o)
	}
	for _, id := range []string{newer.ID, older.ID} {
		if !strings.Contains(page, `id="r-`+id+`"`) {
			t.Errorf("report %s isn't on the page to link to", id)
		}
	}
}

func TestServedOnceThenGone(t *testing.T) {
	o, err := Serve([]byte("<p>the report</p>"))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if !strings.HasPrefix(o.URL, "http://127.0.0.1:") || len(o.URL) < len("http://127.0.0.1:1/")+32 {
		t.Fatalf("address %q: want 127.0.0.1 and a long random key", o.URL)
	}
	base := o.URL[:strings.LastIndex(o.URL, "/")]
	for _, wrong := range []string{base + "/", base + "/favicon.ico", base + "/" + strings.Repeat("0", 32)} {
		if code, _ := get(t, wrong); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", wrong, code)
		}
	}
	if err := o.Wait(10 * time.Millisecond); err == nil {
		t.Error("Wait says it was loaded before anyone had it")
	}
	code, body := get(t, o.URL)
	if code != http.StatusOK || body != "<p>the report</p>" {
		t.Fatalf("first load: %d %q", code, body)
	}
	if err := o.Wait(time.Second); err != nil {
		t.Errorf("Wait after the load: %v", err)
	}
	if code, body := get(t, o.URL); code != http.StatusGone || strings.Contains(body, "the report</p>") {
		t.Errorf("second load: %d %q, want it gone", code, body)
	}
	o.Close()
	if _, err := http.Get(o.URL); err == nil {
		t.Error("still answering after Close")
	}
}

func TestServedOnlyByItsOwnName(t *testing.T) {
	o, err := Serve([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	// A web page that points its own name at 127.0.0.1 (DNS rebinding) gets nothing.
	req, _ := http.NewRequest("GET", o.URL, nil)
	req.Host = "evil.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("another host name: %d, want 404", resp.StatusCode)
	}
	resp, err = http.Post(o.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST: %d, want 404", resp.StatusCode)
	}
	// Neither used up the one load.
	if code, _ := get(t, o.URL); code != http.StatusOK {
		t.Errorf("the real load after them: %d", code)
	}
}

func TestNoStoreAndPolicyHeaders(t *testing.T) {
	o, err := Serve([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	resp, err := http.Get(o.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for k, want := range map[string]string{"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("no content security policy header")
	}
}

func TestShowOpensTheBrowserAndWaits(t *testing.T) {
	var opened string
	open = func(url string) error {
		opened = url
		go http.Get(url) // the browser
		return nil
	}
	defer func() { open = Open }()
	if err := Show([]byte("page")); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(opened, "http://127.0.0.1:") {
		t.Errorf("opened %q", opened)
	}
	if _, err := http.Get(opened); err == nil {
		t.Error("the page is still served after Show returned")
	}
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
