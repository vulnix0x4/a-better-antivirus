// Package report shows an autopsy's full report as a page in the web
// browser: one caught program's (`aba report <id>`, the popup's "Show full
// report" button), or all of them, newest first (`aba reports`, the Start
// menu's "ABA reports").
//
// What the page says is autopsy.Render, section for section, the same as
// `aba autopsy` in a terminal: this package only lays it out.
//
// The reports themselves stay where ABA keeps its alerts, which only
// administrators can read. They name ABA's bait files, so a copy that lasts
// and that you can read would tell a stealer running as you which files to
// leave alone. So the page is never written to disk: it's handed to the
// browser once, from this computer only, at an address with a random
// one-time key (see Serve), with no-store so the browser doesn't keep it in
// its cache either.
package report

import (
	"bytes"
	"html/template"
	"regexp"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/autopsy"
)

// The order the page shows the sections in: the answer and what to do
// first, then what it took and where it went, then the details. Anything
// autopsy.Render adds later that isn't listed comes at the end.
var order = []string{
	autopsy.SecAnswer, autopsy.SecSteps, autopsy.SecUnsure,
	autopsy.SecReads, autopsy.SecSent, autopsy.SecLeft, autopsy.SecStaged,
	autopsy.SecAddresses, autopsy.SecLeads, autopsy.SecProgram, autopsy.SecDid,
	autopsy.SecWatched, autopsy.SecOpen, autopsy.SecEvidence, autopsy.SecNotes,
}

// cell is a piece of a report line: the report's lines put two spaces
// between their parts (a time, a name, a path), which the page shows as
// separate pieces.
type cell struct {
	Text  string
	Class string // "time", "path", "cmd", "tag" or ""
}

type line struct {
	Cells []cell
	Label string // "File" in "File: C:\…" (the program's details)
}

type section struct {
	Key, Title string
	Lines      []line
}

// reportView is one report, ready for the template.
type reportView struct {
	ID, Anchor, Program, Title, When string
	Tone                             string
	Headline                         string
	Summary                          []line
	StepsTitle                       string
	Steps                            []line
	Sections                         []section
}

type pageView struct {
	Title     string
	Index     bool // the list of every report
	Reports   []reportView
	Where     string // how to get back to the reports
	Generated string
}

// Page is the full report of one alert, as a complete HTML page.
func Page(a *alerts.Alert) []byte {
	v := pageView{Title: "ABA report: " + a.ExeName(), Where: Where(), Generated: now().Format("Mon Jan 2 2006, 15:04")}
	v.Reports = []reportView{view(a)}
	return render(v)
}

// Index is every report, newest first, as one page: a list, and each report
// shown when it's picked from the list (no script: the page's own links).
// Alerts without an autopsy aren't reports and are left out.
func Index(list []*alerts.Alert) []byte {
	v := pageView{Title: "ABA reports", Index: true, Where: Where(), Generated: now().Format("Mon Jan 2 2006, 15:04")}
	for _, a := range list {
		if a.Autopsy != nil {
			v.Reports = append(v.Reports, view(a))
		}
	}
	return render(v)
}

var now = time.Now

func view(a *alerts.Alert) reportView {
	r := reportView{ID: a.ID, Anchor: anchor(a.ID), Program: a.ExeName(), Title: a.Title, Tone: autopsy.Tone(a.Autopsy)}
	if !a.Time.IsZero() {
		r.When = a.Time.Local().Format("Mon Jan 2 2006, 15:04:05")
	}
	byKey := map[string]autopsy.Section{}
	var keys []string
	for _, s := range autopsy.Render(a) {
		if _, dup := byKey[s.Key]; !dup {
			keys = append(keys, s.Key)
		}
		byKey[s.Key] = s
	}
	if s, ok := byKey[autopsy.SecAnswer]; ok && len(s.Lines) > 0 {
		r.Headline = s.Lines[0]
		r.Summary = lines(s.Key, s.Lines[1:])
	}
	if s, ok := byKey[autopsy.SecSteps]; ok {
		r.StepsTitle, r.Steps = s.Title, lines(s.Key, s.Lines)
	}
	done := map[string]bool{autopsy.SecAnswer: true, autopsy.SecSteps: true}
	addSec := func(k string) {
		s, ok := byKey[k]
		if !ok || done[k] {
			return
		}
		done[k] = true
		r.Sections = append(r.Sections, section{Key: k, Title: s.Title, Lines: lines(k, s.Lines)})
	}
	for _, k := range order {
		addSec(k)
	}
	for _, k := range keys {
		addSec(k)
	}
	return r
}

// anchor is the name a report goes by within the page: its alert ID, with
// nothing but letters, digits and dashes.
func anchor(id string) string {
	return "r-" + strings.Map(func(r rune) rune {
		if r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return r
		}
		return '_'
	}, id)
}

var (
	gap     = regexp.MustCompile(` {2,}`)
	clockRe = regexp.MustCompile(`^\d{1,2}:\d{2}(:\d{2})?$`)
	labelRe = regexp.MustCompile(`^([A-Z][A-Za-z0-9 ()-]{0,30}): (.+)$`)
)

func lines(key string, in []string) []line {
	var out []line
	for _, l := range in {
		ln := line{}
		if key == autopsy.SecProgram {
			if m := labelRe.FindStringSubmatch(l); m != nil {
				ln.Label, l = m[1], m[2]
			}
		}
		parts := gap.Split(strings.TrimSpace(l), -1)
		for i, p := range parts {
			ln.Cells = append(ln.Cells, cell{Text: p, Class: classOf(key, i, p)})
		}
		out = append(out, ln)
	}
	return out
}

func classOf(key string, i int, p string) string {
	switch {
	case i == 0 && clockRe.MatchString(p):
		return "time"
	case strings.HasPrefix(p, "aba "):
		return "cmd"
	case key == autopsy.SecWatched && i == 0 && len(parts(p)) <= 2:
		return "tag"
	case key == autopsy.SecAddresses && i == 0 && len(p) <= 16:
		return "tag"
	case looksLikePath(p):
		return "path"
	}
	return ""
}

func parts(s string) []string { return strings.Fields(s) }

// looksLikePath: a piece that is a file path or an address (not a sentence
// that mentions one), which gets a fixed-width font.
func looksLikePath(p string) bool {
	if strings.Contains(p, ". ") || strings.Contains(p, ": ") {
		return false // a sentence
	}
	return pathStart.MatchString(p) || (len(p) == 64 && strings.Trim(p, "0123456789abcdef") == "")
}

var pathStart = regexp.MustCompile(`^("?[A-Za-z]:\\|\\\\|/|~/|[a-z]+://)`)

func render(v pageView) []byte {
	var b bytes.Buffer
	if err := tmpl.Execute(&b, v); err != nil {
		// The template is fixed and the data is plain strings: this doesn't
		// happen. If it ever does, say so on the page rather than show half.
		b.Reset()
		b.WriteString("<!doctype html><meta charset=utf-8><title>ABA report</title><p>ABA couldn't lay out this report: " + template.HTMLEscapeString(err.Error()) + "</p>")
	}
	return b.Bytes()
}

// The page: everything in it is escaped by html/template (file names, web
// addresses and program names come from the caught program, which chose
// them). No script, nothing loaded from anywhere, and the policy at the
// top says so to the browser too.
var tmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="data:,">
<title>{{.Title}}</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1e24;--dim:#5b6472;--line:#e2e5ea;--code:#eef0f3;
--bad:#b4232c;--bad-bg:#fdeced;--warn:#8a5a00;--warn-bg:#fff4d6;--good:#1d7a3e;--good-bg:#e5f6ea;--accent:#2457c5}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--card:#1a1d24;--text:#e7e9ee;--dim:#a0a8b6;--line:#2c313b;--code:#242832;
--bad:#ff7b82;--bad-bg:#3a1c20;--warn:#ffc65c;--warn-bg:#352a12;--good:#6fd894;--good-bg:#16301f;--accent:#8fb0ff}}
*{box-sizing:border-box}
body{margin:0;overflow-wrap:anywhere;background:var(--bg);color:var(--text);font:16px/1.55 "Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
main{max-width:58rem;margin:0 auto;padding:2rem 1.25rem 3rem}
header.top{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;flex-wrap:wrap;margin-bottom:1.25rem}
.brand{font-weight:600;color:var(--dim);letter-spacing:.02em}
.meta{color:var(--dim);font-size:.9rem}
h1{font-size:1.5rem;line-height:1.3;margin:.1rem 0 .3rem}
h2{font-size:1.1rem;margin:0 0 .6rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1.1rem 1.3rem;margin:0 0 1rem}
.answer{border-left:6px solid var(--warn);background:var(--warn-bg)}
.answer.bad{border-left-color:var(--bad);background:var(--bad-bg)}
.answer.good{border-left-color:var(--good);background:var(--good-bg)}
.headline{font-size:1.3rem;font-weight:650;line-height:1.35;margin:0 0 .5rem}
.answer.bad .headline{color:var(--bad)}.answer.good .headline{color:var(--good)}.answer.warn .headline{color:var(--warn)}
.steps{border:2px solid var(--text)}
.steps li{margin:.35rem 0;font-size:1.05rem}
ul.lines{list-style:none;margin:0;padding:0}
ul.lines li{padding:.4rem 0;border-top:1px solid var(--line)}
ul.lines li:first-child{border-top:0;padding-top:0}
p.line{margin:.35rem 0}
.c{margin-right:.6rem}
.time{font-variant-numeric:tabular-nums;color:var(--dim);font-weight:600}
.path,.cmd{font-family:ui-monospace,"Cascadia Mono",Consolas,Menlo,monospace;font-size:.9em;overflow-wrap:anywhere;word-break:break-word}
.path{background:var(--code);border-radius:4px;padding:0 .25rem}
.cmd{background:var(--code);border-radius:4px;padding:.05rem .35rem;font-weight:600}
.tag{display:inline-block;font-size:.8rem;font-weight:600;border:1px solid var(--line);border-radius:999px;padding:0 .5rem;color:var(--dim)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem;margin:0}
dt{color:var(--dim)}dd{margin:0;overflow-wrap:anywhere}
.note{color:var(--dim);font-size:.9rem}
nav.list a{display:block;text-decoration:none;color:inherit;padding:.7rem .2rem;border-top:1px solid var(--line)}
nav.list a:first-of-type{border-top:0}
nav.list a:hover .what{text-decoration:underline}
.dot{display:inline-block;width:.7rem;height:.7rem;border-radius:50%;background:var(--warn);margin-right:.5rem}
.dot.bad{background:var(--bad)}.dot.good{background:var(--good)}
.what{font-weight:600}
.back{display:inline-block;margin-bottom:1rem;color:var(--accent)}
.index .report{display:none}
.index .report:target{display:block}
.index:has(.report:target) .listing{display:none}
footer{color:var(--dim);font-size:.85rem;margin-top:2rem;border-top:1px solid var(--line);padding-top:1rem}
@media print{
:root{--bg:#fff;--card:#fff;--text:#000;--dim:#333;--line:#bbb;--code:#f2f2f2;
--bad:#a1121b;--bad-bg:#fdeced;--warn:#6e4700;--warn-bg:#fff4d6;--good:#14632f;--good-bg:#e5f6ea;--accent:#1d4fb8}
body{font-size:11pt}main{max-width:none;padding:0}
.card{break-inside:avoid;border-color:#bbb}
.back{display:none}
.index:has(.report:target) .report:not(:target){display:none}
}
</style>
</head>
<body>
<main class="{{if .Index}}index{{end}}">
<header class="top"><span class="brand">A Better Antivirus</span><span class="meta">Shown {{.Generated}}</span></header>
{{if .Index}}
<section class="listing" id="list">
<h1>Reports</h1>
<p class="meta">Every program ABA caught and looked into, newest first. Pick one to see its full report.</p>
<div class="card">
{{if .Reports}}<nav class="list">{{range .Reports}}<a href="#{{.Anchor}}"><span class="dot {{.Tone}}"></span><span class="what">{{.Program}}</span> <span class="meta">· {{.When}}</span><br><span>{{.Headline}}</span></a>{{end}}</nav>
{{else}}<p>No reports yet. ABA writes one each time it catches a program and looks into what it did.</p>{{end}}
</div>
</section>
{{end}}
{{range .Reports}}
<article class="report" id="{{.Anchor}}">
{{if $.Index}}<a class="back" href="#list">← All reports</a>{{end}}
<h1>{{.Title}}</h1>
<p class="meta">{{.When}} · alert {{.ID}}</p>
<section class="card answer {{.Tone}}">
<p class="headline">{{.Headline}}</p>
{{range .Summary}}<p class="line">{{template "cells" .}}</p>{{end}}
</section>
{{if .Steps}}<section class="card steps"><h2>{{.StepsTitle}}</h2><ul class="lines">{{range .Steps}}<li>{{template "cells" .}}</li>{{end}}</ul></section>{{end}}
{{range .Sections}}
<section class="card sec-{{.Key}}"><h2>{{.Title}}</h2>
{{if eq .Key "program"}}<dl>{{range .Lines}}<dt>{{.Label}}</dt><dd>{{template "cells" .}}</dd>{{end}}</dl>
{{else}}<ul class="lines">{{range .Lines}}<li>{{template "cells" .}}</li>{{end}}</ul>{{end}}
</section>
{{end}}
</article>
{{end}}
<footer>
<p>This page isn't saved anywhere on this computer. ABA keeps its reports where only administrators can read them, because they name ABA's bait files: a stealer that could read them would know which files to leave alone. To see a report again: {{.Where}}.</p>
<p>To keep one, print it (Ctrl+P, or ⌘P on a Mac). A copy saved on this computer could be read by any program running as you.</p>
</footer>
</main>
</body>
</html>
{{define "cells"}}{{range .Cells}}<span class="c{{if .Class}} {{.Class}}{{end}}">{{.Text}}</span>{{end}}{{end}}`))
