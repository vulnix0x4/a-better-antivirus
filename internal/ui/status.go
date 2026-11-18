package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

// StatusData is everything the dashboard shows (all readable without admin).
type StatusData struct {
	Cfg     *config.Config
	State   *config.State
	Service svcctl.State
	Alerts  []*alerts.Alert
	Err     error
	At      time.Time
}

func LoadStatus() StatusData {
	d := StatusData{At: time.Now()}
	d.Cfg, d.Err = config.LoadConfig()
	d.State, _ = config.LoadState()
	d.Service, _ = svcctl.Status()
	d.Alerts, _ = alerts.List(8)
	return d
}

func actionList(acts []config.Action) string {
	if len(acts) == 0 {
		return Dim.Render("notify only")
	}
	var s []string
	for _, a := range acts {
		s = append(s, string(a))
	}
	return strings.Join(s, ", ")
}

// RenderStatus draws the dashboard.
func RenderStatus(d StatusData) string {
	var b strings.Builder
	b.WriteString(Banner(Tagline) + "\n\n")
	if d.Err != nil {
		b.WriteString(Bad.Render(IconBad+" ") + d.Err.Error() + "\n\n" + Hint("Set it up with", "aba install") + "\n")
		return b.String()
	}
	cfg, st := d.Cfg, d.State
	w := Width()

	// Emergency banner.
	if st != nil && (st.Isolation != nil || len(st.Frozen) > 0 || len(st.Blocked) > 0) {
		var lines []string
		if st.Isolation != nil {
			lines = append(lines, fmt.Sprintf("This PC is ISOLATED from the network since %s (alert %s).", st.Isolation.Since.Format("Jan 2 15:04"), st.Isolation.AlertID))
		}
		if len(st.Frozen) > 0 {
			lines = append(lines, fmt.Sprintf("%d process(es) frozen.", len(st.Frozen)))
		}
		if len(st.Blocked) > 0 {
			lines = append(lines, fmt.Sprintf("%d program(s) blocked from the internet.", len(st.Blocked)))
		}
		lines = append(lines, "", "Review: "+Code.Render("aba alerts show <id>")+"   Undo when safe: "+Code.Render("aba release"))
		box := lipgloss.NewStyle().Border(lipgloss.ThickBorder()).BorderForeground(Jaw).Padding(0, 2).Width(w - 4).
			Render(Bad.Bold(true).Render("RESPONSE ACTIVE") + "\n" + strings.Join(lines, "\n"))
		b.WriteString(box + "\n\n")
	}

	// Protection card.
	svcOK := d.Service == svcctl.Running
	svcLine := Check(svcOK, "Service "+string(d.Service))
	if svcOK && st != nil && !st.Heartbeat.IsZero() && time.Since(st.Heartbeat) > 3*time.Minute {
		svcLine = Warn.Render(IconWarn) + " Service running, but quiet since " + Ago(st.Heartbeat)
	}
	prot := []string{svcLine}
	healthy, total := 0, 0
	if st != nil {
		for _, h := range st.Health {
			if h.Name == "Baits" || h.Name == "Network guard" {
				continue
			}
			prot = append(prot, Check(h.OK, h.Name+": "+h.Detail))
		}
		for _, bs := range st.Baits {
			if bs.Status == "retired" {
				continue
			}
			total++
			if bs.Status == "ok" {
				healthy++
			}
		}
	}
	prot = append(prot, Check(total > 0 && healthy == total, fmt.Sprintf("%d of %d baits healthy", healthy, total)))
	if st != nil && !st.Heartbeat.IsZero() {
		prot = append(prot, Dim.Render("last check "+Ago(st.Heartbeat)))
	}
	ver := "version unknown"
	if st != nil && st.ServiceVersion != "" {
		ver = "version " + st.ServiceVersion
	}
	if cfg.AutoUpdate {
		ver += " · auto-update on"
		if st != nil && st.Update != nil && !st.Update.UpdatedAt.IsZero() && time.Since(st.Update.UpdatedAt) < 7*24*time.Hour {
			ver += " (updated " + Ago(st.Update.UpdatedAt) + ")"
		}
	} else {
		ver += " · auto-update off"
	}
	prot = append(prot, Dim.Render(ver))

	// Response card.
	resp := []string{Bold.Render(cfg.PresetName())}
	resp = append(resp, Dim.Render("critical ")+actionList(cfg.Responses[config.TierCritical]))
	resp = append(resp, Dim.Render("warn     ")+actionList(cfg.Responses[config.TierWarn]))
	if cfg.Learning(time.Now()) && cfg.LearningMatters() {
		resp = append(resp, Warn.Render("learning mode, "+Until(cfg.LearningUntil))+Dim.Render(": only critical is stopped"))
	}
	if st != nil && st.Isolation != nil {
		resp = append(resp, Bad.Render("network: ISOLATED"))
	} else {
		resp = append(resp, Good.Render("network: online"))
	}

	half := (w - 4) / 2
	left := Card.Width(half).Render(Section.Render("Protection") + "\n" + strings.Join(prot, "\n"))
	right := Card.Width(w - 4 - half).Render(Section.Render("Response") + "\n" + strings.Join(resp, "\n"))
	if w < 70 {
		b.WriteString(left + "\n" + right + "\n")
	} else {
		b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right) + "\n")
	}

	// Alerts.
	b.WriteString(Heading("Recent alerts") + "\n")
	if len(d.Alerts) == 0 {
		b.WriteString(Dim.Render("  Nothing has touched your baits. ") + Hint("Try", "aba test") + "\n")
	} else {
		b.WriteString(AlertTable(d.Alerts, w) + "\n")
	}
	return b.String()
}

// AlertTable renders a compact list of alerts.
func AlertTable(list []*alerts.Alert, w int) string {
	var b strings.Builder
	head := fmt.Sprintf("  %-12s %-9s %-24s %s", "WHEN", "TIER", "WHO", "WHAT")
	b.WriteString(Fainter.Render(head) + "\n")
	for _, a := range list {
		when := a.Time.Format("Jan 02 15:04")
		who := Truncate(a.ExeName(), 24)
		what := ""
		if len(a.Baits) > 0 {
			what = a.Baits[0].Name
			if len(a.Baits) > 1 {
				what += fmt.Sprintf(" +%d more", len(a.Baits)-1)
			}
		} else {
			what = a.Title
		}
		var tags []string
		if a.Test {
			tags = append(tags, "test")
		}
		if a.Learning {
			tags = append(tags, "learning")
		}
		for _, r := range a.Actions {
			if r.OK {
				tags = append(tags, string(r.Action))
			}
		}
		if a.Status == "resolved" {
			tags = append(tags, "resolved")
		}
		tier := lipgloss.NewStyle().Width(9).Render(TierWord(a.Tier))
		line := fmt.Sprintf("  %-12s %s %-24s %s", when, tier, who, Truncate(what, w-52))
		b.WriteString(line + "\n")
		sub := Fainter.Render("    " + a.ID)
		if len(tags) > 0 {
			sub += "  " + Dim.Render(strings.Join(tags, " · "))
		}
		b.WriteString(sub + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// AlertDetail renders one alert fully.
func AlertDetail(a *alerts.Alert) string {
	var b strings.Builder
	b.WriteString(TierBadge(a.Tier) + " " + Bold.Render(a.Title) + "\n")
	b.WriteString(Dim.Render(a.Time.Format("Mon Jan 2 2006, 15:04:05")+"  ·  "+a.ID) + "\n")
	if a.Summary != "" {
		b.WriteString("\n" + a.Summary + "\n")
	}
	if a.Test {
		b.WriteString(Info.Render("This was a test run by `aba test`.") + "\n")
	}
	if a.Learning {
		b.WriteString(Warn.Render("Learning mode: no action was taken. ") + Hint("Review with", "aba learn") + "\n")
	}
	if len(a.Baits) > 0 {
		b.WriteString(Heading("Baits touched") + "\n")
		for _, h := range a.Baits {
			b.WriteString(fmt.Sprintf("  %s %s %s\n    %s\n", Dim.Render(h.Time.Format("15:04:05.000")), h.Access, Bold.Render(h.Name), Fainter.Render(h.Path)))
		}
	}
	if p := a.Process; p != nil {
		b.WriteString(Heading("Reader") + "\n")
		rows := [][2]string{{"Process", fmt.Sprintf("%s (pid %d)", a.ExeName(), p.PID)}}
		if p.Image != "" {
			rows = append(rows, [2]string{"Path", p.Image})
		}
		sig := p.Signature.String()
		if p.Signature.Valid {
			sig = Good.Render(sig)
		} else {
			sig = Bad.Render(sig)
		}
		rows = append(rows, [2]string{"Signature", sig})
		if p.CommandLine != "" {
			rows = append(rows, [2]string{"Command", Truncate(p.CommandLine, Width()-14)})
		}
		if p.User != "" {
			rows = append(rows, [2]string{"User", p.User})
		}
		if p.SHA256 != "" {
			rows = append(rows, [2]string{"SHA-256", p.SHA256})
		}
		for i, par := range p.Parents {
			label := "Parent"
			if i > 0 {
				label = strings.Repeat(" ", 2*i) + "└ parent"
			}
			v := fmt.Sprintf("pid %d (exited)", par.PID)
			if !par.Exited {
				v = fmt.Sprintf("%s (pid %d)", par.Image, par.PID)
			}
			rows = append(rows, [2]string{label, v})
		}
		b.WriteString(indent(KV(rows), 2) + "\n")
		if len(p.Connections) > 0 {
			b.WriteString(Heading("Network connections at detection") + "\n")
			for _, c := range p.Connections {
				line := fmt.Sprintf("  %-5s %-22s", c.Proto, c.Local)
				if c.Remote != "" && !strings.HasPrefix(c.Remote, "0.0.0.0") && !strings.HasPrefix(c.Remote, "[::]") {
					line += " → " + Bold.Render(c.Remote)
				}
				if c.State != "" {
					line += " " + Dim.Render(c.State)
				}
				b.WriteString(line + "\n")
			}
		}
	}
	if len(a.Verdict.Reasons) > 0 {
		b.WriteString(Heading("Why this severity") + "\n")
		for _, r := range a.Verdict.Reasons {
			b.WriteString("  " + IconDot + " " + r + "\n")
		}
	}
	if len(a.Actions) > 0 {
		b.WriteString(Heading("Response") + "\n")
		for _, r := range a.Actions {
			b.WriteString("  " + Check(r.OK, r.Action.Describe()) + " " + Dim.Render(r.Detail) + "\n")
		}
		if a.LatencyMS > 0 {
			b.WriteString(Dim.Render(fmt.Sprintf("  frozen %d ms after the read was logged", a.LatencyMS)) + "\n")
		}
	}
	if a.Status == "resolved" {
		b.WriteString("\n" + Good.Render("Resolved: "+a.Note) + "\n")
	} else if a.Did(config.ActionFreeze) || a.Did(config.ActionIsolate) || a.Did(config.ActionBlockProgram) {
		b.WriteString(Heading("Next") + "\n")
		b.WriteString("  " + Hint("It's malware:", "aba kill "+shortID(a.ID)) + "\n")
		b.WriteString("  " + Hint("It's yours:  ", "aba resume "+shortID(a.ID)) + "\n")
		b.WriteString("  " + Hint("Undo all:    ", "aba release") + "\n")
	}
	if a.Tier == config.TierCritical && !a.Test && a.Status != "resolved" {
		b.WriteString(Heading("If you didn't cause this") + "\n")
		for i, s := range alerts.Checklist(a) {
			b.WriteString(lipgloss.NewStyle().PaddingLeft(5).Width(Width() - 2).Render(fmt.Sprintf("%d. %s", i+1, s))[3:] + "\n")
		}
	}
	return b.String()
}

func shortID(id string) string {
	if i := strings.LastIndex(id, "-"); i > 0 {
		return id[i+1:]
	}
	return id
}

func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
}

// ---- live dashboard ----

type tickMsg time.Time

type statusModel struct {
	data StatusData
}

func (m statusModel) Init() tea.Cmd { return tick() }

func tick() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m statusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "r":
			m.data = LoadStatus()
		}
	case tickMsg:
		m.data = LoadStatus()
		return m, tick()
	case tea.WindowSizeMsg:
		return m, nil
	}
	return m, nil
}

func (m statusModel) View() string {
	return RenderStatus(m.data) + "\n" + Fainter.Render("  q quit · r refresh · live, updates every 2s") + "\n"
}

// RunDashboard shows the live dashboard (or a single snapshot without a TTY).
func RunDashboard(once bool) error {
	d := LoadStatus()
	if once || !IsTTY() {
		fmt.Print(RenderStatus(d))
		return nil
	}
	_, err := tea.NewProgram(statusModel{data: d}, tea.WithAltScreen()).Run()
	return err
}
