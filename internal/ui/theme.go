// Package ui holds ABA's terminal look: colours, layout helpers, the
// install wizard, the live status dashboard and the step runner.
package ui

import (
	crand "crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

var (
	Leaf   = lipgloss.AdaptiveColor{Light: "#1E8A4C", Dark: "#7BD88F"}
	Jaw    = lipgloss.AdaptiveColor{Light: "#C4314B", Dark: "#FF6B85"}
	Amber  = lipgloss.AdaptiveColor{Light: "#B26B00", Dark: "#FFC66D"}
	Sky    = lipgloss.AdaptiveColor{Light: "#1F6FB2", Dark: "#7CC4FF"}
	Muted  = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#8B93A1"}
	Faint  = lipgloss.AdaptiveColor{Light: "#9CA3AF", Dark: "#5C6370"}
	Border = lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#3B4252"}
	Text   = lipgloss.AdaptiveColor{Light: "#111827", Dark: "#E5E9F0"}

	Bold    = lipgloss.NewStyle().Bold(true).Foreground(Text)
	Dim     = lipgloss.NewStyle().Foreground(Muted)
	Fainter = lipgloss.NewStyle().Foreground(Faint)
	Good    = lipgloss.NewStyle().Foreground(Leaf)
	Bad     = lipgloss.NewStyle().Foreground(Jaw)
	Warn    = lipgloss.NewStyle().Foreground(Amber)
	Info    = lipgloss.NewStyle().Foreground(Sky)
	Code    = lipgloss.NewStyle().Foreground(Leaf).Bold(true)
	Title   = lipgloss.NewStyle().Bold(true).Foreground(Text).MarginBottom(1)
	Section = lipgloss.NewStyle().Bold(true).Foreground(Leaf)

	Card = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(Border).Padding(0, 2)
)

const (
	IconOK   = "✓"
	IconBad  = "✗"
	IconWarn = "!"
	IconDot  = "•"
	IconArr  = "›"
)

// IsTTY reports whether stdout is an interactive terminal.
func IsTTY() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

// Width of the terminal (80 if unknown), capped for readability.
func Width() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	if w > 100 {
		return 100
	}
	return w
}

// Banner is the header shown on interactive screens.
func Banner(subtitle string) string {
	mark := lipgloss.NewStyle().Foreground(lipgloss.Color("#0B1F12")).Background(lipgloss.Color("#7BD88F")).Bold(true).Padding(0, 1).Render("ABA")
	name := lipgloss.NewStyle().Foreground(Text).Bold(true).Render(" A Better Antivirus")
	tag := Dim.Render("  " + subtitle)
	return mark + name + tag
}

// TierBadge renders a coloured tier label.
func TierBadge(t config.Tier) string {
	s := lipgloss.NewStyle().Bold(true).Padding(0, 1)
	switch t {
	case config.TierCritical:
		return s.Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#D7263D")).Render("CRITICAL")
	case config.TierWarn:
		return s.Foreground(lipgloss.Color("#1A1A1A")).Background(lipgloss.Color("#FFB000")).Render("WARN")
	case config.TierInfo:
		return s.Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#3B82F6")).Render("INFO")
	}
	return s.Render(strings.ToUpper(string(t)))
}

// TierWord is a coloured tier name without a background (for tables).
func TierWord(t config.Tier) string {
	switch t {
	case config.TierCritical:
		return Bad.Bold(true).Render("critical")
	case config.TierWarn:
		return Warn.Render("warn")
	}
	return Info.Render("info")
}

// Check renders ✓/✗ with a label.
func Check(ok bool, label string) string {
	if ok {
		return Good.Render(IconOK) + " " + label
	}
	return Bad.Render(IconBad) + " " + label
}

// KV renders aligned key/value rows.
func KV(rows [][2]string) string {
	w := 0
	for _, r := range rows {
		if l := lipgloss.Width(r[0]); l > w {
			w = l
		}
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(Dim.Render(fmt.Sprintf("%-*s", w, r[0])) + "  " + r[1] + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// Ago formats a time relative to now.
func Ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// Until formats a remaining duration.
func Until(t time.Time) string {
	d := time.Until(t)
	if d <= 0 {
		return "ended"
	}
	if d > 48*time.Hour {
		return fmt.Sprintf("%d days left", int(d.Hours()/24+0.5))
	}
	if d > time.Hour {
		return fmt.Sprintf("%dh left", int(d.Hours()))
	}
	return fmt.Sprintf("%dm left", int(d.Minutes())+1)
}

// Truncate shortens s to n display cells with an ellipsis.
func Truncate(s string, n int) string {
	if n <= 1 || lipgloss.Width(s) <= n {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r))+1 > n {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// TruncateMiddle keeps the start and end of a path.
func TruncateMiddle(s string, n int) string {
	r := []rune(s)
	if len(r) <= n || n < 8 {
		return s
	}
	keep := (n - 1) / 2
	return string(r[:keep]) + "…" + string(r[len(r)-(n-1-keep):])
}

// Println prints with a trailing newline.
func Println(s ...string) { fmt.Println(strings.Join(s, " ")) }

// Fail prints an error line.
func Fail(err error) {
	fmt.Fprintln(os.Stderr, Bad.Render(IconBad+" ")+err.Error())
}

// Hint prints a dim hint with a highlighted command.
func Hint(text, cmd string) string {
	return Dim.Render(text+" ") + Code.Render(cmd)
}

func randByte() byte {
	var b [1]byte
	crand.Read(b[:])
	return b[0]
}

// Heading is a section title preceded by a blank line.
func Heading(s string) string { return "\n" + Section.Render(s) }

// Tagline is the one-liner shown under the name.
const Tagline = "it's not an antivirus. it's a better one."
