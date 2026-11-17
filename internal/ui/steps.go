package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vulnix0x4/a-better-antivirus/internal/install"
)

type stepState int

const (
	pending stepState = iota
	running
	done
	warned
	failed
)

type stepRow struct {
	name   string
	state  stepState
	detail string
	took   time.Duration
}

type stepsModel struct {
	steps   []install.Step
	rows    []stepRow
	cur     int
	spin    spinner.Model
	started time.Time
	err     error
	quit    bool
}

type stepDone struct {
	detail string
	err    error
	took   time.Duration
}

func (m stepsModel) Init() tea.Cmd { return tea.Batch(m.spin.Tick, m.runCurrent()) }

func (m stepsModel) runCurrent() tea.Cmd {
	if m.cur >= len(m.steps) {
		return nil
	}
	st := m.steps[m.cur]
	return func() tea.Msg {
		t := time.Now()
		d, err := st.Run()
		return stepDone{d, err, time.Since(t)}
	}
}

func (m stepsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.err, m.quit = fmt.Errorf("cancelled"), true
			return m, tea.Quit
		}
	case spinner.TickMsg:
		var c tea.Cmd
		m.spin, c = m.spin.Update(msg)
		return m, c
	case stepDone:
		r := &m.rows[m.cur]
		r.detail, r.took = msg.detail, msg.took
		switch {
		case msg.err == nil:
			r.state = done
		case m.steps[m.cur].Soft:
			r.state, r.detail = warned, msg.err.Error()
		default:
			r.state, r.detail = failed, msg.err.Error()
			m.err, m.quit = fmt.Errorf("%s: %w", r.name, msg.err), true
			return m, tea.Quit
		}
		m.cur++
		if m.cur >= len(m.steps) {
			m.quit = true
			return m, tea.Quit
		}
		m.rows[m.cur].state = running
		return m, m.runCurrent()
	}
	return m, nil
}

func (m stepsModel) View() string {
	var b strings.Builder
	w := Width() - 6
	for _, r := range m.rows {
		var icon string
		name := r.name
		switch r.state {
		case pending:
			icon, name = Fainter.Render(IconDot), Fainter.Render(name)
		case running:
			icon = m.spin.View()
		case done:
			icon = Good.Render(IconOK)
		case warned:
			icon = Warn.Render(IconWarn)
		case failed:
			icon = Bad.Render(IconBad)
		}
		b.WriteString(" " + icon + " " + name)
		if r.state == done && r.took > 1500*time.Millisecond {
			b.WriteString(Fainter.Render(fmt.Sprintf("  %.1fs", r.took.Seconds())))
		}
		b.WriteString("\n")
		if r.detail != "" && r.state != pending {
			style := Dim
			if r.state == failed {
				style = Bad
			} else if r.state == warned {
				style = Warn
			}
			b.WriteString(lipgloss.NewStyle().PaddingLeft(4).Width(w).Render(style.Render(r.detail)) + "\n")
		}
	}
	return b.String()
}

// RunSteps executes steps with live progress. Without a TTY it prints plainly.
func RunSteps(steps []install.Step) error {
	if len(steps) == 0 {
		return nil
	}
	if !IsTTY() {
		for _, s := range steps {
			d, err := s.Run()
			switch {
			case err == nil:
				fmt.Printf("%s %s %s\n", IconOK, s.Name, d)
			case s.Soft:
				fmt.Printf("%s %s: %v\n", IconWarn, s.Name, err)
			default:
				fmt.Printf("%s %s: %v\n", IconBad, s.Name, err)
				return fmt.Errorf("%s: %w", s.Name, err)
			}
		}
		return nil
	}
	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(lipgloss.NewStyle().Foreground(Leaf)))
	m := stepsModel{steps: steps, spin: sp, started: time.Now()}
	for _, s := range steps {
		m.rows = append(m.rows, stepRow{name: s.Name})
	}
	m.rows[0].state = running
	out, err := tea.NewProgram(m).Run()
	if err != nil {
		return err
	}
	return out.(stepsModel).err
}
