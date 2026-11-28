package appapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// The actions of PARITY.md beyond the first screens': how each is checked
// and what it runs. Paths, patterns and addresses are Windows' (the app is
// Windows only); the checks are plain string work, so they're tested on
// every system.

// maxArg is the most an ID or argument may be.
const maxArg = 8 << 10

var (
	hex12Re = regexp.MustCompile(`^[0-9a-f]{12}$`)
	// The bait wallet addresses ABA puts out (package clipbait's shapes).
	walletRes = []*regexp.Regexp{
		regexp.MustCompile(`^1[1-9A-HJ-NP-Za-km-z]{25,34}$`),
		regexp.MustCompile(`^bc1q[02-9ac-hj-np-z]{38}$`),
		regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`),
		regexp.MustCompile(`^T[1-9A-HJ-NP-Za-km-z]{33}$`),
	}
	driveRe = regexp.MustCompile(`^[A-Za-z]:\\`)
)

// ValidRuleID reports whether id looks like an ignore rule's or a
// suggestion's ID (config.IgnoreRule.ID, trust.Suggestion.ID).
func ValidRuleID(id string) bool { return hex12Re.MatchString(id) }

// ValidWallet reports whether s is shaped like a bait wallet address.
func ValidWallet(s string) bool {
	for _, re := range walletRes {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// plainText: valid UTF-8, no control or invisible direction characters, at
// most max bytes.
func plainText(what, s string, max int) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s isn't text", what)
	}
	if err := config.PlainText(what, s, max); err != nil {
		return err
	}
	for _, r := range s {
		if (r >= '\u200b' && r <= '\u200f') || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') || r == '\ufeff' {
			return fmt.Errorf("%s has a hidden character", what)
		}
	}
	return nil
}

// noFlag: a value that is passed as a flag's own value ("--signer=x") may
// start with anything, but a value on its own must not look like a flag.
func noFlag(what, s string) error {
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("%s can't start with -", what)
	}
	return nil
}

// protectedDirs are folders a bait must never be made in: Windows' and
// programs' own, and ABA's.
var protectedDirs = []string{
	`c:\windows`, `c:\program files`, `c:\program files (x86)`, `c:\programdata`,
	`c:\$recycle.bin`, `c:\system volume information`, `c:\recovery`, `c:\boot`,
}

// localPath checks an absolute path on a local drive: "C:\…", no ".." or
// "." parts, no doubled separators, no alternate data streams, no device or
// network paths, no wildcards.
func localPath(what, p string, wild bool) error {
	if err := plainText(what, p, 400); err != nil {
		return err
	}
	if !driveRe.MatchString(p) {
		return fmt.Errorf("%s has to be a full path on a drive of this PC (C:\\…)", what)
	}
	if strings.ContainsAny(p, `/"<>|`) || strings.Contains(p[2:], ":") {
		return fmt.Errorf("%s has a character a path can't have", what)
	}
	if !wild && strings.ContainsAny(p, "*?") {
		return fmt.Errorf("%s can't have * or ?", what)
	}
	parts := strings.Split(p[3:], `\`)
	for i, part := range parts {
		if part == "" && i == len(parts)-1 {
			return fmt.Errorf("%s has to end in a file name", what)
		}
		if part == "" || part == "." || part == ".." || strings.TrimRight(part, ". ") != part {
			return fmt.Errorf("%s has an odd part (%q)", what, part)
		}
	}
	return nil
}

// CustomBaitPath reports what's wrong with making file p a bait.
func CustomBaitPath(p string) error {
	if err := localPath("the file", p, false); err != nil {
		return err
	}
	if len(p) > 260 {
		return errors.New("the path is too long")
	}
	low := strings.ToLower(p)
	if strings.Count(low, `\`) < 2 {
		return errors.New("a bait goes in a folder, not at the top of a drive")
	}
	for _, d := range protectedDirs { // on any drive
		if strings.HasPrefix(low[2:], d[2:]+`\`) {
			return errors.New("a bait can't go in Windows' or programs' own folders")
		}
	}
	return nil
}

// IgnorePattern reports what's wrong with trusting programs matching
// pattern (a glob on the program's full path: * within a folder, ** across).
func IgnorePattern(pattern string) error {
	what := "the program's path"
	if strings.HasPrefix(pattern, `**\`) {
		if err := plainText(what, pattern, 400); err != nil {
			return err
		}
		if strings.ContainsAny(pattern, `/"<>|:`) {
			return fmt.Errorf("%s has a character a path can't have", what)
		}
	} else if err := localPath(what, pattern, true); err != nil {
		return err
	}
	name := pattern[strings.LastIndexByte(pattern, '\\')+1:]
	literal := strings.NewReplacer("*", "", "?", "").Replace(name)
	if strings.HasPrefix(name, "*") || len(literal) < 3 || strings.TrimLeft(literal, ".") != literal {
		return errors.New("the pattern has to name the program (…\\backup.exe, not …\\*.exe)")
	}
	return nil
}

// decodeArg reads a JSON argument into v: an object, nothing else after
// it, no fields v doesn't have.
func decodeArg(arg string, v any) error {
	d := json.NewDecoder(strings.NewReader(arg))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("not the settings this takes: %v", err)
	}
	if d.More() {
		return errors.New("more than one set of settings")
	}
	return nil
}

// IgnoreAdd is the argument of ignore-add.
type IgnoreAdd struct {
	Path        string `json:"path"`
	Signer      string `json:"signer,omitempty"`
	Note        string `json:"note,omitempty"`
	AllowTricks bool   `json:"allowTricks,omitempty"`
}

// ResponsesArg is the argument of responses.
type ResponsesArg struct {
	Warn     []string `json:"warn"`
	Critical []string `json:"critical"`
}

func actionsFlag(what string, acts []string) (string, error) {
	seen := map[string]bool{}
	for _, a := range acts {
		known := false
		for _, x := range config.AllActions {
			known = known || string(x) == a
		}
		if !known {
			return "", fmt.Errorf("%s: no action %q", what, a)
		}
		if seen[a] {
			return "", fmt.Errorf("%s: %s is there twice", what, a)
		}
		seen[a] = true
	}
	return strings.Join(acts, ","), nil
}

// prepareMore checks and builds the actions of PARITY.md.
func prepareMore(kind, id, arg string, ex Exists) (args []string, stdin []byte, err error) {
	alert := func() error {
		if !ValidAlertID(id) {
			return fmt.Errorf("not an alert: %q", id)
		}
		if ex.Alert == nil || !ex.Alert(id) {
			return fmt.Errorf("no alert %s", id)
		}
		if arg != "" {
			return fmt.Errorf("%s takes no argument", kind)
		}
		return nil
	}
	none := func() error {
		if id != "" || arg != "" {
			return fmt.Errorf("%s takes no ID or argument", kind)
		}
		return nil
	}
	onlyArg := func() error {
		if id != "" {
			return fmt.Errorf("%s takes no ID", kind)
		}
		return nil
	}
	switch kind {
	case ActAlertJSON:
		return []string{"alerts", "json", "--", id}, nil, alert()
	case ActAutopsyNow:
		return []string{"autopsy", "--now", "--", id}, nil, alert()
	case ActExportIOC:
		return []string{"export-ioc", "--downloads", "--", id}, nil, alert()
	case ActDoctor:
		return []string{"doctor"}, nil, none()
	case ActDoctorFix:
		return []string{"doctor", "--fix"}, nil, none()
	case ActBaitRename:
		return []string{"bait", "rename"}, nil, none()
	case ActPhoneOff:
		return []string{"phone", "off"}, nil, none()
	case ActClipboardTest:
		return []string{"clipboard", "test"}, nil, none()
	case ActMinersTest:
		return []string{"miners", "test"}, nil, none()

	case ActLearnDays:
		if err := onlyArg(); err != nil {
			return nil, nil, err
		}
		n, err := strconv.Atoi(arg)
		if err != nil || n < 0 || n > 30 || strconv.Itoa(n) != arg {
			return nil, nil, errors.New("learning mode is 0 (off) to 30 days")
		}
		return []string{"learn", "--days=" + arg}, nil, nil
	case ActLearnTrust:
		if err := onlyArg(); err != nil {
			return nil, nil, err
		}
		ids := strings.Split(arg, ",")
		if arg == "" || len(ids) > 50 {
			return nil, nil, errors.New("say which programs to trust (1 to 50)")
		}
		for _, x := range ids {
			if !ValidRuleID(x) {
				return nil, nil, fmt.Errorf("not a program to trust: %q", x)
			}
		}
		return []string{"learn", "--trust=" + arg}, nil, nil
	case ActIgnoreAdd:
		if err := onlyArg(); err != nil {
			return nil, nil, err
		}
		var in IgnoreAdd
		if err := decodeArg(arg, &in); err != nil {
			return nil, nil, err
		}
		if err := IgnorePattern(in.Path); err != nil {
			return nil, nil, err
		}
		if err := plainText("the publisher", in.Signer, 200); err != nil {
			return nil, nil, err
		}
		if in.Signer != "" && len(strings.TrimSpace(in.Signer)) < 3 {
			return nil, nil, errors.New("the publisher's name is too short to pin anything")
		}
		if err := plainText("the note", in.Note, 200); err != nil {
			return nil, nil, err
		}
		args := []string{"ignore", "add"}
		if in.Signer != "" {
			args = append(args, "--signer="+in.Signer)
		}
		if in.Note != "" {
			args = append(args, "--note="+in.Note)
		}
		if in.AllowTricks {
			args = append(args, "--allow-tricks")
		}
		return append(args, "--", in.Path), nil, nil
	case ActIgnoreRemove:
		switch {
		case arg != "":
			return nil, nil, errors.New("ignore-remove takes no argument")
		case !ValidRuleID(id):
			return nil, nil, fmt.Errorf("not a rule: %q", id)
		case ex.Rule == nil || !ex.Rule(id):
			return nil, nil, fmt.Errorf("no rule %s", id)
		}
		return []string{"ignore", "remove", "--", id}, nil, nil
	case ActBaitAdd:
		switch {
		case arg != "":
			return nil, nil, errors.New("bait-add takes no argument")
		case !ValidBaitID(id) || strings.HasPrefix(id, "custom-"):
			return nil, nil, fmt.Errorf("not a bait from the catalog: %q", id)
		case ex.Catalog == nil || !ex.Catalog(id):
			return nil, nil, fmt.Errorf("no bait %s in the catalog", id)
		}
		return []string{"bait", "add", "--", id}, nil, nil
	case ActBaitAddFile:
		if err := onlyArg(); err != nil {
			return nil, nil, err
		}
		if err := CustomBaitPath(arg); err != nil {
			return nil, nil, err
		}
		return []string{"bait", "add", "--file", "--", arg}, nil, nil
	case ActBaitRemove:
		switch {
		case arg != "":
			return nil, nil, errors.New("bait-remove takes no argument")
		case !ValidBaitID(id):
			return nil, nil, fmt.Errorf("not a bait: %q", id)
		case ex.Bait == nil || !ex.Bait(id):
			return nil, nil, fmt.Errorf("no bait %s", id)
		}
		return []string{"bait", "remove", "--", id}, nil, nil
	case ActResponses:
		if err := onlyArg(); err != nil {
			return nil, nil, err
		}
		var in ResponsesArg
		if err := decodeArg(arg, &in); err != nil {
			return nil, nil, err
		}
		w, err := actionsFlag("suspicious", in.Warn)
		if err != nil {
			return nil, nil, err
		}
		c, err := actionsFlag("critical", in.Critical)
		if err != nil {
			return nil, nil, err
		}
		return []string{"preset", "custom", "--warn=" + w, "--critical=" + c}, nil, nil
	case ActRecent:
		if err := onlyArg(); err != nil {
			return nil, nil, err
		}
		if arg != "on" && arg != "off" {
			return nil, nil, fmt.Errorf("recent takes on or off, not %q", arg)
		}
		return []string{"recent", arg}, nil, nil
	case ActPhoneTier:
		if err := onlyArg(); err != nil {
			return nil, nil, err
		}
		if !config.ValidTier(config.Tier(arg)) {
			return nil, nil, fmt.Errorf("no such alerts: %q (info, warn or critical)", arg)
		}
		return []string{"phone", "tier", arg}, nil, nil
	case ActPhoneSet:
		if err := onlyArg(); err != nil {
			return nil, nil, err
		}
		var in config.PhoneSetting
		if err := decodeArg(arg, &in); err != nil {
			return nil, nil, err
		}
		if !in.Only() {
			return nil, nil, fmt.Errorf("these settings are for %s but hold another kind's too", in.Kind)
		}
		if in.MinTier != "" && !config.ValidTier(in.MinTier) {
			return nil, nil, errors.New("minTier is info, warn or critical")
		}
		if err := in.Check(true); err != nil {
			return nil, nil, err
		}
		b, err := json.Marshal(in)
		if err != nil {
			return nil, nil, err
		}
		return []string{"phone", "set"}, b, nil
	case ActCanaryOn:
		if err := onlyArg(); err != nil {
			return nil, nil, err
		}
		var in struct {
			Email string `json:"email"`
		}
		if err := decodeArg(arg, &in); err != nil {
			return nil, nil, err
		}
		if !config.ValidEmail(in.Email) {
			return nil, nil, errors.New("that isn't an email address")
		}
		b, _ := json.Marshal(in)
		return []string{"canary", "on"}, b, nil
	case ActClipboardKey:
		switch {
		case arg != "":
			return nil, nil, errors.New("clipboard-key takes no argument")
		case !ValidWallet(id):
			return nil, nil, errors.New("that isn't a wallet address ABA puts out")
		}
		return []string{"clipboard", "key", "--", id}, nil, nil
	case ActUninstall:
		switch {
		case id != "":
			return nil, nil, errors.New("uninstall takes no ID")
		case arg == "":
			return []string{"uninstall"}, nil, nil
		case arg == "purge":
			return []string{"uninstall", "--purge"}, nil, nil
		}
		return nil, nil, fmt.Errorf("uninstall takes \"\" or purge, not %q", arg)
	}
	return nil, nil, fmt.Errorf("unknown action %q", kind)
}

// keepKey takes a bait wallet's private key out of what the page gets: the
// app shows it in a window of its own.
func keepKey(res Result) Result {
	if !res.OK {
		return res
	}
	raw, _ := res.Details.(json.RawMessage)
	var d struct {
		Address, Coin, Key, How string
	}
	if json.Unmarshal(raw, &d) != nil || d.Key == "" {
		return Result{OK: false, Message: "ABA didn't give the key back as expected."}
	}
	return Result{OK: true, Message: "The key is shown in a window of its own. Anyone with it can take what's sent to that address: don't share it.",
		Details: map[string]any{"address": d.Address, "coin": d.Coin, "shown": true},
		Private: &Private{Title: "Private key of a bait address", Text: "Bait address " + d.Address + " (" + d.Coin + ")\n\nPrivate key:\n" + d.Key + "\n\n" + d.How + "\nAnyone with this key can take what's there: don't share it."}}
}

// reveal is phone-reveal: the ntfy topic, for the app's own window.
func (a *Actor) reveal(id, arg string) Result {
	if id != "" || arg != "" {
		return Result{OK: false, Message: "phone-reveal takes no ID or argument"}
	}
	if a.Secrets == nil {
		return Result{OK: false, Message: "not available"}
	}
	sec, err := a.Secrets()
	if err != nil {
		return Result{OK: false, Message: "ABA couldn't read its secrets file: " + err.Error()}
	}
	p := sec.Phone
	if p.Kind != "ntfy" {
		return Result{OK: false, Message: "Only an ntfy topic can be shown (the rest are passwords: type them again to change them)."}
	}
	srv := p.Ntfy.Server
	if srv == "" {
		srv = "https://ntfy.sh"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "Topic: %s\nServer: %s\n\nIn the ntfy app, tap + and subscribe to this topic (on this server). Anyone who knows it can read your alerts: keep it to yourself.", p.Ntfy.Topic, strings.TrimSuffix(srv, "/"))
	return Result{OK: true, Message: "Your ntfy topic is shown in a window of its own.", Details: map[string]any{"shown": true},
		Private: &Private{Title: "Your ntfy topic", Text: b.String()}}
}
