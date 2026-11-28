package config

import "testing"

func TestKeepSecrets(t *testing.T) {
	old := PhoneConfig{Kind: "email", Email: EmailConfig{Host: "smtp.gmail.com", Port: 587, Username: "sam", Password: "pw", To: "a@b.co"}}
	p := PhoneConfig{Kind: "email", Email: EmailConfig{Host: "SMTP.gmail.com", Port: 465, Username: "sam", To: "c@d.co"}}
	if got := p.KeepSecrets(old); got.Email.Password != "pw" || got.Email.Port != 465 || got.Email.To != "c@d.co" {
		t.Fatalf("%+v", got)
	}
	// Another server or user: the password isn't sent there.
	p.Email.Username = "other"
	if got := p.KeepSecrets(old); got.Email.Password != "" {
		t.Fatal("password kept for another user")
	}
	// Another kind: nothing kept.
	d := PhoneConfig{Kind: "discord"}
	if got := d.KeepSecrets(PhoneConfig{Kind: "pushover", Pushover: PushoverConfig{AppToken: "x"}}); got != d {
		t.Fatalf("%+v", got)
	}
	n := PhoneConfig{Kind: "ntfy", Ntfy: NtfyConfig{Server: "https://ntfy.example.org", Topic: "t"}}
	if got := n.KeepSecrets(PhoneConfig{Kind: "ntfy", Ntfy: NtfyConfig{Server: "https://ntfy.sh", Topic: "t", Token: "tk"}}); got.Ntfy.Token != "" {
		t.Fatal("token sent to another server")
	}
	if got := n.KeepSecrets(PhoneConfig{Kind: "ntfy", Ntfy: NtfyConfig{Server: "https://ntfy.example.org/", Topic: "x", Token: "tk"}}); got.Ntfy.Token != "tk" {
		t.Fatal("token not kept")
	}
	po := PhoneConfig{Kind: "pushover"}
	got := po.KeepSecrets(PhoneConfig{Kind: "pushover", Pushover: PushoverConfig{AppToken: "a", UserKey: "u"}})
	if got.Pushover.AppToken != "a" || got.Pushover.UserKey != "u" {
		t.Fatalf("%+v", got)
	}
	if err := po.Check(false); err == nil {
		t.Fatal("empty Pushover keys pass a full check")
	}
	if err := po.Check(true); err != nil {
		t.Fatal(err)
	}
}

func TestValidEmail(t *testing.T) {
	for _, s := range []string{"a@b.co", "sam.okafor91@gmail.com", "x+y@mail.example.org"} {
		if !ValidEmail(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", "a", "a@b", "Sam <a@b.co>", "a@b.co\n", "a@b.co, c@d.co", "\"a b\"@c.co", "a@b.co\u2028"} {
		if ValidEmail(s) {
			t.Errorf("%q allowed", s)
		}
	}
}

func TestIgnoreRuleID(t *testing.T) {
	r := IgnoreRule{Path: `C:\X\a.exe`, Signer: "A", Baits: []string{"b", "a"}, Note: "x"}
	s := IgnoreRule{Path: `c:\x\A.EXE`, Signer: "a", Baits: []string{"A", "B"}, Note: "other"}
	if r.ID() != s.ID() || len(r.ID()) != 12 {
		t.Fatalf("%s %s", r.ID(), s.ID())
	}
	s.Tricks = true
	if r.ID() == s.ID() {
		t.Fatal("tricks don't change the ID")
	}
	s.Tricks, s.Baits = false, nil
	if r.ID() == s.ID() {
		t.Fatal("baits don't change the ID")
	}
}
