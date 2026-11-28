package appapi

import (
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/origin"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// The scenarios the fixtures in testdata/ are made from: realistic files as
// the service writes them, on a Windows PC, on 27 Nov 2026 at 14:03 UTC.

var now = time.Date(2026, 11, 27, 14, 3, 0, 0, time.UTC)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

const user = `C:\Users\sam`

// plantedBaits are 14 baits, as state.json lists them.
func plantedBaits(check time.Time) map[string]*config.BaitState {
	created := at("2026-10-02T09:12:00Z")
	mk := func(id, name, kind string, files ...config.BaitFile) *config.BaitState {
		return &config.BaitState{ID: id, Name: name, Kind: kind, Files: files, Status: "ok", CreatedAt: created, LastCheck: check}
	}
	f := func(p string, size int64, text string) config.BaitFile {
		return config.BaitFile{Path: p, Audit: true, Size: size, Text: text, Created: true, ModTime: created}
	}
	side := func(p string, size int64) config.BaitFile {
		return config.BaitFile{Path: p, Size: size, Created: true, ModTime: created}
	}
	ld := user + `\AppData\Local`
	rd := user + `\AppData\Roaming`
	return map[string]*config.BaitState{
		"discord": mk("discord", "Discord token store", "decoy",
			f(rd+`\discord\Local Storage\leveldb\000005.ldb`, 2148, ""), side(rd+`\discord\Local Storage\leveldb\CURRENT`, 16)),
		"chrome-profile": mk("chrome-profile", "extra profile inside your Chrome", "decoy",
			f(ld+`\Google\Chrome\User Data\Profile 23\Login Data`, 40960, ""), f(ld+`\Google\Chrome\User Data\Profile 23\Network\Cookies`, 28672, "")),
		"metamask": mk("metamask", "MetaMask wallet (inside a fake browser)", "decoy",
			f(ld+`\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\000003.log`, 5120, "")),
		"ssh-backup": mk("ssh-backup", "Old SSH key backup (~/.ssh)", "file",
			f(user+`\.ssh\id_rsa.bak`, 1679, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n…\n-----END OPENSSH PRIVATE KEY-----\n")),
		"telegram": mk("telegram", "Telegram Desktop session", "decoy",
			f(rd+`\Telegram Desktop\tdata\key_datas`, 332, "")),
		"desktop-passwords": mk("desktop-passwords", "password list on the Desktop", "file",
			f(user+`\Desktop\passwords.txt`, 412, "gmail: sam.okafor91@gmail.com / Summer2019!\nbank: 4417 web login / Tr0ub4dor&3\nsteam: samok / gamer4life\n")),
		"edge-profile": mk("edge-profile", "extra profile inside your Edge", "decoy",
			f(ld+`\Microsoft\Edge\User Data\Profile 7\Login Data`, 40960, "")),
		"exodus": mk("exodus", "Exodus wallet", "decoy",
			f(rd+`\Exodus\exodus.wallet\seed.seco`, 9384, ""), side(rd+`\Exodus\exodus.wallet\passphrase.json`, 92)),
		"aws": mk("aws", "AWS credentials (~/.aws)", "canary",
			f(user+`\.aws\credentials`, 116, "[default]\naws_access_key_id = AKIA2EXAMPLE7QX4TZ\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")),
		"seed-phrase": mk("seed-phrase", "wallet recovery phrase (Documents)", "file",
			f(user+`\Documents\wallet seed.txt`, 98, "orbit cactus maple velvet throne nickel scan hazard mutual oyster fringe denial\n")),
		"brave": mk("brave", "Brave browser profile", "decoy",
			f(ld+`\BraveSoftware\Brave-Browser\User Data\Default\Login Data`, 40960, "")),
		"electrum": mk("electrum", "Electrum wallet", "decoy",
			f(rd+`\Electrum\wallets\default_wallet`, 3012, "")),
		"backup-codes": mk("backup-codes", "2FA backup codes (Documents)", "file",
			f(user+`\Documents\backup codes.txt`, 160, "Google backup codes\n4821 0937\n7710 2284\n5593 1046\n")),
		"opera": mk("opera", "Opera browser profile", "decoy",
			f(rd+`\Opera Software\Opera Stable\Login Data`, 40960, "")),
	}
}

func baseConfig() *config.Config {
	c := config.Default()
	c.InstalledAt = at("2026-10-02T09:10:00Z")
	c.User = config.UserInfo{Name: "sam", Profile: user}
	c.ClipboardBait, c.MinerTrap = true, true
	return c
}

func serviceHealth() []config.HealthItem {
	return []config.HealthItem{
		{Name: "Instant freeze armed", OK: true},
		{Name: "Backup watcher on", OK: true, Detail: "the event log, in case instant freeze misses one"},
		{Name: "Flight recorder", OK: true},
	}
}

func baseState() *config.State {
	st := config.NewState()
	st.Baits = plantedBaits(now.Add(-2 * time.Minute))
	st.Heartbeat = now.Add(-40 * time.Second)
	st.ServiceVersion = "v0.10.2"
	st.Health = serviceHealth()
	st.Update = &config.UpdateStatus{LastCheck: at("2026-11-27T08:00:00Z"), Latest: "v0.10.2", LastResult: "up to date"}
	return st
}

func source(st *config.State, list ...*alerts.Alert) *Source {
	return &Source{Version: "v0.10.2", Now: now, Config: baseConfig(), State: st, Alerts: list, ServiceRunning: true,
		PhoneVia: "ntfy", ClipboardSupported: true, MinersSupported: true, Updatable: true,
		Newer: func(cur, tag string) bool { return tag > cur }}
}

func unsigned() provenance.Result { return provenance.Result{} }

// ---- alerts ----

// quietTouch: a signed program read a bait; ABA only noted it.
func quietTouch(id string, t time.Time, exe, signer, bait, baitName, path string) *alerts.Alert {
	return &alerts.Alert{ID: id, Time: t, Kind: alerts.KindRead, Tier: config.TierInfo, Status: alerts.StatusNoted,
		Title:   exe + " read a bait (looks legitimate)",
		Summary: "signed by " + signer,
		Baits:   []alerts.BaitHit{{ID: bait, Name: baitName, Path: path, Access: "read", Time: t}},
		Process: &alerts.Process{PID: 7312, Image: `C:\Windows\System32\` + exe, Signature: provenance.Result{Signed: true, Valid: true, Signer: signer}},
		Verdict: classify.Verdict{Tier: config.TierInfo, Builtin: true, Reasons: []string{"signed by " + signer}}}
}

// nitroGen is the mockup's catch: an unsigned "free Nitro" tool from
// Downloads opened the Discord bait 1.8 s after reading the real Chrome
// cookies, and sent 4 KB to discord.com before the freeze.
func nitroGen(sent string) *alerts.Alert {
	bait := at("2026-11-27T14:02:07.000Z")
	start := at("2026-11-27T14:02:05.100Z")
	frozen := bait.Add(120 * time.Millisecond)
	exe := user + `\Downloads\NitroGen-Free.exe`
	a := &alerts.Alert{ID: "20261127-140207-7f3a", Time: frozen, Kind: alerts.KindRead, Tier: config.TierCritical, Status: "open",
		Title:     "Likely infostealer: NitroGen-Free.exe opened your bait",
		Summary:   "Caught the moment it opened the bait (instant freeze). unsigned program running from your Downloads folder",
		Instant:   true,
		LatencyMS: 120,
		Baits: []alerts.BaitHit{{ID: "discord", Name: "Discord token store", Access: "read", Time: bait,
			Path: user + `\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb`}},
		Process: &alerts.Process{PID: 9120, Image: exe, CommandLine: `"` + exe + `"`, Dir: user + `\Downloads`, User: `DESKTOP-4K2\sam`,
			SHA256:    "9f2c41d077ab03e5c1b6f28e4d9a0c73b5e18d2f6a4c90b7e3d1f5a8c2b6e41b",
			Signature: unsigned(),
			Parents:   []procinfo.Parent{{PID: 5124, Image: `C:\Windows\explorer.exe`}},
			TreePIDs:  []uint32{9120, 9188},
			Origin: &origin.Origin{File: exe, URL: "https://cdn.discordapp.com/attachments/1180000000000000000/1180000000000000001/NitroGen-Free.exe",
				Referrer: "https://discord.com/channels/@me"}},
		Verdict: classify.Verdict{Tier: config.TierCritical, Reasons: []string{"unsigned program running from your Downloads folder", "it opened a bait no program of its kind has any reason to read"}},
	}
	a.Actions = []alerts.ActionResult{
		{Action: config.ActionFreeze, OK: true, Detail: "2 process(es) frozen", Time: frozen},
		{Action: config.ActionBlockProgram, OK: true, Time: frozen.Add(30 * time.Millisecond)},
	}
	ap := &alerts.Autopsy{Started: frozen.Add(200 * time.Millisecond), Finished: frozen.Add(9 * time.Second),
		ProcessStart: start, BaitAt: bait, Answer: alerts.AnswerRead,
		Headline: "It had already opened your real Chrome cookies and saved passwords.",
		Summary: []string{
			"1.8 s before it opened the bait, it opened your real Chrome cookies (the flight recorder saw it).",
			"It packed them into a zip in your Temp folder, with the Discord bait.",
		},
		Steps: []string{
			"Kill NitroGen-Free.exe: it's still frozen. Killing it ends it for good and keeps the evidence.",
			"Sign out of every site in Chrome: stolen cookies let someone be you without a password. Signing out makes them useless.",
			"Change your Discord password, then log out all other sessions in Discord's settings.",
		},
		Reads: []alerts.StoreRead{
			{Store: "chrome", Name: "your Chrome", Kind: "browser", Path: user + `\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`,
				At: bait.Add(-1800 * time.Millisecond), PID: 9120, Image: exe, How: "the flight recorder saw it open it"},
			{Store: "chrome", Name: "your Chrome", Kind: "browser", Path: user + `\AppData\Local\Google\Chrome\User Data\Default\Login Data`,
				At: bait.Add(-1700 * time.Millisecond), PID: 9120, Image: exe, How: "the flight recorder saw it open it"},
		},
		Watched: []alerts.StoreWatch{
			{Store: "chrome", Name: "your Chrome", Kind: "browser", Watched: true, Since: at("2026-11-27T08:01:00Z")},
			{Store: "firefox", Name: "your Firefox", Kind: "browser", Absent: true},
			{Store: "telegram", Name: "Telegram Desktop", Watched: false, Why: "it was installed after the flight recorder started"},
		},
		OpenFiles: []alerts.FileSeen{{Path: user + `\AppData\Local\Temp\ng_7f3a.zip`, PID: 9120}},
		Staged: []alerts.Staged{{
			Path: user + `\AppData\Local\Temp\ng_7f3a.zip`, Size: 198656, Appeared: bait.Add(-900 * time.Millisecond), HeldOpen: true,
			Archive: "zip", What: "an archive of 4 files (1 baits, 2 copies of your real files)", Saved: `C:\ProgramData\FileAccessMonitor\evidence\20261127-140207-7f3a\ng_7f3a.zip`,
			Entries: []alerts.ArchiveEntry{
				{Name: "Chrome/Cookies", Size: 151552, What: "your Chrome's: the same bytes as your real file " + user + `\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`},
				{Name: "Chrome/Login Data", Size: 45056, What: "your Chrome's: the same bytes as your real file " + user + `\AppData\Local\Google\Chrome\User Data\Default\Login Data`},
				{Name: "Discord/000005.ldb", Size: 2148, What: "a bait (Discord token store): fake, nothing lost"},
				{Name: "info.txt", Size: 512},
			},
		}},
		StagedWhere: []string{user + `\AppData\Local\Temp`},
		Addresses: []alerts.Address{
			{Kind: "discord-webhook", Value: "https://discord.com/api/webhooks/1180000000000000000/EXAMPLE-not-real", Where: "memory"},
			{Kind: "url", Value: "http://ip-api.com/json", Where: "memory"},
		},
		MemoryScanned: 48 << 20,
		Evidence:      `C:\ProgramData\FileAccessMonitor\evidence\20261127-140207-7f3a`,
		MemoryImage:   true,
	}
	switch sent {
	case alerts.SentSome:
		ap.Sent = alerts.SentSome
		ap.Sends = []alerts.NetSend{
			{PID: 9120, Image: "NitroGen-Free.exe", To: "162.159.135.232:443", Name: "discord.com", First: bait.Add(-1100 * time.Millisecond),
				Last: bait.Add(-1000 * time.Millisecond), Bytes: 4198, Conns: 1, After: true, BytesAfter: 4198},
			{PID: 9120, Image: "NitroGen-Free.exe", To: "208.95.112.1:80", Name: "ip-api.com", First: start.Add(300 * time.Millisecond),
				Last: start.Add(400 * time.Millisecond), Bytes: 310, Conns: 1},
		}
		ap.Summary = append(ap.Summary, "It sent about 4 KB to discord.com 1.1 s before it opened the bait: assume they were taken.")
	case alerts.SentNothing:
		ap.Sent = alerts.SentNothing
		ap.Headline = "It opened your real Chrome cookies, but nothing left this PC."
		ap.Sends = []alerts.NetSend{{PID: 9120, Image: "NitroGen-Free.exe", To: "208.95.112.1:80", Name: "ip-api.com",
			First: start.Add(300 * time.Millisecond), Last: start.Add(400 * time.Millisecond), Bytes: 310, Conns: 1}}
		ap.Summary = append(ap.Summary, "It looked up where you are (ip-api.com) before it opened anything of yours, and sent nothing after.")
	case alerts.SentUnknown:
		ap.Sent = alerts.SentUnknown
		ap.SentWhy = []string{"The network record wasn't running when it started (the service had just restarted)."}
	}
	a.Autopsy = ap
	return a
}

// cannotTell: ABA couldn't see whether it took anything.
func cannotTell() *alerts.Alert {
	a := nitroGen(alerts.SentUnknown)
	a.ID = "20261126-221530-c41e"
	shift := a.Time.Sub(at("2026-11-26T22:15:30Z"))
	a.Time = a.Time.Add(-shift)
	a.Process.Image = user + `\AppData\Local\Temp\7zS4A21\Setup.exe`
	a.Process.Origin = nil
	a.Process.Parents = []procinfo.Parent{{PID: 6640, Exited: true}}
	a.Title = "Likely infostealer: Setup.exe opened your bait"
	a.Baits[0].Time = a.Baits[0].Time.Add(-shift)
	for i := range a.Actions {
		a.Actions[i].Time = a.Actions[i].Time.Add(-shift)
	}
	ap := a.Autopsy
	ap.Started, ap.Finished, ap.BaitAt, ap.ProcessStart = ap.Started.Add(-shift), ap.Finished.Add(-shift), ap.BaitAt.Add(-shift), time.Time{}
	ap.Answer = alerts.AnswerUnknown
	ap.Headline = "ABA can't tell whether it took anything of yours."
	ap.Summary = []string{"It started before ABA did, so the flight recorder didn't see its first seconds."}
	ap.Unsure = []string{"It had been running for 3 minutes before ABA's service started.", "Your Telegram data wasn't watched (installed after the flight recorder started)."}
	ap.Steps = []string{"Kill Setup.exe.", "To be safe, change your important passwords from another device, email first."}
	ap.Reads, ap.Staged, ap.OpenFiles, ap.Addresses = nil, nil, nil, nil
	ap.Leads = []string{"A folder of its own code appeared in your Temp folder while it ran."}
	ap.Unpacked = []alerts.Unpacked{{Dir: user + `\AppData\Local\Temp\_MEI66402`, Files: 212, Size: 31 << 20}}
	ap.Evidence, ap.MemoryImage = "", false
	ap.Notes = []string{"Its memory couldn't be copied: it's a 32-bit program and the copy failed (access denied)."}
	return a
}

func miner() *alerts.Alert {
	t := at("2026-11-19T03:12:44Z")
	exe := user + `\AppData\Roaming\Microsoft\svc-update.exe`
	a := &alerts.Alert{ID: "20261119-031244-0b9d", Time: t, Kind: alerts.KindMiner, Tier: config.TierCritical, Status: "resolved", Note: "killed",
		Title:   "Hidden miner: svc-update.exe tried to mine on this PC",
		Summary: "it logged in to mine at a mining pool (gulf.moneroocean.stream), which the miner trap answers",
		Baits:   []alerts.BaitHit{{ID: "miner", Name: "the miner trap", Access: "mine", Time: t, Path: "gulf.moneroocean.stream:10128"}},
		Process: &alerts.Process{PID: 4411, Image: exe, CommandLine: exe + ` --donate-level 0 -o gulf.moneroocean.stream:10128 --cpu-max-threads-hint 50`,
			Signature: unsigned(), SHA256: "3be1d7a0c2f94e8a6b51d03f7c9e2a48b6d1f0e39c75a28d4e6b9f1c0a3d5e72",
			Parents:   []procinfo.Parent{{PID: 1880, Image: `C:\Windows\System32\svchost.exe`}}},
		Mine: &alerts.Mine{Pool: "gulf.moneroocean.stream:10128", Wallet: "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A", Agent: "XMRig/6.21.0 (Windows NT 10.0; Win64; x64)"},
		Verdict: classify.Verdict{Tier: config.TierCritical, Reasons: []string{"it tried to mine cryptocurrency on this PC"}},
	}
	a.Actions = []alerts.ActionResult{
		{Action: config.ActionFreeze, OK: true, Detail: "1 process(es) frozen", Time: t},
		{Action: config.ActionBlockProgram, OK: true, Time: t},
		{Action: config.ActionKill, OK: true, Detail: "by you", Time: t.Add(3 * time.Minute)},
	}
	return a
}

func clipper() *alerts.Alert {
	t := at("2026-11-11T16:40:02Z")
	exe := user + `\AppData\Local\clipfix\clipfix.exe`
	a := &alerts.Alert{ID: "20261111-164002-5e21", Time: t, Kind: alerts.KindClipper, Tier: config.TierCritical, Status: "resolved", Note: "killed",
		Title:   "Clipper: clipfix.exe swapped a wallet address on your clipboard",
		Summary: "it replaced the bait Bitcoin address ABA put on the clipboard with its own",
		Baits:   []alerts.BaitHit{{ID: "clipboard", Name: "the clipboard bait", Access: "swap", Time: t}},
		Process: &alerts.Process{PID: 3388, Image: exe, Signature: unsigned(), SHA256: "c0ffee5a1e9b2d7f48a3e61b90d5c27f3e8a14b6d02c9f75e1a3b8d4c6f20e19"},
		Verdict: classify.Verdict{Tier: config.TierCritical, Reasons: []string{"it swapped a wallet address on the clipboard"}},
	}
	a.Actions = []alerts.ActionResult{
		{Action: config.ActionFreeze, OK: true, Detail: "1 process(es) frozen", Time: t},
		{Action: config.ActionKill, OK: true, Detail: "by you", Time: t.Add(40 * time.Second)},
	}
	a.Autopsy = &alerts.Autopsy{Started: t.Add(time.Second), Finished: t.Add(6 * time.Second), BaitAt: t, Answer: alerts.AnswerNoSign,
		Headline:       "No sign it read anything of yours.",
		Steps:          []string{"Don't send crypto from this PC until it's cleaned."},
		AttackerWallet: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", MemoryScanned: 12 << 20}
	return a
}

func trusted() *alerts.Alert {
	t := at("2026-11-06T11:20:31Z")
	a := &alerts.Alert{ID: "20261106-112031-91aa", Time: t, Kind: alerts.KindRead, Tier: config.TierWarn, Status: "resolved", Note: "you trusted this program",
		Title:   "Reflect.exe read a bait",
		Summary: "signed program running from an unusual place",
		Baits: []alerts.BaitHit{{ID: "seed-phrase", Name: "wallet recovery phrase (Documents)", Access: "read", Time: t,
			Path: user + `\Documents\wallet seed.txt`}},
		Process: &alerts.Process{PID: 6012, Image: `C:\Program Files\Macrium\Reflect\Reflect.exe`,
			Signature: provenance.Result{Signed: true, Valid: true, Signer: "Paramount Software UK Ltd"}},
		Verdict: classify.Verdict{Tier: config.TierWarn, Reasons: []string{"signed by Paramount Software UK Ltd, but it read a bait"}},
	}
	return a
}

func oldStealer() *alerts.Alert {
	t := at("2026-10-29T19:55:10Z")
	exe := user + `\Downloads\setup_crack.exe`
	a := &alerts.Alert{ID: "20261029-195510-aa07", Time: t, Kind: alerts.KindRead, Tier: config.TierCritical, Status: "resolved", Note: "killed",
		Title:   "Likely infostealer: setup_crack.exe opened your bait",
		Summary: "unsigned program running from your Downloads folder",
		Baits:   []alerts.BaitHit{{ID: "metamask", Name: "MetaMask wallet (inside a fake browser)", Access: "read", Time: t}},
		Process: &alerts.Process{PID: 2210, Image: exe, Signature: unsigned()},
		Verdict: classify.Verdict{Tier: config.TierCritical, Reasons: []string{"unsigned program running from your Downloads folder"}},
		Actions: []alerts.ActionResult{
			{Action: config.ActionFreeze, OK: true, Detail: "1 process(es) frozen", Time: t},
			{Action: config.ActionBlockProgram, OK: true, Time: t},
			{Action: config.ActionKill, OK: true, Detail: "by you", Time: t.Add(time.Minute)},
		},
	}
	return a
}

// hostile is a catch whose every attacker-chosen string tries to be HTML,
// or hides characters: the page must show all of it as text.
func hostile() *alerts.Alert {
	a := nitroGen(alerts.SentSome)
	a.ID = "20261127-135900-dead"
	a.Process.Image = user + `\Downloads\<img src=x onerror=alert(1)>.exe`
	a.Process.CommandLine = `"<script>alert('cmd')</script>" --x="</textarea><svg onload=alert(2)>"`
	a.Title = "Likely infostealer: <img src=x onerror=alert(1)>.exe opened your bait"
	a.Process.Origin.URL = `javascript:alert(3)//https://example.com/"><b>bold</b>`
	ap := a.Autopsy
	ap.Addresses = []alerts.Address{
		{Kind: "discord-webhook", Value: `https://discord.com/api/webhooks/1/"><img src=x onerror=alert(4)>`, Where: "memory+file"},
		{Kind: "telegram-bot", Value: `bot123456:AA<script>alert(5)</script>`, Where: "file"},
	}
	ap.Staged[0].Path = user + "\\AppData\\Local\\Temp\\\u200b\u202e\\loot<b>.zip"
	ap.Staged[0].Entries = append(ap.Staged[0].Entries, alerts.ArchiveEntry{Name: "<iframe src=javascript:alert(6)>.txt", Size: 10, What: "named like a bait (<u>x</u>)"})
	ap.Headline = "It had already opened <b>your</b> real Chrome cookies."
	return a
}

func testCatch() *alerts.Alert {
	t := at("2026-11-20T10:00:03Z")
	return &alerts.Alert{ID: "20261120-100003-77c2", Time: t, Kind: alerts.KindRead, Tier: config.TierCritical, Status: "resolved", Test: true,
		Note:    "test",
		Title:   "Test detection: aba-test-8812.exe read a bait",
		Summary: "unsigned program running from your Temp folder",
		Baits:   []alerts.BaitHit{{ID: "desktop-passwords", Name: "password list on the Desktop", Access: "read", Time: t, Path: user + `\Desktop\passwords.txt`}},
		Process: &alerts.Process{PID: 8812, Image: user + `\AppData\Local\Temp\aba-test-8812.exe`, Signature: unsigned()},
		Verdict: classify.Verdict{Tier: config.TierCritical, Reasons: []string{"unsigned program running from your Temp folder"}},
		Actions: []alerts.ActionResult{{Action: config.ActionFreeze, OK: true, Detail: "1 process(es) frozen", Time: t}},
	}
}

func quietOnes() []*alerts.Alert {
	return []*alerts.Alert{
		quietTouch("20261125-091502-1a2b", at("2026-11-25T09:15:02Z"), "SearchProtocolHost.exe", "Microsoft Windows", "desktop-passwords", "password list on the Desktop", user+`\Desktop\passwords.txt`),
		quietTouch("20261122-201144-3c4d", at("2026-11-22T20:11:44Z"), "MsMpEng.exe", "Microsoft Windows Publisher", "seed-phrase", "wallet recovery phrase (Documents)", user+`\Documents\wallet seed.txt`),
	}
}

// ---- the scenarios ----

// protectedSource: all quiet, the last catch 8 days ago.
func protectedSource() *Source {
	list := append(quietOnes(), miner(), clipper(), trusted(), oldStealer())
	return source(baseState(), list...)
}

// frozenSource: NitroGen-Free.exe frozen right now, with everything before.
func frozenSource(sent string) (*Source, *alerts.Alert) {
	a := nitroGen(sent)
	st := baseState()
	st.Frozen = []config.FrozenProcess{
		{PID: 9120, Image: a.Process.Image, AlertID: a.ID, Since: a.Time},
		{PID: 9188, Image: a.Process.Image, AlertID: a.ID, Since: a.Time},
	}
	st.Blocked = []config.BlockedProgram{{Path: a.Process.Image, AlertID: a.ID, Since: a.Time}}
	list := append([]*alerts.Alert{a}, quietOnes()...)
	list = append(list, testCatch(), miner(), clipper(), trusted(), oldStealer())
	return source(st, list...), a
}
