package minertrap

import (
	"encoding/json"
	"strings"
)

// Stratum is how miners talk to pools: one JSON-RPC message per line, over a
// plain or TLS connection. A miner's first message logs in, and names the
// wallet it mines for. There are three dialects:
//
//   - Monero's (XMRig and its copies): {"method":"login","params":{"login":
//     "<wallet>","pass":"x","agent":"XMRig/6.24.0 ...","algo":["rx/0"]}}
//   - Bitcoin's "stratum v1", used for most other coins: "mining.subscribe"
//     (with the miner's name), then "mining.authorize" ["<wallet.worker>","x"]
//   - Ethereum's proxy dialect: "eth_submitLogin" ["<wallet>","x"]
//
// Any of them is a program trying to mine. Nothing else that reaches a
// pool's name speaks it (a browser opening the pool's website speaks HTTP).

// MaxLine is the longest message the fake pool reads. A login is a few
// hundred bytes; anything this long is not a miner.
const MaxLine = 16 << 10

// Login is what a miner sent to log in.
type Login struct {
	Method string   // "login", "mining.subscribe", "mining.authorize", "eth_submitLogin", ...
	Wallet string   // the wallet (or account) it mines for; "" if it didn't say yet
	Pass   string   // the "password": usually x, or a worker or campaign name
	Agent  string   // the miner's name and version, as it gives them
	Algo   []string // algorithms it offered
	Rig    string   // the rig ID it gave
}

// IsStratum reports whether method is one only a miner sends.
func IsStratum(method string) bool {
	switch {
	case method == "login", method == "eth_submitLogin", method == "eth_login", method == "submitLogin":
		return true
	case strings.HasPrefix(method, "mining."):
		return true
	}
	return false
}

type rpc struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Worker string          `json:"worker"`
}

// ParseMessage reads one Stratum message. ok is false when line isn't one
// (not JSON, not an object, no method only a miner sends).
func ParseMessage(line []byte) (l Login, id json.RawMessage, ok bool) {
	if len(line) > MaxLine {
		return l, nil, false
	}
	var m rpc
	if err := json.Unmarshal(line, &m); err != nil || !IsStratum(m.Method) {
		return l, nil, false
	}
	l.Method = m.Method
	switch m.Method {
	case "login":
		var p struct {
			Login string   `json:"login"`
			Pass  string   `json:"pass"`
			Agent string   `json:"agent"`
			Algo  []string `json:"algo"`
			Rig   string   `json:"rigid"`
		}
		if json.Unmarshal(m.Params, &p) == nil {
			l.Wallet, l.Pass, l.Agent, l.Algo, l.Rig = p.Login, p.Pass, p.Agent, p.Algo, p.Rig
		}
	case "mining.subscribe", "mining.hello":
		if args := stringArgs(m.Params); len(args) > 0 {
			l.Agent = args[0]
		}
		var h struct {
			Agent string `json:"agent"`
		}
		if json.Unmarshal(m.Params, &h) == nil && h.Agent != "" {
			l.Agent = h.Agent
		}
	case "mining.authorize", "eth_submitLogin", "eth_login", "submitLogin":
		args := stringArgs(m.Params)
		if len(args) > 0 {
			l.Wallet = args[0]
		}
		if len(args) > 1 {
			l.Pass = args[1]
		}
		if m.Worker != "" {
			l.Rig = m.Worker
		}
	}
	l.Wallet = clean(l.Wallet, 200)
	l.Pass = clean(l.Pass, 200)
	l.Agent = clean(l.Agent, 300)
	l.Rig = clean(l.Rig, 100)
	if len(l.Algo) > 16 {
		l.Algo = l.Algo[:16]
	}
	for i := range l.Algo {
		l.Algo[i] = clean(l.Algo[i], 40)
	}
	return l, m.ID, true
}

// stringArgs is a JSON array's leading strings.
func stringArgs(raw json.RawMessage) []string {
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil {
		return nil
	}
	var out []string
	for _, a := range arr {
		var s string
		if json.Unmarshal(a, &s) != nil {
			break
		}
		out = append(out, s)
	}
	return out
}

// clean makes what a miner sent safe to show: printable, on one line, cut to max.
func clean(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			continue // control characters, and the ones that reorder text on screen
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Merge adds what a later message said to what's known.
func (l *Login) Merge(m Login) {
	if l.Method == "" || (m.Wallet != "" && l.Wallet == "") {
		l.Method = m.Method
	}
	if l.Wallet == "" {
		l.Wallet = m.Wallet
	}
	if l.Pass == "" {
		l.Pass = m.Pass
	}
	if l.Agent == "" {
		l.Agent = m.Agent
	}
	if len(l.Algo) == 0 {
		l.Algo = m.Algo
	}
	if l.Rig == "" {
		l.Rig = m.Rig
	}
}

// subscribeReply answers mining.subscribe so the miner goes on to authorize,
// which names its wallet.
func subscribeReply(id json.RawMessage) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return []byte(`{"id":` + string(id) + `,"result":[[["mining.notify","ab0a0a0a0a0a0a0a"]],"0a0a0a0a",4],"error":null}` + "\n")
}
