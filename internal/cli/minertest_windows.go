package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/engine"
	"github.com/vulnix0x4/a-better-antivirus/internal/minertrap"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

// testWallet is what the fake miner says it mines for: plainly not a wallet.
const testWallet = "ABA-TEST-not-a-real-wallet"

func minerCmds() []*cobra.Command {
	return []*cobra.Command{{
		// The fake miner of `aba miners test`.
		Use:    "test-miner",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fakeMiner(2 * time.Minute)
		},
	}}
}

// trapLookup looks up the test pool's name the way any program does, and
// says whether it leads to the trap (and where it leads otherwise).
func trapLookup(wait time.Duration) (bool, string) {
	deadline := time.Now().Add(wait)
	last := ""
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", minertrap.TestPool)
		cancel()
		switch {
		case err != nil:
			last = err.Error()
		case len(ips) == 1 && ips[0].Unmap() == minertrap.AddrIP:
			return true, ""
		default:
			var s []string
			for _, ip := range ips {
				s = append(s, ip.Unmap().String())
			}
			last = "it leads to " + strings.Join(s, ", ")
		}
		if time.Now().After(deadline) {
			return false, last
		}
		time.Sleep(time.Second)
	}
}

// fakeMiner logs in at the trap, the way XMRig does, and waits. It connects
// only if the pool's name led to the trap: never to a real pool.
func fakeMiner(stay time.Duration) error {
	if ok, why := trapLookup(10 * time.Second); !ok {
		return fmt.Errorf("%s doesn't lead to the trap (%s): not connecting", minertrap.TestPool, why)
	}
	c, err := net.DialTimeout("tcp4", netip.AddrPortFrom(minertrap.AddrIP, minertrap.TestPort).String(), 10*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	login, _ := json.Marshal(map[string]any{"id": 1, "jsonrpc": "2.0", "method": "login", "params": map[string]any{
		"login": testWallet, "pass": "x", "agent": "ABA test miner (harmless)", "algo": []string{"rx/0"}}})
	if _, err := c.Write(append(login, '\n')); err != nil {
		return err
	}
	c.SetReadDeadline(time.Now().Add(stay))
	c.Read(make([]byte, 1))
	return nil
}

// runMinerTest is `aba miners test`: a harmless fake miner, caught the way a
// real one would be.
func runMinerTest() error {
	if s, _ := svcctl.Status(); s != svcctl.Running {
		return exitf("the service isn't running (%s); try `aba doctor --fix`", s)
	}
	cfg, err := mustConfig()
	if err != nil {
		return err
	}
	if !cfg.MinerTrap {
		return exitf("the miner trap is off: switch it on with `aba miners on`")
	}
	fmt.Println()
	fmt.Println(ui.Banner("safe test"))
	fmt.Println()
	fmt.Println(" " + ui.Plain.Render("A harmless fake miner in your Temp folder is about to look up a real mining pool,"))
	fmt.Println(" " + ui.Plain.Render(minertrap.TestPool+", and log in to mine there. The trap sends it to ABA's fake pool."))
	fmt.Println()
	if ok, why := trapLookup(20 * time.Second); !ok {
		fmt.Println(" " + ui.Bad.Bold(true).Render(ui.IconBad) + " " + ui.Plain.Render(minertrap.TestPool+" doesn't lead to the trap: "+why+"."))
		fmt.Println("   " + ui.Dim.Render("The fake miner wasn't started. `aba doctor` says what's wrong; the log says more: "+paths.LogFile()))
		return exitf("test failed")
	}
	self, _ := os.Executable()
	b, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	miner, err := startTestCopy(b, "test-miner")
	if err != nil {
		return err
	}
	defer func() {
		miner.Close()
		for i := 0; i < 20; i++ {
			if _, err := os.Stat(miner.Path); err != nil || os.Remove(miner.Path) == nil {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()
	pid := miner.PID
	tr, _ := json.Marshal(engine.TestRequest{PID: pid, Nonce: strconv.Itoa(int(pid)), Since: time.Now(), Miner: true})
	if err := os.WriteFile(paths.TestFile(), tr, 0o644); err != nil {
		return err
	}
	fmt.Println(" " + ui.Good.Render(ui.IconArr) + ui.Dim.Render(" Fake miner started…"))
	start := time.Now()
	var found *alerts.Alert
	for time.Since(start) < 40*time.Second && found == nil {
		time.Sleep(200 * time.Millisecond)
		list, _ := alerts.List(5)
		for _, a := range list {
			if a.Test && a.Process != nil && a.Process.PID == pid {
				found = a
			}
		}
	}
	miner.Close()
	fmt.Println()
	if found == nil {
		os.Remove(paths.TestFile())
		fmt.Println(" " + ui.Bad.Bold(true).Render(ui.IconBad) + " " + ui.Plain.Render("ABA didn't catch it within 40 seconds."))
		fmt.Println("   " + ui.Dim.Render("The log says what happened: "+paths.LogFile()))
		return exitf("test failed")
	}
	rows := [][2]string{{"Caught", ui.TierWord(found.Tier) + ui.Dim.Render(": it logged in to mine at the fake pool")}}
	if found.Did(config.ActionFreeze) {
		rows = append(rows, [2]string{"Frozen", ui.Good.Bold(true).Render(fmt.Sprintf("%d ms", found.LatencyMS)) + ui.Dim.Render(" after it logged in")})
	}
	rows = append(rows, [2]string{"Cleaned up", ui.Dim.Render("the fake miner was killed and deleted; nothing left this " + "PC")})
	for _, r := range rows {
		fmt.Printf(" %s %s %s\n", ui.Good.Bold(true).Render(ui.IconOK), ui.Plain.Render(fmt.Sprintf("%-11s", r[0])), r[1])
	}
	fmt.Println("\n " + ui.Plain.Render("That's what happens to a real one.") + ui.Dim.Render(" Everything ABA saw: ") +
		ui.Code.Render("aba alerts show "+found.ID[strings.LastIndex(found.ID, "-")+1:]))
	return nil
}
