package cli

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/session"
)

// windowCheckCmds: `aba window-check <pid>...`, which the service runs in
// the person's session (as SYSTEM, see session.StartSystem) to find out
// whether a browser that went through a fake profile has a window they can
// see: a service can't see the windows of another session. It prints one
// JSON line: {"visible": true, "windows": 2}, or {"error": "..."}.
func windowCheckCmds() []*cobra.Command {
	return []*cobra.Command{{
		Use:    "window-check <pid>...",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var pids []uint32
			for _, a := range args {
				if p, err := strconv.ParseUint(a, 10, 32); err == nil {
					pids = append(pids, uint32(p))
				}
			}
			out := map[string]any{}
			n, err := session.VisibleWindows(pids)
			if err != nil {
				out["error"] = err.Error()
			} else {
				out["visible"], out["windows"] = n > 0, n
			}
			return json.NewEncoder(os.Stdout).Encode(out)
		},
	}}
}
