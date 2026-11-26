package netrec

import (
	"context"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
)

// Watch would keep r from this system's own record of network sends. There
// isn't one yet here: the autopsy says it can't tell whether anything left.
func Watch(ctx context.Context, r *Record, logf func(string, ...any)) error {
	r.Stopped(time.Now(), "ABA doesn't keep one on "+platform.OSName()+" yet")
	return platform.Unsupported("keeping a record of what programs send over the network")
}
