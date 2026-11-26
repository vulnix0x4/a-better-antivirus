//go:build preview

package engine

import (
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
)

// MineVerdictForPreview is a miner's verdict, for the screen previews.
func MineVerdictForPreview(m *detect.Mine, image string) classify.Verdict {
	return mineVerdict(m, image, true)
}
