package doctor

// Linux isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a Linux backend has to provide.

import (
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
)

// checkDetection checks whatever the operating system needs switched on for
// bait opens to be noticed at all, and reports with add. Without admin rights
// it goes by what the service last recorded in st.Health.
func checkDetection(admin bool, st *config.State, add func(l Level, name, detail, fix string)) {
	add(Problem, "Watching baits", platform.ErrUnsupported.Error(), "")
}

// fixDetection puts right what checkDetection looks at, and says what it did.
func fixDetection() []string { return nil }

// syncTools are sync and backup programs (process name, lowercase -> product):
// software that legitimately reads the files in your folders.
var syncTools = map[string]string{}
