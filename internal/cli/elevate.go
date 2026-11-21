package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"

	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

// Most commands need administrator rights (see requireAdmin, which is up to
// the operating system: elevate_<os>.go).

// pauseFlag is added when we relaunch ourselves elevated, so the new console
// window stays open long enough to read the result.
const pauseFlag = "--elevated-pause"

var errRelaunched = errors.New("continued in the administrator window")

func pause() {
	fmt.Print("\n " + ui.Fainter.Render("Press Enter to close this window…"))
	bufio.NewReader(os.Stdin).ReadString('\n')
}
