package clipbait

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FreeFromFrozen makes sure none of frozen (processes ABA has frozen) owns
// the clipboard of this session. While a frozen program owns it, everyone
// who copies anything waits about five seconds for its window to answer, on
// every copy, for as long as it stays frozen.
//
// If one does, this takes the clipboard over. What's on it goes back as it
// was, unless it looks like a wallet address: then it's wiped, because a
// frozen program is most likely malware, and an address it left behind is
// most likely the attacker's. It says what it did ("" if nothing).
//
// One thing it can't fix: a program frozen while it had the clipboard open
// keeps it open, and nobody can copy until it's let go or killed.
func FreeFromFrozen(frozen []uint32) (string, error) { return freeFromFrozen(frozen, nil) }

func freeFromFrozen(frozen []uint32, onThread func() error) (did string, err error) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if onThread != nil {
			if err = onThread(); err != nil {
				return
			}
		}
		did, err = freeOnThisThread(frozen)
	}()
	<-done
	return did, err
}

func freeOnThisThread(frozen []uint32) (string, error) {
	isFrozen := map[uint32]bool{}
	for _, p := range frozen {
		isFrozen[p] = true
	}
	h, _, _ := pGetClipboardOwner.Call()
	owner := hwndPid(h)
	if owner == 0 || !isFrozen[owner] {
		return "", nil
	}
	hwnd := makeWindow()
	if hwnd == 0 {
		return "", errors.New("clipbait: could not create a window")
	}
	defer pDestroyWindow.Call(hwnd)
	if !openClip(hwnd) {
		return "", fmt.Errorf("pid %d owns the clipboard, and it couldn't be opened (frozen while it had it open?)", owner)
	}
	defer closeClip()
	// Only text that's already there: asking a frozen owner to hand over
	// what it only promised would wait for it as well.
	text := ""
	if has, _, _ := user32.NewProc("IsClipboardFormatAvailable").Call(cfUnicodeText); has != 0 {
		text = readText()
	}
	pEmptyClipboard.Call() // the frozen owner is told, and doesn't answer: the last wait
	if text == "" || Looks(text) {
		if text != "" {
			return fmt.Sprintf("took the clipboard from frozen pid %d and wiped the wallet address it held (%s)", owner, text), nil
		}
		return fmt.Sprintf("took the clipboard from frozen pid %d (it held no text)", owner), nil
	}
	u, _ := windows.UTF16FromString(text)
	setFormat(cfUnicodeText, unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2))
	// The window goes away with this program; the text stays.
	return fmt.Sprintf("took the clipboard from frozen pid %d, keeping its text", owner), nil
}
