package service

// The clipboard bait (package clipbait) is Windows only for now.

func (s *server) clipboardBait(on bool) {}

func (s *server) clipboardBaitNow() {}

func (s *server) freeClipboard(frozen []uint32) {}
