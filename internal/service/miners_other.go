//go:build !windows

package service

// The miner trap (package minertrap) is Windows only for now.

func (s *server) minerTrap(on bool) {}

func (s *server) minerTrapStop() {}

func (s *server) minerHealth(add func(name string, ok bool, detail string)) {}
