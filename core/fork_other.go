//go:build !linux

package core

// wipeOnFork has no equivalent off Linux.
func wipeOnFork(_ []byte) {}
