//go:build !windows

// Modified 2026-10-23 for the VulScan-only product namespace.
package python

import (
	"os"
	"syscall"
)

// lockFileExcl takes an exclusive advisory lock (flock). Blocks until
// acquired — the JS bootstrap's block-until-acquired semantics.
func lockFileExcl(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// unlockFile releases the advisory lock.
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
