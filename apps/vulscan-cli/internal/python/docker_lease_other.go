//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

// Modified 2026-10-23 for the VulScan-only product namespace.
package python

import (
	"os"
	"os/exec"
)

// Platforms without flock retain ordinary post-exit cleanup, but never guess
// whether a previous scan is dead. Stale recovery there is explicitly manual.
func newDockerRegistry(owner string) (string, *os.File, error) {
	registry, err := os.MkdirTemp("", "vulscan-docker-"+owner+"-")
	return registry, nil, err
}
func (d *dockerInvocation) attachLease(cmd *exec.Cmd) {}
func (d *dockerInvocation) recoverStale(pythonPath, workDir string, env []string, onLog func(string)) {
}

func (d *dockerInvocation) lockForCleanup(wait bool) error { return nil }
