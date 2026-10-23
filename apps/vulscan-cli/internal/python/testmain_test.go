// Modified 2026-10-23 for the VulScan-only product namespace.
package python

import (
	"fmt"
	"os"
	"testing"
)

// Invocation tests must never inspect/recover the developer's real registries.
func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "vulscan-go-test-state-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = os.Setenv("VULSCAN_DOCKER_STATE_DIR", root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(root)
	os.Exit(code)
}
