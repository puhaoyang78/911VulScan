// Modified 2026-10-23 for the VulScan-only product namespace.
package cmd

import (
	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/python"
)

// ensurePython detects the Python runtime and validates that vulscan is installed.
// If needed, creates a managed venv at ~/.vulscan/venv/ and installs the package.
func ensurePython() (*python.RuntimeInfo, error) {
	return python.EnsureRuntime()
}
