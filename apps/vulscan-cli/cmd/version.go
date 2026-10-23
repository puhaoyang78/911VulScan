// Modified 2026-10-23 for the VulScan-only product namespace.
package cmd

import (
	"runtime"

	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/output"
	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/python"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run:   runVersion,
}

func runVersion(cmd *cobra.Command, args []string) {
	pythonVersion := ""
	rt, err := python.DetectRuntime()
	if err == nil {
		pythonVersion = rt.Version
	}

	output.PrintVersion(version, runtime.Version(), pythonVersion)
}
