// Modified 2026-10-23 for 911VulScan product branding; new-only namespace.
package cmd

import (
	"os"

	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/output"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff [repository-path]",
	Short: "Scan only the code changed vs a base ref, GitHub PR, or the staged index",
	Long: `Diff runs the full scan pipeline but filters to units whose bodies
overlap a git diff hunk. One of --diff-base, --pr, or --staged is required.

Examples:
  vulscan diff --diff-base origin/main
  vulscan diff --pr 123
  vulscan diff --staged                       # pre-commit hook usage
  vulscan diff --diff-base HEAD~5 --diff-scope callers --verify

All scan flags (--level, --workers, --verify, etc.) work the same here.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if scanDiffBase == "" && scanPR == 0 && !scanStaged {
			output.PrintError("vulscan diff requires --diff-base <ref>, --pr <N>, or --staged")
			os.Exit(2)
		}
		runScan(cmd, args)
	},
}

func init() {
	registerScanFlags(diffCmd)
}
