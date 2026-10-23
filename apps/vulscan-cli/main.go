// Modified 2026-10-23 for the VulScan-only product namespace.
// VulScan CLI - LLM-powered static analysis security testing.
//
// This binary wraps the Python `vulscan` package, providing a native CLI
// experience with colored output, progress streaming, and JSON mode.
package main

import "github.com/puhaoyang78/911VulScan/apps/vulscan-cli/cmd"

func main() {
	cmd.Execute()
}
