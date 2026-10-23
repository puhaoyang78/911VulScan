//go:build !unix

// Modified 2026-10-23 for the VulScan-only product namespace.
package python

import "os/exec"

// setProcGroupKill is a no-op on non-unix platforms: there is no portable
// process-group SIGKILL, so exec.CommandContext's default behaviour (kill the
// top process on cancel) applies. cmd.WaitDelay (set by the caller) still bounds
// a lingering pipe holder.
func setProcGroupKill(cmd *exec.Cmd) {}
