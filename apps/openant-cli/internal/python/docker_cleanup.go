package python

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const dockerOwnerEnv = "OPENANT_DOCKER_OWNER"
const dockerLeaseEnv = "OPENANT_DOCKER_LEASE_FD"
const dockerRegistryEnv = "OPENANT_DOCKER_REGISTRY_DIR"
const dockerCleanupTimeout = 30 * time.Second

// dockerInvocation is private to one child, including when several web jobs run
// concurrently. Never trust an inherited/caller-supplied owner for deletion.
type dockerInvocation struct {
	owner         string
	registry      string
	lease         *os.File
	cleanupLocked bool
}

func newDockerInvocation() (*dockerInvocation, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, fmt.Errorf("Docker cleanup ownership: %w", err)
	}
	owner := hex.EncodeToString(token[:])
	registry, lease, err := newDockerRegistry(owner)
	if err != nil {
		return nil, fmt.Errorf("Docker cleanup registry: %w", err)
	}
	return &dockerInvocation{owner: owner, registry: registry, lease: lease}, nil
}

func (d *dockerInvocation) environment(base []string) []string {
	return mergeEnv(base, map[string]string{dockerOwnerEnv: d.owner, dockerRegistryEnv: d.registry, dockerLeaseEnv: ""})
}

// cleanup runs AFTER Wait, including SIGKILL/timeout paths that bypass Python's
// finally blocks. It has its own budget, not the cancelled scan context. Python
// writes the registry BEFORE creating resources; no registry means no Docker
// work and avoids loading the cleanup helper on ordinary parse/analyze calls.
// Failed cleanup leaves the registry for diagnosis/recovery; never recursively
// remove a directory containing resources the helper could not reclaim.
func (d *dockerInvocation) cleanup(pythonPath, workDir string, env []string, onLog func(string)) {
	d.cleanupWithTimeout(pythonPath, workDir, env, onLog, dockerCleanupTimeout)
}

func (d *dockerInvocation) cleanupWithTimeout(pythonPath, workDir string, env []string, onLog func(string), timeout time.Duration) {
	if d.lease != nil {
		defer func() {
			if d.lease != nil {
				_ = d.lease.Close()
			}
		}()
	}
	emptyBeforeLock, inspectErr := d.emptyRegistry()
	if os.IsNotExist(inspectErr) {
		return
	}
	if err := d.lockForCleanup(!emptyBeforeLock); err != nil {
		// A detached non-Docker pipe holder must not add warnings to a
		// successful scan. Keep its empty leased state silently for recovery.
		if !emptyBeforeLock && !os.IsNotExist(err) && onLog != nil {
			onLog("[openant] 工作进程或清理进程仍持有租约，已延后清理本次扫描的 Docker 资源；保留恢复记录：" + d.registry)
		}
		return
	}
	empty, err := d.emptyRegistry()
	if err == nil && empty {
		_ = d.removeEmptyRegistry()
		return
	}
	if os.IsNotExist(err) {
		return
	}
	warn := func() {
		if onLog != nil {
			onLog("[openant] 本次扫描的 Docker 资源未完全清理；保留恢复记录：" + d.registry)
		}
	}
	if err != nil {
		warn()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, pythonPath, "-P", "-m", "utilities.docker_resources", "cleanup", "--owner", d.owner)
	cmd.Dir = workDir
	cmd.Env = d.environment(env)
	cmd.Stdout = io.Discard
	// The helper reports failure by exit status. Do not let untrusted Docker
	// diagnostics flood logs or accidentally expose environment credentials.
	cmd.Stderr = io.Discard
	setProcGroupKill(cmd)
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		warn()
		return
	}
	// Only the helper may remove registered work dirs. Remove the registry root
	// only if it is now empty; leftover records must remain available for retry.
	if err := d.removeEmptyRegistry(); err != nil && !os.IsNotExist(err) {
		warn()
	}
}

func (d *dockerInvocation) emptyRegistry() (bool, error) {
	entries, err := os.ReadDir(d.registry)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Name() != ".backend" && (entry.Name() != ".lease" || d.lease == nil) {
			return false, nil
		}
	}
	return true, nil
}
func (d *dockerInvocation) removeEmptyRegistry() error {
	empty, err := d.emptyRegistry()
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("recovery records remain")
	}
	if err := os.Remove(filepath.Join(d.registry, ".backend")); err != nil && !os.IsNotExist(err) {
		return err
	}
	if d.lease != nil {
		if err := os.Remove(filepath.Join(d.registry, ".lease")); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return os.Remove(d.registry)
}
