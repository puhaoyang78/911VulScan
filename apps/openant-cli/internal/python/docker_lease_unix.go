//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package python

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

var dockerOwnerPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func privateOwned(info os.FileInfo, dir bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Getuid()) && info.Mode().Perm()&0077 == 0 && info.IsDir() == dir && (dir || info.Mode().IsRegular())
}

func dockerStateRoot() (string, error) {
	root := os.Getenv("OPENANT_DOCKER_STATE_DIR")
	if root == "" {
		config, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		root = filepath.Join(config, "openant", "docker-lifecycle")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if !privateOwned(info, true) {
		return "", fmt.Errorf("Docker lifecycle state must be a private owned directory")
	}
	return root, nil
}

func newDockerRegistry(owner string) (string, *os.File, error) {
	root, err := dockerStateRoot()
	if err != nil {
		return "", nil, err
	}
	// Publish only after locking: another process must never reap a new lease
	// in the interval between its creation and our flock call.
	staging, err := os.MkdirTemp(root, ".pending-")
	if err != nil {
		return "", nil, err
	}
	lease, err := os.OpenFile(filepath.Join(staging, ".lease"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		_ = os.Remove(staging)
		return "", nil, err
	}
	fail := func(err error) (string, *os.File, error) {
		lease.Close()
		os.Remove(filepath.Join(staging, ".lease"))
		os.Remove(staging)
		return "", nil, err
	}
	if err = syscall.Flock(int(lease.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return fail(err)
	}
	registry := filepath.Join(root, owner)
	if err = os.Rename(staging, registry); err != nil {
		return fail(err)
	}
	return registry, lease, nil
}

func (d *dockerInvocation) attachLease(cmd *exec.Cmd) {
	if d.lease == nil {
		return
	}
	fd := 3 + len(cmd.ExtraFiles)
	cmd.ExtraFiles = append(cmd.ExtraFiles, d.lease)
	cmd.Env = mergeEnv(cmd.Env, map[string]string{dockerLeaseEnv: strconv.Itoa(fd)})
}

// Recover only an exclusive, nonblocking lifetime lease, never a PID guess.
// The shared lease is inherited by Python, so a live child remains protected
// even if its Go parent has crashed. Python workers also acquire shared leases
// before registering resources. No lease is acquired for arbitrary directories.
func (d *dockerInvocation) recoverStale(pythonPath, workDir string, env []string, onLog func(string)) {
	root := filepath.Dir(d.registry)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	deadline := time.Now().Add(dockerCleanupTimeout)
	for _, entry := range entries {
		if time.Until(deadline) <= 0 {
			return
		}
		if !dockerOwnerPattern.MatchString(entry.Name()) || entry.Name() == d.owner {
			continue
		}
		registry := filepath.Join(root, entry.Name())
		info, err := os.Lstat(registry)
		if err != nil || !privateOwned(info, true) {
			continue
		}
		leasePath := filepath.Join(registry, ".lease")
		fd, err := syscall.Open(leasePath, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		lease := os.NewFile(uintptr(fd), leasePath)
		leaseInfo, err := lease.Stat()
		if err != nil || !privateOwned(leaseInfo, false) {
			lease.Close()
			continue
		}
		if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			lease.Close()
			continue
		}
		// Revalidate the named inode after acquiring the lock. A removed/replaced
		// lease is not evidence that the directory now at this path is abandoned.
		current, err := os.Lstat(leasePath)
		if err != nil || !os.SameFile(leaseInfo, current) {
			lease.Close()
			continue
		}
		old := &dockerInvocation{owner: entry.Name(), registry: registry, lease: lease, cleanupLocked: true}
		if !old.matchingBackend(env) {
			if onLog != nil {
				onLog("[openant] Docker 后端身份不匹配或缺失，已保留遗留任务的恢复记录：" + registry)
			}
			lease.Close()
			continue
		}

		old.cleanupWithTimeout(pythonPath, workDir, env, onLog, time.Until(deadline))
	}
}

func (d *dockerInvocation) lockForCleanup(wait bool) error {
	if d.lease == nil || d.cleanupLocked {
		return nil
	}
	// A lock upgrade on the inherited open-file description would also upgrade
	// a surviving descendant's shared lock. Close ONLY our reference, then use
	// an independently opened description to detect every surviving holder.
	old := d.lease
	path := filepath.Join(d.registry, ".lease")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	d.lease = os.NewFile(uintptr(fd), path)
	_ = old.Close()
	info, err := d.lease.Stat()
	if err != nil {
		return err
	}
	if !privateOwned(info, false) {
		return fmt.Errorf("unsafe Docker lifecycle lease")
	}
	// A concurrent fork briefly inherits all file descriptions until exec
	// applies CLOEXEC, even for another scan. Allow that transient holder to
	// exit; never assume an outstanding lease is dead when the budget ends.
	deadline := time.Now()
	if wait {
		deadline = deadline.Add(time.Second)
	}
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if (err != syscall.EWOULDBLOCK && err != syscall.EAGAIN) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(info, current) {
		return fmt.Errorf("Docker lifecycle lease changed")
	}
	d.cleanupLocked = true
	return nil
}
