//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Modified 2026-10-23 for the VulScan-only product namespace.
package python

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func recordLeaseFixture(t *testing.T, d *dockerInvocation, event string) {
	t.Helper()
	if err := d.recordBackend(os.Environ()); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{filepath.Join(d.registry, "record"): event, event + ".owner": d.owner + "\n", event + ".registry": d.registry + "\n"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDockerLeaseRecoverySkipsLiveAndReclaimsDead(t *testing.T) {
	script, event := cleanupFixture(t)
	old, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	recordLeaseFixture(t, old, event)
	current, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	defer current.cleanup(script, "", os.Environ(), nil)
	env := mergeEnv(os.Environ(), map[string]string{"TEST_EVENT": event})
	current.recoverStale(script, "", env, nil)
	if _, err := os.Stat(event + ".cleanup"); !os.IsNotExist(err) {
		t.Fatal("reaped a live invocation")
	}
	if err := old.lease.Close(); err != nil {
		t.Fatal(err)
	}
	current.recoverStale(script, "", env, func(s string) { t.Error(s) })
	assertCleanup(t, event)
}

func TestDockerLeaseInheritedChildSurvivesParent(t *testing.T) {
	script, event := cleanupFixture(t)
	old, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	recordLeaseFixture(t, old, event)
	child := exec.CommandContext(context.Background(), "sh", "-c", "exec sleep 30")
	child.Env = old.environment(os.Environ())
	old.attachLease(child)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	env := mergeEnv(os.Environ(), map[string]string{"TEST_EVENT": event})
	// Simulates root Python exit while an inherited worker remains. Own cleanup
	// must reopen a separate lock description, not upgrade the inherited one.
	var warning string
	old.cleanup(script, "", env, func(s string) { warning = s })
	if !strings.Contains(warning, "租约") {
		t.Fatalf("missing live-worker warning: %q", warning)
	}
	current, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	defer current.cleanup(script, "", env, nil)
	current.recoverStale(script, "", env, nil)
	if _, err := os.Stat(event + ".cleanup"); !os.IsNotExist(err) {
		t.Fatal("reaped a surviving child")
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	current.recoverStale(script, "", env, func(s string) { t.Error(s) })
	assertCleanup(t, event)
}

func TestDockerLeaseRejectsUnsafeStateAndSymlinks(t *testing.T) {
	root := t.TempDir()
	t.Setenv("VULSCAN_DOCKER_STATE_DIR", root)
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := newDockerInvocation(); err == nil {
		t.Fatal("accepted nonprivate state")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, strings.Repeat("a", 32))); err != nil {
		t.Fatal(err)
	}
	current, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	defer current.cleanup("/missing-python", "", nil, nil)
	current.recoverStale("/missing-python", "", nil, func(s string) { t.Fatal(s) })
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("followed symlink")
	}
}

func TestDockerLeaseRecoveryRequiresSameBackend(t *testing.T) {
	script, event := cleanupFixture(t)
	old, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	recordLeaseFixture(t, old, event)
	old.lease.Close()
	current, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	defer current.cleanup(script, "", os.Environ(), nil)
	env := mergeEnv(os.Environ(), map[string]string{"TEST_EVENT": event, "DOCKER_HOST": "tcp://different-daemon.invalid:2376"})
	var warning string
	current.recoverStale(script, "", env, func(s string) { warning = s })
	if !strings.Contains(warning, "后端") {
		t.Fatalf("missing mismatch warning: %q", warning)
	}
	if _, err := os.Stat(filepath.Join(old.registry, "record")); err != nil {
		t.Fatal("lost old backend recovery record", err)
	}
	if _, err := os.Stat(event + ".cleanup"); !os.IsNotExist(err) {
		t.Fatal("queried wrong daemon")
	}
	current.recoverStale(script, "", mergeEnv(os.Environ(), map[string]string{"TEST_EVENT": event}), func(s string) { t.Error(s) })
	assertCleanup(t, event)
}

func TestDockerLeaseBackendContextChangesAndNoSecrets(t *testing.T) {
	config := t.TempDir()
	t.Setenv("DOCKER_CONFIG", config)
	path := filepath.Join(config, "config.json")
	secret := `{"auths":{"example":{"auth":"never-persist-me"}},"currentContext":"first"}`
	if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	script, event := cleanupFixture(t)
	old, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	recordLeaseFixture(t, old, event)
	saved, err := os.ReadFile(filepath.Join(old.registry, ".backend"))
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 64 || strings.Contains(string(saved), "never-persist-me") {
		t.Fatal("backend identity is not a digest")
	}
	old.lease.Close()
	current, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	defer current.cleanup(script, "", os.Environ(), nil)
	env := mergeEnv(os.Environ(), map[string]string{"TEST_EVENT": event})
	if err := os.WriteFile(path, []byte(`{"currentContext":"second"}`), 0600); err != nil {
		t.Fatal(err)
	}
	current.recoverStale(script, "", env, nil)
	if _, err := os.Stat(event + ".cleanup"); !os.IsNotExist(err) {
		t.Fatal("reaped changed default context")
	}
	if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	current.recoverStale(script, "", env, func(s string) { t.Error(s) })
	assertCleanup(t, event)
}

func TestDockerLeaseTransientForkReference(t *testing.T) {
	script, event := cleanupFixture(t)
	d, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	recordLeaseFixture(t, d, event)
	// Model a concurrent fork holding this open-file description until exec
	// closes CLOEXEC descriptors. The original Python child has already exited.
	fd, err := syscall.Dup(int(d.lease.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	transient := os.NewFile(uintptr(fd), "transient-fork-lease")
	defer transient.Close()
	released := make(chan struct{})
	go func() { time.Sleep(50 * time.Millisecond); transient.Close(); close(released) }()
	d.cleanup(script, "", mergeEnv(os.Environ(), map[string]string{"TEST_EVENT": event}), func(s string) { t.Error(s) })
	<-released
	assertCleanup(t, event)
}
