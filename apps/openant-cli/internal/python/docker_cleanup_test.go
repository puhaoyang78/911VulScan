package python

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func cleanupFixture(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fixture")
	}
	t.Setenv("OPENANT_DOCKER_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	dir := t.TempDir()
	script := filepath.Join(dir, "python")
	body := `#!/bin/sh
if [ "$3" = utilities.docker_resources ]; then
  test "$5" = --owner && test "$6" = "$OPENANT_DOCKER_OWNER" || exit 7
  event=$(cat "$OPENANT_DOCKER_REGISTRY_DIR/record")
  printf '%s\n' "$OPENANT_DOCKER_OWNER" > "$event.cleanup"
  rm "$OPENANT_DOCKER_REGISTRY_DIR/record"
  exit 0
fi
printf '%s\n' "$OPENANT_DOCKER_OWNER" > "$TEST_EVENT.owner"
printf '%s' "$TEST_EVENT" > "$OPENANT_DOCKER_REGISTRY_DIR/record"
printf '%s\n' "$OPENANT_DOCKER_REGISTRY_DIR" > "$TEST_EVENT.registry"
case "$TEST_MODE" in
 fail) exit 2;;
 hang) while :; do sleep 1; done;;
esac
printf '{"status":"success"}'
`
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return script, filepath.Join(dir, "event")
}

func assertCleanup(t *testing.T, event string) string {
	t.Helper()
	owner, err := os.ReadFile(event + ".owner")
	if err != nil {
		t.Fatal(err)
	}
	clean, err := os.ReadFile(event + ".cleanup")
	if err != nil {
		t.Fatal(err)
	}
	if string(owner) != string(clean) || !regexp.MustCompile(`^[0-9a-f]{32}\n$`).Match(owner) {
		t.Fatalf("ownership mismatch %q %q", owner, clean)
	}
	registry, err := os.ReadFile(event + ".registry")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(strings.TrimSpace(string(registry))); !os.IsNotExist(err) {
		t.Fatalf("registry not reclaimed: %v", err)
	}
	return strings.TrimSpace(string(owner))
}

func TestDockerCleanupInvocationOutcomes(t *testing.T) {
	for _, mode := range []string{"normal", "fail", "hang", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			script, event := cleanupFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			actualMode := mode
			if mode == "hang" {
				t.Setenv("OPENANT_INVOKE_TIMEOUT", "500ms")
			}
			if mode == "cancel" {
				actualMode = "hang"
				done := make(chan struct{})
				defer close(done)
				go func() {
					timer := time.NewTicker(time.Millisecond)
					defer timer.Stop()
					for {
						select {
						case <-done:
							return
						case <-timer.C:
							if _, err := os.Stat(event + ".registry"); err == nil {
								cancel()
								return
							}
						}
					}
				}()
			}
			env := map[string]string{"TEST_EVENT": event, "TEST_MODE": actualMode, dockerOwnerEnv: "unsafe-inherited-owner", dockerRegistryEnv: "/do/not/use"}
			out, code, err := InvokeCtxCaptureEnv(ctx, script, []string{"scan"}, "", env, nil)
			switch mode {
			case "normal":
				if err != nil || code != 0 || out != `{"status":"success"}` {
					t.Fatalf("normal outcome %q %d %v", out, code, err)
				}
			case "fail":
				if err != nil || code != 2 {
					t.Fatalf("failure outcome %d %v", code, err)
				}
			case "hang":
				if !errors.Is(err, ErrInvokeDeadline) {
					t.Fatalf("deadline lost: %v", err)
				}
			case "cancel":
				if err != nil || code != -1 {
					t.Fatalf("cancel outcome %d %v", code, err)
				}
			}
			assertCleanup(t, event)
			if env[dockerOwnerEnv] != "unsafe-inherited-owner" {
				t.Fatal("mutated caller environment")
			}
		})
	}
}

func TestDockerCleanupCLI(t *testing.T) {
	for _, mode := range []string{"normal", "fail", "hang"} {
		t.Run(mode, func(t *testing.T) {
			script, event := cleanupFixture(t)
			if mode == "hang" {
				t.Setenv("OPENANT_INVOKE_TIMEOUT", "500ms")
			}
			_, err := Invoke(script, []string{"scan"}, "", true, "", map[string]string{"TEST_EVENT": event, "TEST_MODE": mode})
			if mode == "hang" && err == nil {
				t.Fatal("expected timeout")
			}
			if mode != "hang" && err != nil {
				t.Fatal(err)
			}
			assertCleanup(t, event)
		})
	}
}

func TestDockerCleanupParallelOwners(t *testing.T) {
	script, event := cleanupFixture(t)
	var wg sync.WaitGroup
	for _, id := range []string{"a", "b"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, code, err := InvokeCtxCaptureEnv(context.Background(), script, []string{"scan"}, "", map[string]string{"TEST_EVENT": event + id}, func(s string) { t.Logf("job %s: %s", id, s) })
			if err != nil || code != 0 {
				t.Errorf("invoke %s: %d %v", id, code, err)
			}
		}(id)
	}
	wg.Wait()
	if assertCleanup(t, event+"a") == assertCleanup(t, event+"b") {
		t.Fatal("shared owner")
	}
}

func TestDockerCleanupBoundedAndRetainsRegistry(t *testing.T) {
	t.Setenv("OPENANT_DOCKER_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	d, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d.registry)
	if err := os.WriteFile(filepath.Join(d.registry, "record"), []byte("registered"), 0600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "hang")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nwhile :; do sleep 1; done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	var warning string
	start := time.Now()
	d.cleanupWithTimeout(script, "", os.Environ(), func(s string) { warning = s }, 50*time.Millisecond)
	if time.Since(start) > 2*time.Second {
		t.Fatal("cleanup unbounded")
	}
	if warning == "" {
		t.Fatal("missing cleanup warning")
	}
	if _, err := os.Stat(filepath.Join(d.registry, "record")); err != nil {
		t.Fatal("lost recovery record", err)
	}
}

func TestDockerCleanupNoResourcesDoesNotLaunch(t *testing.T) {
	t.Setenv("OPENANT_DOCKER_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	d, err := newDockerInvocation()
	if err != nil {
		t.Fatal(err)
	}
	d.cleanup("/nonexistent-python", "", nil, func(s string) { t.Fatal(s) })
	if _, err := os.Stat(d.registry); !os.IsNotExist(err) {
		t.Fatalf("empty registry remained: %v", err)
	}
}

func TestDockerCleanupCLIInterrupt(t *testing.T) {
	script, event := cleanupFixture(t)
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "10s")
	done := make(chan struct{})
	var result *InvokeResult
	var invokeErr error
	go func() {
		defer close(done)
		result, invokeErr = Invoke(script, []string{"scan"}, "", true, "", map[string]string{"TEST_EVENT": event, "TEST_MODE": "hang"})
	}()
	waitForSentinel(t, event+".registry", 5*time.Second)
	// The child starts immediately before signal.Notify is installed.
	time.Sleep(50 * time.Millisecond)
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err = self.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("interrupt did not finish")
	}
	if invokeErr != nil || result == nil || result.ExitCode != 130 {
		t.Fatalf("interrupt changed: result=%v err=%v", result, invokeErr)
	}
	assertCleanup(t, event)
}
