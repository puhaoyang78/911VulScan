// Modified 2026-10-23 for the VulScan-only product namespace.
package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A scanned repository must never be able to answer "where should I install the
// engine from?".
//
// findVulscanCore's result is passed to `pip install -e`, which executes the
// target's build backend. The previous implementation fell back to walking up
// from the CURRENT WORKING DIRECTORY looking for libs/vulscan-core/pyproject.toml
// — so running vulscan at or below a repository shipping that path, with the
// import probe failing, installed and executed code from that repository.
//
// VulScan exists to be pointed at untrusted third-party repositories. This test
// builds exactly such a repository and asserts the search does not take the bait.
func TestFindVulscanCoreIgnoresTheWorkingDirectory(t *testing.T) {
	hostile := t.TempDir()
	core := filepath.Join(hostile, "libs", "vulscan-core")
	if err := os.MkdirAll(core, 0o755); err != nil {
		t.Fatal(err)
	}
	// A build backend that would run on `pip install -e`.
	if err := os.WriteFile(filepath.Join(core, "pyproject.toml"),
		[]byte("[build-system]\nrequires=[\"setuptools\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(core, "setup.py"),
		[]byte("import os; os.system('touch /tmp/vulscan-pwned')\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Precondition: the bait is real. Without this the test could pass because the
	// fixture was never built, which is the vacuous-green failure mode.
	if _, err := os.Stat(filepath.Join(core, "pyproject.toml")); err != nil {
		t.Fatalf("fixture not built: %v", err)
	}

	t.Chdir(hostile)
	t.Setenv(VulscanCoreEnv, "")

	got, err := findVulscanCore()
	if err == nil && strings.HasPrefix(got, hostile) {
		t.Fatalf("findVulscanCore resolved to the untrusted working directory (%s); "+
			"pip install -e would execute its build backend", got)
	}
}

// The escape hatch must still work, or developers will find a worse one.
func TestFindVulscanCoreHonoursTheExplicitOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[project]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(VulscanCoreEnv, dir)

	got, err := findVulscanCore()
	if err != nil {
		t.Fatalf("explicit override rejected: %v", err)
	}
	if got != dir {
		t.Errorf("got %q, want %q", got, dir)
	}
}

// A bad override must fail loudly rather than silently falling back to a search —
// a silent fallback is how the CWD path became reachable in the first place.
func TestBadOverrideFailsClosed(t *testing.T) {
	t.Setenv(VulscanCoreEnv, filepath.Join(t.TempDir(), "nonexistent"))
	if _, err := findVulscanCore(); err == nil {
		t.Error("a non-existent override was accepted; it must fail closed")
	}
}
