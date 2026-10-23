// Modified 2026-10-23 for the VulScan-only product namespace.
// Package python handles Python runtime detection and validation.
package python

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// MinPythonMajor is the minimum required Python major version.
const MinPythonMajor = 3

// MinPythonMinor is the minimum required Python minor version.
const MinPythonMinor = 11

// RuntimeInfo holds information about the detected Python runtime.
type RuntimeInfo struct {
	Path    string // Full path to the Python binary
	Version string // Version string (e.g., "3.11.5")
	Major   int
	Minor   int
}

// pythonCandidates returns a list of Python binary names to search for, in order of preference.
func pythonCandidates() []string {
	return []string{"python3", "python"}
}

// venvDir returns the path to the managed venv: ~/.vulscan/venv/
func venvDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vulscan", "venv")
}

// venvPython returns the path to the Python binary inside the managed venv.
func venvPython() string {
	base := venvDir()
	if runtime.GOOS == "windows" {
		return filepath.Join(base, "Scripts", "python.exe")
	}
	return filepath.Join(base, "bin", "python")
}

// DetectRuntime finds a suitable Python 3.11+ installation.
//
// Search order:
//  1. VULSCAN_PYTHON env var (if set and valid) — set this to pin a specific
//     interpreter for debugging, CI, or container use (e.g. VULSCAN_PYTHON=python3.11).
//  2. Managed venv at ~/.vulscan/venv/ (if it exists and is valid)
//  3. python3 / python on PATH
//
// The managed-venv path (strategy 2) automatically detects the correct Python
// binary location based on the OS: "bin/python" on Unix-like systems, or
// "Scripts/python.exe" on Windows.
func DetectRuntime() (*RuntimeInfo, error) {
	// Strategy 0: honour explicit override via VULSCAN_PYTHON env var.
	// If the override is set but unusable, warn and fall through rather than
	// silently using a different interpreter behind the caller's back.
	if override := os.Getenv("VULSCAN_PYTHON"); override != "" {
		info, err := checkPython(override)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: VULSCAN_PYTHON=%q is not a usable Python binary (%v); ignoring override\n",
				override, err)
		} else if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
			return info, nil
		} else {
			fmt.Fprintf(os.Stderr,
				"warning: VULSCAN_PYTHON=%q is Python %s, below the required %d.%d; ignoring override\n",
				override, info.Version, MinPythonMajor, MinPythonMinor)
		}
	}

	// Strategy 1: check managed venv
	vp := venvPython()
	if fileExists(vp) {
		if info, err := checkPython(vp); err == nil {
			if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
				return info, nil
			}
		}
	}

	// Strategy 2: check PATH
	for _, name := range pythonCandidates() {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}

		info, err := checkPython(path)
		if err != nil {
			continue
		}

		if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
			return info, nil
		}
	}

	return nil, fmt.Errorf(
		"Python %d.%d+ is required but not found on PATH.\n"+
			"Install Python from https://python.org or use your system package manager.",
		MinPythonMajor, MinPythonMinor,
	)
}

// checkPython runs the given binary and extracts version info.
func checkPython(path string) (*RuntimeInfo, error) {
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run %s: %w", path, err)
	}

	// Output is "Python X.Y.Z\n"
	version := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "Python "))
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("unexpected version format: %s", version)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %s", parts[0])
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	return &RuntimeInfo{
		Path:    path,
		Version: version,
		Major:   major,
		Minor:   minor,
	}, nil
}

// CheckVulscan Installed verifies that the `vulscan` package is importable.
// If the package is missing, it attempts to:
//  1. Locate libs/vulscan-core
//  2. Create a managed venv at ~/.vulscan/venv/ (if not using one already)
//  3. Install vulscan into the venv
//
// On success, it updates the RuntimeInfo to point to the venv Python.
func CheckVulscanInstalled(pythonPath string) error {
	if isVulscanImportable(pythonPath) {
		return nil
	}

	// Not installed — try to find the source and install it.
	corePath, err := findVulscanCore()
	if err != nil {
		return fmt.Errorf(
			"vulscan Python package is not installed and could not be located automatically.\n"+
				"Install it with: pip install -e <path-to-vulscan-core>\n"+
				"(%s)", err,
		)
	}

	// #62 (ar7casper): concurrent invocations that both detect a missing
	// install race pip on the same venv (pip does not support concurrent
	// writes) — and BOTH create the venv itself if it is missing. Serialize
	// the ENTIRE create-then-install sequence on the OS-level lock
	// (review finding: createVenv previously raced outside it), mirroring
	// the JS bootstrap's .vulscan-npm-install.lock pattern.
	venvRoot := filepath.Dir(venvDir())
	if err := withVenvInstallLock(venvRoot, func() error {
		// Re-check under the lock: another process may have finished
		// creating+installing while we waited (the JS pattern's re-check).
		if pythonPath != venvPython() {
			fmt.Fprintln(os.Stderr, "Creating managed Python environment at ~/.vulscan/venv/...")
			if err := createVenv(pythonPath); err != nil {
				return fmt.Errorf(
					"failed to create venv at %s: %w\n"+
						"Try manually: %s -m venv %s && %s -m pip install -e %s",
					venvDir(), err, pythonPath, venvDir(), venvPython(), corePath,
				)
			}
			pythonPath = venvPython()
		}
		fmt.Fprintf(os.Stderr, "Installing vulscan from %s...\n", corePath)
		if isVulscanImportable(pythonPath) {
			return nil
		}
		return installVulscan(pythonPath, corePath)
	}); err != nil {
		return fmt.Errorf(
			"failed to install vulscan from %s:\n  %w\n"+
				"Try manually: %s -m pip install -e %s",
			corePath, err, pythonPath, corePath,
		)
	}

	// Verify it actually worked.
	if !isVulscanImportable(pythonPath) {
		return fmt.Errorf(
			"pip install succeeded but `import vulscan` still fails.\n"+
				"Try manually: %s -m pip install -e %s",
			pythonPath, corePath,
		)
	}

	// Save dependency hash so CheckDepsStale knows this is the baseline.
	if h, err := depsHash(corePath); err == nil {
		if err := writeStoredHash(h); err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: could not save dependency hash at %s: %v (next run may reinstall)\n",
				depsHashPath(), err)
		}
	}

	fmt.Fprintln(os.Stderr, "vulscan installed successfully.")
	return nil
}

// EnsureRuntime is a convenience that detects a runtime, ensures vulscan
// is installed (creating a venv if necessary), and returns the final
// RuntimeInfo pointing to the correct Python binary.
func EnsureRuntime() (*RuntimeInfo, error) {
	rt, err := DetectRuntime()
	if err != nil {
		return nil, err
	}

	if err := CheckVulscanInstalled(rt.Path); err != nil {
		return nil, err
	}

	// After CheckVulscanInstalled, the venv may have been created.
	// Re-detect to pick up the venv Python if it was just created —
	// unless the active runtime IS the explicit VULSCAN_PYTHON override.
	rt = preferVenv(rt)

	// Check if dependencies have changed since last install.
	// #437 (wave r1, opus): the .deps-hash is VENV-scoped
	// (depsHashPath -> ~/.vulscan/venv/.deps-hash) — an override run
	// (rt.Path is not the venv python) must not pip-install into the
	// user's pinned interpreter on the venv's stamp: that installed into
	// the system Python while stamping the venv, and once the override is
	// unset the venv silently ran the OLD dependencies forever — the exact
	// staleness failure the #59 hash exists to prevent. The override's
	// environment is its owner's to manage; the venv's staleness is
	// checked on the runs that use the venv.
	if rt.Path == venvPython() {
		if err := CheckDepsStale(rt.Path); err != nil {
			return nil, err
		}
	}

	return rt, nil
}

// preferVenv is EnsureRuntime's post-install re-detect: after
// CheckVulscanInstalled the managed venv may have just been created, so the
// venv Python is picked up — EXCEPT when the active runtime is the explicit
// VULSCAN_PYTHON override. #437: with the venv present (the normal install
// state) this block silently replaced a valid, explicitly-set override with
// the venv interpreter, no warning — inverting the README's documented
// precedence ("Takes precedence over the managed venv at ~/.vulscan/venv/ and
// any Python on PATH") and doing exactly what DetectRuntime's own comment
// forbids ("never silently using a different interpreter behind the
// caller's back") for a USABLE override. The override wins.
func preferVenv(rt *RuntimeInfo) *RuntimeInfo {
	// #437 (wave r1, three axes): keep the override only when it is
	// SELF-SUFFICIENT — isVulscanImportable. DetectRuntime probes --version
	// only; a version-adequate override WITHOUT vulscan (the documented
	// CI/container pin shape) is exactly what CheckVulscanInstalled just
	// bootstrapped the managed venv FOR (its local pythonPath reassignment
	// cannot reach the caller), and keeping the bare override returned an
	// interpreter that failed EVERY subsequent invocation with
	// ModuleNotFoundError — a regression the pre-fix unconditional
	// re-detect never had. The venv was built FROM the override's
	// interpreter, so the pin is still honoured at the base level.
	if override := os.Getenv("VULSCAN_PYTHON"); override != "" && rt.Path == override {
		if isVulscanImportable(rt.Path) {
			return rt
		}
	}
	vp := venvPython()
	if rt.Path != vp && fileExists(vp) && isVulscanImportable(vp) {
		if info, err := checkPython(vp); err == nil {
			return info
		}
	}
	return rt
}

// depsHashPath returns the path to the stored dependency hash inside the venv.
func depsHashPath() string {
	return filepath.Join(venvDir(), ".deps-hash")
}

// hashFile returns the hex-encoded SHA-256 of a file's contents.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// readHashAt reads a stored hash from the given path, or "" if absent.
func readHashAt(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// writeHashAt saves a hash to the given path, creating the parent directory
// if it does not already exist.
func writeHashAt(path, hash string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(hash+"\n"), 0644)
}

// readStoredHash reads the previously stored dependency hash, or "" if absent.
func readStoredHash() string { return readHashAt(depsHashPath()) }

// writeStoredHash saves the dependency hash to the venv marker file.
func writeStoredHash(hash string) error { return writeHashAt(depsHashPath(), hash) }

// depsHash keys the dependency stamp on BOTH pyproject.toml contents AND corePath (the
// editable-install source). The managed venv is a single global path shared across worktrees;
// without corePath in the key, two worktrees with identical pyproject.toml share one editable
// install and a binary built in one silently imports the other's source. Including corePath forces
// a reinstall (re-pointing the editable install) when the active source changes.
func depsHash(corePath string) (string, error) {
	pyproject, err := os.ReadFile(filepath.Join(corePath, "pyproject.toml"))
	if err != nil {
		return "", err
	}
	// #59: the staleness key covers requirements.txt too — installVulscan
	// now installs it (the exact CI pins), so a pin change must trigger a
	// reinstall the same way a pyproject change does. A MISSING file is not
	// an error (the dev-layout degrade path): hash the corePath+pyproject
	// alone, matching the old key.
	reqs, reqsErr := os.ReadFile(filepath.Join(corePath, "requirements.txt"))
	if reqsErr != nil {
		reqs = nil // degrade: the dev layout without requirements.txt
	}
	sum := sha256.Sum256(append(append([]byte(corePath+"\x00"), pyproject...), reqs...))
	return hex.EncodeToString(sum[:]), nil
}

// depsStalenessAt inspects pyproject.toml at corePath and the hash stored at
// hashPath, and reports whether a reinstall is needed. The boolean is true
// when deps are stale (i.e. the hash differs and a reinstall is warranted).
// The caller is expected to skip the check on any error.
func depsStalenessAt(corePath, hashPath string) (stale bool, currentHash string, err error) {
	currentHash, err = depsHash(corePath)
	if err != nil {
		return false, "", err
	}
	return currentHash != readHashAt(hashPath), currentHash, nil
}

// depsStaleness is the production wrapper around depsStalenessAt that uses
// the real venv hash path.
func depsStaleness(corePath string) (stale bool, currentHash string, err error) {
	return depsStalenessAt(corePath, depsHashPath())
}

// CheckDepsStale checks if pyproject.toml has changed since the last install.
// If stale, it re-runs pip install -e and updates the stored hash.
// Returns nil if deps are up-to-date or were successfully refreshed.
func CheckDepsStale(pythonPath string) error {
	return checkDepsStaleWith(pythonPath, findVulscanCore)
}

// checkDepsStaleWith is the testable core of CheckDepsStale; coreFinder is
// injected so tests can avoid os.Chdir to simulate a missing source tree.
func checkDepsStaleWith(pythonPath string, coreFinder func() (string, error)) error {
	corePath, err := coreFinder()
	if err != nil {
		// Can't find source — skip staleness check
		return nil
	}

	stale, currentHash, err := depsStaleness(corePath)
	if err != nil {
		// Can't read pyproject.toml — skip check
		return nil
	}
	if !stale {
		return nil // deps are up-to-date
	}

	fmt.Fprintln(os.Stderr, "Dependencies changed, updating vulscan installation...")
	// #62 (ar7casper): the known limitation is closed — concurrent
	// invocations serialize on the OS-level lock (mirroring the JS
	// bootstrap), and staleness is re-checked under it.
	venvRoot := filepath.Dir(venvDir())
	if err := withVenvInstallLock(venvRoot, func() error {
		if stale2, _, err2 := depsStaleness(corePath); err2 == nil && !stale2 {
			return nil
		}
		return installVulscan(pythonPath, corePath)
	}); err != nil {
		return fmt.Errorf(
			"failed to update vulscan dependencies: %w\n"+
				"Try manually: %s -m pip install -e %s",
			err, pythonPath, corePath,
		)
	}

	// Store the new hash
	if err := writeStoredHash(currentHash); err != nil {
		// Non-fatal — install succeeded, just can't cache the hash
		fmt.Fprintf(os.Stderr, "Warning: could not save dependency hash: %v\n", err)
	}

	fmt.Fprintln(os.Stderr, "Dependencies updated successfully.")
	return nil
}

// createVenv creates a new venv at ~/.vulscan/venv/ using the given Python.
func createVenv(pythonPath string) error {
	dir := venvDir()
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return err
	}
	cmd := exec.Command(pythonPath, "-m", "venv", dir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// isVulscanImportable returns true if `python -c "import vulscan"` succeeds.
func isVulscanImportable(pythonPath string) bool {
	cmd := exec.Command(pythonPath, "-c", "from vulscan import __version__")
	return cmd.Run() == nil
}

// installVulscan runs `python -m pip install -e <corePath>`.
// installVulscanCmds builds the commands installVulscan runs (the test seam).
func installVulscanCmds(pythonPath, corePath string) []*exec.Cmd {
	// #59 (ar7casper): end-user installs must be DETERMINISTIC — CI runs
	// `pip install -r requirements.txt && pip install ".[dev]"`, where
	// requirements.txt carries the EXACT pins. An end user running `vulscan
	// scan` today resolves pyproject.toml's FLOOR pins (>=), pulling whatever
	// PyPI currently serves — so a user hits anthropic==1.2.1 while CI tested
	// ==1.2.0, and an upstream SDK change lands on users without ever being
	// exercised in CI. Mirror CI: requirements.txt first (the exact pins),
	// then the editable install (which must not upgrade what was pinned — pip
	// does not downgrade pinned deps unless the pin conflicts, and
	// pyproject's floors are compatible with the pins by construction).
	//
	// #428: the honest boundary of "deterministic" — the LLM-SDK chain
	// (anthropic/openai/google-genai/pydantic/httpx and their transitive
	// pins) is EXACTLY locked; the shared floor lines (PyYAML, requests, the
	// eight tree-sitter grammars) and anthropic[bedrock]'s extra (boto3/
	// botocore, unpinned — botocore releases ~daily) resolve at whatever the
	// floor admits. The drift hazard this leaves — a pyproject floor raised
	// ABOVE a requirements pin would silently upgrade past the pin on the
	// editable install — is guarded by
	// libs/vulscan-core/tests/test_issue428_floors_vs_pins.py.
	reqs := filepath.Join(corePath, "requirements.txt")
	cmds := []*exec.Cmd{}
	if _, err := os.Stat(reqs); err == nil {
		reqCmd := exec.Command(pythonPath, "-m", "pip", "install", "-r", reqs)
		reqCmd.Stdout = os.Stderr // pip output goes to stderr so it doesn't pollute JSON stdout
		reqCmd.Stderr = os.Stderr
		cmds = append(cmds, reqCmd)
	}
	// A dev layout without requirements.txt degrades to the old behavior
	// (the editable install alone) — the staleness check must not error
	// every run.
	cmd := exec.Command(pythonPath, "-m", "pip", "install", "-e", corePath)
	cmd.Stdout = os.Stderr // pip output goes to stderr so it doesn't pollute JSON stdout
	cmd.Stderr = os.Stderr
	cmds = append(cmds, cmd)
	return cmds
}

// installVulscan mirrors CI: requirements.txt (the exact pins) first, then
// the editable install.
func installVulscan(pythonPath, corePath string) error {
	for _, c := range installVulscanCmds(pythonPath, corePath) {
		if err := c.Run(); err != nil {
			return fmt.Errorf("pip install failed (%v): %w", c.Args, err)
		}
	}
	return nil
}

// PipUninstall returns an *exec.Cmd that runs `python -m pip uninstall vulscan -y`.
func PipUninstall(pythonPath string) *exec.Cmd {
	cmd := exec.Command(pythonPath, "-m", "pip", "uninstall", "vulscan", "-y")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd
}

// VulscanCoreEnv lets a developer point at a checkout explicitly. It is the ONLY
// way to name a core path that is not derived from the installed executable.
const VulscanCoreEnv = "VULSCAN_CORE_PATH"

// findVulscanCore locates the libs/vulscan-core directory to install from.
//
// Resolution order, deliberately narrow:
//  1. $VULSCAN_CORE_PATH — an explicit, operator-supplied development checkout.
//  2. Walking up from the running executable — the monorepo/dev layout.
//
// It does NOT search the current working directory, and that omission is the
// whole point of this function.
//
// The caller feeds the result to `pip install -e`, and an editable install
// EXECUTES the target's build backend. Searching upward from CWD therefore meant:
// run `vulscan` anywhere at or below a repository that happens to ship
// `libs/vulscan-core/pyproject.toml`, with the import probe failing, and the CLI
// installs and runs code from that repository.
//
// For a tool whose entire purpose is being pointed at untrusted third-party
// repositories, that turns the scan target into an installation source — remote
// code execution reachable by a repo layout alone. The trigger is conditional
// (the probe must fail first), which makes it latent rather than acceptable: a
// broken venv, a partial upgrade, or a Python version bump is enough.
//
// An operator who genuinely wants a checkout can say so with the env var. What
// they cannot do is have one chosen for them by whatever directory they happened
// to be standing in.
func findVulscanCore() (string, error) {
	marker := filepath.Join("libs", "vulscan-core", "pyproject.toml")

	// Strategy 1: explicit operator override.
	if explicit := strings.TrimSpace(os.Getenv(VulscanCoreEnv)); explicit != "" {
		if fileExists(filepath.Join(explicit, "pyproject.toml")) {
			return explicit, nil
		}
		return "", fmt.Errorf(
			"%s=%q does not contain pyproject.toml; point it at libs/vulscan-core",
			VulscanCoreEnv, explicit)
	}

	// Strategy 2: walk up from the executable. Trusted because the operator chose
	// which binary to run; the scan target has no say in where it lives.
	if exePath, err := os.Executable(); err == nil {
		exePath, _ = filepath.EvalSymlinks(exePath)
		dir := filepath.Dir(exePath)
		for range 6 { // at most 6 levels up
			candidate := filepath.Join(dir, "libs", "vulscan-core")
			if fileExists(filepath.Join(dir, marker)) {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	// Fail closed, with the remediation the user needs. Previously this fell
	// through to a CWD search, which is how a scanned repository could answer the
	// question "where should I install the engine from?".
	return "", fmt.Errorf(
		"could not locate the vulscan engine relative to the executable.\n"+
			"The working directory is deliberately NOT searched: it may be an "+
			"untrusted repository, and installing from it would execute its build "+
			"code.\n"+
			"Fix by installing the engine (pip install /path/to/libs/vulscan-core) or, for a "+
			"development checkout, set %s=/path/to/libs/vulscan-core",
		VulscanCoreEnv)
}

// fileExists is a small helper that returns true if path exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// venvInstallLockPath returns the lockfile path guarding concurrent pip
// installs into the managed venv. Mirrors the JS bootstrap's pattern
// (parser_adapter.py's _file_lock over .vulscan-npm-install.lock): the
// withVenvInstallLock runs fn under an exclusive lock so two concurrent
// invocations that both detect a missing or stale install serialize
// instead of racing pip on the same venv (pip does not support
// concurrent writes: corrupted RECORD files, partial wheel extraction,
// broken .dist-info metadata).
//
// The lock is the same cross-platform shape the JS bootstrap uses
// (msvcrt.locking on Windows, flock elsewhere) via Go's build-tag
// split: lock_unix.go / lock_windows.go.
func withVenvInstallLock(venvDir string, fn func() error) error {
	lockPath := filepath.Join(venvDir, ".deps-install.lock")
	if err := os.MkdirAll(venvDir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := lockFileExcl(f); err != nil {
		return err
	}
	defer unlockFile(f)
	return fn()
}
