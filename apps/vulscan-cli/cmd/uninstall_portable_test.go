// Modified 2026-10-23 for the VulScan-only product namespace.
// Added 2026-10-23: portable deployments must never delete legacy state.
package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestPortableUninstallRefusesBeforeTouchingLegacyState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// A deliberately untrusted marker must only trigger refusal, never deletion.
	t.Setenv("VULSCAN_PORTABLE_ROOT", "/")
	files := []string{".vulscan/venv/sentinel", ".vulscan/projects/scan.json", ".config/vulscan/config.json"}
	for _, name := range files {
		path := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("retain-me"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	oldHard := uninstallHard
	defer func() { uninstallHard = oldHard }()
	command := &cobra.Command{Use: "uninstall", PreRunE: uninstallCmd.PreRunE, Run: runUninstall, SilenceErrors: true, SilenceUsage: true}
	command.Flags().BoolVar(&uninstallHard, "hard", false, "")
	command.SetArgs([]string{"--hard"})
	command.SetIn(strings.NewReader("yes\n"))
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "portable") {
		t.Fatalf("want portable refusal, got %v", err)
	}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(home, name))
		if err != nil || string(data) != "retain-me" {
			t.Fatalf("legacy file changed: %s (%v)", name, err)
		}
	}
}
