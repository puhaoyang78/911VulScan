// Modified 2026-10-23 for the VulScan-only product namespace.
// Added 2026-10-23: new-only product configuration and data namespace.
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVulScanUsesNewConfigurationAndData(t *testing.T) {
	withConfigJSON(t, `{"api_key":"namespace-fixture", "active_project":"org/repo", "default_llm":"vulscan-default"}`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "namespace-fixture" || cfg.ActiveProject != "org/repo" {
		t.Fatal("new namespace configuration not loaded")
	}
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(filepath.Dir(path)) != "vulscan" {
		t.Fatalf("new namespace config path changed: %s", path)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	data, err := DataDir()
	if err != nil {
		t.Fatal(err)
	}
	if data != filepath.Join(home, ".vulscan") {
		t.Fatalf("new namespace data path changed: %s", data)
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	again, err := Load()
	if err != nil || again.APIKey != cfg.APIKey {
		t.Fatal("new namespace roundtrip failed")
	}
}

func TestVulScanDoesNotImportOrModifyOldNamespace(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("APPDATA", filepath.Join(home, "config"))
	oldConfig := filepath.Join(home, "config", "openant", "config.json")
	oldData := filepath.Join(home, ".openant", "projects", "sentinel")
	for _, p := range []string{oldConfig, oldData} {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(`{"api_key":"old-only-key"}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "" {
		t.Fatal("old namespace was imported")
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{oldConfig, oldData} {
		data, err := os.ReadFile(p)
		if err != nil || string(data) != `{"api_key":"old-only-key"}` {
			t.Fatalf("old user state touched: %s (%v)", p, err)
		}
	}
}
