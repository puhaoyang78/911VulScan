// Modified 2026-10-23 for the VulScan-only product namespace.
// Added 2026-10-23: 911VulScan public branding regression coverage.
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestVulScanPublicHelpBranding(t *testing.T) {
	if rootCmd.Name() != "vulscan" {
		t.Fatalf("command = %q", rootCmd.Name())
	}
	var out bytes.Buffer
	old := rootCmd.OutOrStdout()
	rootCmd.SetOut(&out)
	defer rootCmd.SetOut(old)
	if err := rootCmd.Help(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"911VulScan", "vulscan", "LICENSE", "THIRD_PARTY_NOTICES.md"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help missing %q", want)
		}
	}
	if strings.Contains(out.String(), "openant setup") {
		t.Fatal("help advertises old command")
	}
}
