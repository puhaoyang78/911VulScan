package cmd

import (
	"os"
	"testing"
)

func TestApplyScanInvokeBudgetSetsThreeHoursForDynamicScan(t *testing.T) {
	t.Setenv("VULSCAN_INVOKE_TIMEOUT", "")
	applyScanInvokeBudget(true, true)
	if got := os.Getenv("VULSCAN_INVOKE_TIMEOUT"); got != "3h" {
		t.Fatalf("VULSCAN_INVOKE_TIMEOUT = %q, want 3h", got)
	}
}

func TestApplyScanInvokeBudgetKeepsUserValue(t *testing.T) {
	t.Setenv("VULSCAN_INVOKE_TIMEOUT", "90m")
	applyScanInvokeBudget(true, true)
	if got := os.Getenv("VULSCAN_INVOKE_TIMEOUT"); got != "90m" {
		t.Fatalf("VULSCAN_INVOKE_TIMEOUT = %q, want 90m", got)
	}
}

func TestApplyScanInvokeBudgetIgnoresStaticScan(t *testing.T) {
	t.Setenv("VULSCAN_INVOKE_TIMEOUT", "")
	applyScanInvokeBudget(false, true)
	if got := os.Getenv("VULSCAN_INVOKE_TIMEOUT"); got != "" {
		t.Fatalf("VULSCAN_INVOKE_TIMEOUT = %q, want empty", got)
	}
}
