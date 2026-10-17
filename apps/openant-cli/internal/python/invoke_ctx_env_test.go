package python

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestInvokeCtxCaptureEnvScopesProviderKeys(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the environment fixture uses a POSIX shell")
	}
	t.Setenv("DEEPSEEK_API_KEY", "parent-value")
	t.Setenv("ANTHROPIC_API_KEY", "legacy-value")
	script := filepath.Join(t.TempDir(), "provider-env.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '{\"deepseek\":\"%s\",\"anthropic\":\"%s\"}' \"$DEEPSEEK_API_KEY\" \"$ANTHROPIC_API_KEY\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, key := range []string{"job-one", "job-two"} {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			out, code, err := InvokeCtxCaptureEnv(context.Background(), script, nil, "", map[string]string{"DEEPSEEK_API_KEY": key}, nil)
			if err != nil || code != 0 {
				t.Errorf("subprocess failed: code=%d err=%v", code, err)
				return
			}
			var env map[string]string
			if err := json.Unmarshal([]byte(out), &env); err != nil {
				t.Errorf("invalid fixture output: %v", err)
				return
			}
			if env["deepseek"] != key || env["anthropic"] != "legacy-value" {
				t.Errorf("provider override crossed job/provider boundaries")
			}
		}(key)
	}
	wg.Wait()
	if got := os.Getenv("DEEPSEEK_API_KEY"); got != "parent-value" {
		t.Fatal("per-job credential changed the parent process environment")
	}
}

func TestInvokeCtxEnvPreservesLegacyAPI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the environment fixture uses a POSIX shell")
	}
	script := filepath.Join(t.TempDir(), "provider-check.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntest \"$DEEPSEEK_API_KEY\" = job-only\n"), 0700); err != nil {
		t.Fatal(err)
	}
	code, err := InvokeCtxEnv(context.Background(), script, nil, "", map[string]string{"DEEPSEEK_API_KEY": "job-only"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("env-only invocation: code=%d err=%v", code, err)
	}
	legacy := legacyAPIKeyEnv("anthropic-only")
	if legacy["ANTHROPIC_API_KEY"] != "anthropic-only" || legacy["DEEPSEEK_API_KEY"] != "" {
		t.Fatal("legacy API key routing changed")
	}
}
