package python

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInvokeCtxCaptureEnvTimeoutParallelIsolation(t *testing.T) {
	// A process-wide short timeout must not clamp the long job, nor may its
	// explicit budget extend the short job. Both calls execute the same stub.
	t.Setenv("VULSCAN_INVOKE_TIMEOUT", "100ms")
	script := writeCtxScript(t, "sleep 2\nprintf '%s' \"$JOB_NAME\"\n")
	type result struct {
		out  string
		code int
		err  error
	}
	results := make([]result, 2)
	budgets := []time.Duration{time.Second, 10 * time.Second}
	var wg sync.WaitGroup
	for i := range budgets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i].out, results[i].code, results[i].err = InvokeCtxCaptureEnvTimeout(context.Background(), script, nil, "", map[string]string{"JOB_NAME": "long-job", "VULSCAN_INVOKE_TIMEOUT": "20h"}, nil, budgets[i])
		}(i)
	}
	wg.Wait()
	if !errors.Is(results[0].err, ErrInvokeDeadline) || results[0].code != -1 {
		t.Fatalf("short job did not use its own Go deadline: %+v", results[0])
	}
	if !strings.Contains(results[0].err.Error(), "1s") {
		t.Fatalf("diagnosis does not report effective budget: %v", results[0].err)
	}
	if results[1].err != nil || results[1].code != 0 || results[1].out != "long-job" {
		t.Fatalf("long job inherited another timeout: %+v", results[1])
	}
	if got := os.Getenv("VULSCAN_INVOKE_TIMEOUT"); got != "100ms" {
		t.Fatalf("per-call budget mutated process environment: %q", got)
	}
}

func TestInvokeCtxCaptureEnvTimeoutRejectsInvalidBeforeSpawn(t *testing.T) {
	for _, budget := range []time.Duration{0, -time.Second} {
		_, _, err := InvokeCtxCaptureEnvTimeout(context.Background(), "/must-not-spawn", nil, "", nil, nil, budget)
		if err == nil || !strings.Contains(err.Error(), "timeout must be positive") {
			t.Fatalf("budget %v was not rejected before spawn: %v", budget, err)
		}
	}
}
