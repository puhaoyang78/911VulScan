package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScanBudgetValidationAndPersistence(t *testing.T) {
	isolatedModelConfig(t)
	t.Setenv("VULSCAN_INVOKE_TIMEOUT", "1ms") // web defaults must ignore CLI override
	for _, value := range []string{"", "30m", "1h", "2h", "4h", "8h", "24h", "0", "-1h", "25h", "garbage", "1ms", "999999999999999999h"} {
		t.Run(value, func(t *testing.T) {
			s, err := New("unused", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for n := 0; n < cap(s.sem); n++ {
				s.sem <- struct{}{}
			}
			values := url.Values{"csrf": {s.csrfToken}, "repo": {"/authorized/project"}, "provider": {"configured"}}
			if value != "" {
				values.Set("scan_timeout", value)
			}
			w := httptest.NewRecorder()
			s.handleStartScan(w, modelRequest(t, values))
			want, err := parseScanTimeout(value)
			if err != nil {
				if w.Code != http.StatusBadRequest {
					t.Fatalf("invalid accepted: %d %s", w.Code, w.Body)
				}
				entries, _ := os.ReadDir(s.outDir)
				if len(s.mgr.all()) != 0 || len(entries) != 0 {
					t.Fatal("invalid input created work")
				}
				return
			}
			if w.Code != http.StatusSeeOther {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			j := s.mgr.all()[0]
			if j.scanTimeout != want {
				t.Fatalf("budget=%s want=%s", j.scanTimeout, want)
			}
			j.Cancel()
			<-j.done
			var meta jobMeta
			b, err := os.ReadFile(filepath.Join(s.outDir, j.ID, "meta.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(b, &meta); err != nil || meta.ScanTimeout != scanTimeoutValue(want) {
				t.Fatalf("metadata: %s %v", b, err)
			}
			recovered, err := New("unused", s.outDir)
			if err != nil {
				t.Fatal(err)
			}
			restored, ok := recovered.mgr.get(j.ID)
			if !ok || restored.scanTimeout != want {
				t.Fatal("budget lost on restart")
			}
			r := httptest.NewRequest("GET", "/scan/"+j.ID, nil)
			r.SetPathValue("id", j.ID)
			page := httptest.NewRecorder()
			recovered.handleScanPage(page, r)
			if !strings.Contains(page.Body.String(), scanTimeoutValue(want)) {
				t.Fatal("detail lost chosen budget")
			}
		})
	}
}

// Short internal budgets exercise the actual runner-to-Go-timer wiring without
// weakening the public form's minimum, contacting providers, or spawning Docker.
func TestRunJobSelectedBudgetReachesInvocation(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("VULSCAN_INVOKE_TIMEOUT", "1h")
	dir := t.TempDir()
	script := filepath.Join(dir, "stub")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 10\n"), 0700); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: dir, pythonPath: script, mgr: newManager(dir), sem: make(chan struct{}, 1)}
	id := "aabbccddeeff0011"
	jd := filepath.Join(dir, id)
	os.Mkdir(jd, 0750)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	j := &Job{ID: id, Repo: dir, Status: StatusRunning, ctx: ctx, Cancel: cancel, done: make(chan struct{}), scanTimeout: 60 * time.Millisecond}
	s.wg.Add(1)
	go s.runJob(j)
	select {
	case <-j.done:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("selected deadline ignored")
	}
	if j.Status != StatusTimeout {
		t.Fatalf("status=%s logs=%v", j.Status, j.LogBuf)
	}
	if ctx.Err() != nil {
		t.Fatal("invocation deadline cancelled job parent")
	}
	if len(s.sem) != 0 {
		t.Fatal("timeout did not release scan slot")
	}
}
