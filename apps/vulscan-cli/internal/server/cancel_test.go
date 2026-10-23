package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func cancelRequest(s *Server, id, token, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/scan/"+id+"/cancel", nil)
	r.SetPathValue("id", id)
	r.Host = "127.0.0.1"
	r.Header.Set("X-CSRF-Token", token)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	s.handleCancelScan(w, r)
	return w
}

func TestCancelScanPreservesQueuedJobAndPersists(t *testing.T) {
	dir := t.TempDir()
	s := &Server{outDir: dir, mgr: newManager(dir), csrfToken: "tok", sem: make(chan struct{}, 1), pythonPath: "/bin/false"}
	s.sem <- struct{}{} // queued job must never need a free execution slot
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := "abcdef0123456789"
	jd := filepath.Join(dir, id)
	if err := os.Mkdir(jd, 0750); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(jd, "meta.json"), []byte(`{"id":"abcdef0123456789"}`), 0640)
	os.WriteFile(filepath.Join(jd, "partial.json"), []byte("preserve me"), 0640)
	os.WriteFile(filepath.Join(jd, "report.html"), []byte("partial report"), 0640)
	j := &Job{ID: id, Status: StatusRunning, ctx: ctx, Cancel: cancel, done: make(chan struct{}), outDir: jd}
	j.addLog("existing log")
	s.mgr.add(j)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := cancelRequest(s, id, "tok", "")
			if w.Code != 202 {
				t.Errorf("cancel status=%d: %s", w.Code, w.Body)
			}
		}()
	}
	wg.Wait()
	if j.Status != StatusCancelling {
		t.Fatalf("premature terminal status %s", j.Status)
	}
	j.setDone("report.html", "", nil)
	j.setError()
	j.setTimeout()
	if j.Status != StatusCancelling {
		t.Fatal("runner overwrote accepted cancellation")
	}
	s.wg.Add(1)
	go s.runJob(j)
	select {
	case <-j.done:
	case <-time.After(2 * time.Second):
		t.Fatal("queued cancellation blocked on semaphore")
	}
	if j.Status != StatusCancelled {
		t.Fatalf("status=%s", j.Status)
	}
	if j.ReportPath != filepath.Join(jd, "report.html") {
		t.Fatal("partial report unavailable after cancellation")
	}
	if _, ok := s.mgr.get(id); !ok {
		t.Fatal("cancel removed job")
	}
	if b, e := os.ReadFile(filepath.Join(jd, "partial.json")); e != nil || string(b) != "preserve me" {
		t.Fatal("cancel removed artifact")
	}
	if b, e := os.ReadFile(filepath.Join(jd, "logs.txt")); e != nil || !strings.Contains(string(b), "existing log") {
		t.Fatal("logs lost")
	}
	w := cancelRequest(s, id, "tok", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "cancelled") {
		t.Fatalf("repeat terminal cancel: %d %s", w.Code, w.Body)
	}
	recovered := &Server{outDir: dir, mgr: newManager(dir)}
	recovered.recoverJobs()
	restored, ok := recovered.mgr.get(id)
	if !ok || restored.Status != StatusCancelled {
		t.Fatal("cancelled state not restored")
	}
}

func TestCancelScanGuardsAndTerminalStates(t *testing.T) {
	s := &Server{mgr: newManager(t.TempDir()), csrfToken: "tok"}
	id := "abcdef0123456789"
	for _, status := range []string{StatusDone, StatusError, StatusTimeout, StatusCancelled} {
		called := false
		j := &Job{ID: id, Status: status, Cancel: func() { called = true }}
		s.mgr.add(j)
		w := cancelRequest(s, id, "tok", "")
		var body map[string]string
		json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != 200 || body["status"] != status || called {
			t.Fatalf("terminal %s changed: %d %s", status, w.Code, w.Body)
		}
	}
	for _, tc := range []struct {
		id, token, origin string
		code              int
	}{
		{id, "bad", "", 403}, {id, "tok", "https://evil.example", 403}, {"missing", "tok", "", 404}, {"aaaaaaaaaaaaaaaa", "tok", "", 404},
	} {
		w := cancelRequest(s, tc.id, tc.token, tc.origin)
		if w.Code != tc.code {
			t.Errorf("guard got %d want %d", w.Code, tc.code)
		}
	}
}

func TestCancellingSSEWaitsForRunner(t *testing.T) {
	s := &Server{mgr: newManager(t.TempDir())}
	j := &Job{ID: "abcdef0123456789", Status: StatusCancelling, LogBuf: []string{"stopping"}}
	s.mgr.add(j)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("GET", "/scan/"+j.ID+"/logs", nil).WithContext(ctx)
	r.SetPathValue("id", j.ID)
	w := httptest.NewRecorder()
	returned := make(chan struct{})
	go func() { s.handleScanLogs(w, r); close(returned) }()
	select {
	case <-returned:
		t.Fatal("SSE treated cancelling as terminal")
	case <-time.After(250 * time.Millisecond):
	}
	j.mu.Lock()
	j.Status = StatusCancelled
	j.mu.Unlock()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("SSE did not finish")
	}
	if !strings.Contains(w.Body.String(), "event: done\ndata: cancelled") {
		t.Fatalf("wrong terminal event: %s", w.Body)
	}
}

func TestDeleteTimeoutPreservesActiveJob(t *testing.T) {
	dir := t.TempDir()
	s := &Server{outDir: dir, mgr: newManager(dir), csrfToken: "tok"}
	id := "abcdef0123456789"
	jd := filepath.Join(dir, id)
	os.Mkdir(jd, 0750)
	j := &Job{ID: id, Status: StatusCancelling, done: make(chan struct{})}
	s.mgr.add(j)
	r := httptest.NewRequest("DELETE", "/scan/"+id, nil)
	r.SetPathValue("id", id)
	r.Host = "127.0.0.1"
	r.Header.Set("X-CSRF-Token", "tok")
	w := httptest.NewRecorder()
	s.handleDeleteScan(w, r)
	if w.Code != 409 {
		t.Fatalf("status=%d want409", w.Code)
	}
	if _, ok := s.mgr.get(id); !ok {
		t.Fatal("active job removed")
	}
	if _, err := os.Stat(jd); err != nil {
		t.Fatal("active directory removed")
	}
}

func TestRecoverInterruptedCancellationNeverReportsSuccess(t *testing.T) {
	dir := t.TempDir()
	id := "abcdef0123456789"
	jd := filepath.Join(dir, id)
	os.Mkdir(jd, 0750)
	os.WriteFile(filepath.Join(jd, "meta.json"), []byte(`{"status":"cancelling"}`), 0640)
	os.WriteFile(filepath.Join(jd, "report.html"), []byte("partial"), 0640)
	s := &Server{outDir: dir, mgr: newManager(dir)}
	s.recoverJobs()
	j, _ := s.mgr.get(id)
	if j.Status != StatusError {
		t.Fatalf("interrupted cancellation status=%s", j.Status)
	}
}

// Use short injected budgets to verify both sides of shutdown's bounded drain
// without adding the production 75-second worst-case budget to every test run.
func TestShutdownDrainAwaitsRunnerAndRemainsBounded(t *testing.T) {
	s := &Server{draining: true}
	s.wg.Add(1)
	result := make(chan bool, 1)
	go func() { result <- s.waitForJobs(time.Second) }()
	select {
	case <-result:
		t.Fatal("shutdown returned while runner was cleaning")
	case <-time.After(40 * time.Millisecond):
	}
	s.wg.Done()
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("completed runner timed out")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish")
	}
	s.wg.Add(1)
	if s.waitForJobs(20 * time.Millisecond) {
		t.Fatal("wedged runner did not time out")
	}
	s.wg.Done()
}
