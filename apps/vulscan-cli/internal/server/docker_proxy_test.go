package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestDockerProxyValidationAndPersistence(t *testing.T) {
	isolatedModelConfig(t)
	for _, tc := range []struct{ host, port, want string }{
		{"", "", ""}, {"127.0.0.1", "7890", "http://127.0.0.1:7890"},
		{"::1", "7890", "http://[::1]:7890"}, {"192.168.1.2", "8080", "http://192.168.1.2:8080"},
		{"127.0.0.1", "", "invalid"}, {"", "7890", "invalid"},
		{"localhost", "7890", "invalid"}, {"127.0.0.1", "65536", "invalid"},
		{"0.0.0.0", "7890", "invalid"}, {"127.0.0.1/path", "7890", "invalid"},
	} {
		t.Run(tc.host+":"+tc.port, func(t *testing.T) {
			s, err := New("unused", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for n := 0; n < cap(s.sem); n++ {
				s.sem <- struct{}{}
			}
			w := httptest.NewRecorder()
			s.handleStartScan(w, modelRequest(t, url.Values{"csrf": {s.csrfToken}, "repo": {"/authorized/project"},
				"provider": {"configured"}, "docker_proxy_ip": {tc.host}, "docker_proxy_port": {tc.port}}))
			if tc.want == "invalid" {
				if w.Code != http.StatusBadRequest || len(s.mgr.all()) != 0 {
					t.Fatalf("invalid proxy accepted: %d", w.Code)
				}
				return
			}
			if w.Code != http.StatusSeeOther {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			j := s.mgr.all()[0]
			j.Cancel()
			<-j.done
			if j.dockerProxy != tc.want {
				t.Fatalf("proxy=%q", j.dockerProxy)
			}
			var meta jobMeta
			data, err := os.ReadFile(filepath.Join(s.outDir, j.ID, "meta.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &meta); err != nil || meta.DockerProxy != tc.want {
				t.Fatalf("metadata: %s %v", data, err)
			}
			reloaded, err := New("unused", s.outDir)
			if err != nil {
				t.Fatal(err)
			}
			restored, ok := reloaded.mgr.get(j.ID)
			if !ok || restored.dockerProxy != tc.want {
				t.Fatal("proxy lost on restart")
			}
		})
	}
}

func TestRunJobForwardsProxyToActualProcess(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "python-stub")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >&2\nexit 2\n"), 0700); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: dir, pythonPath: script, mgr: newManager(dir), sem: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	j := &Job{ID: "aabbccddeeff0011", Repo: dir, Status: StatusRunning, ctx: ctx, Cancel: cancel,
		done: make(chan struct{}), dynamicTest: true, dockerProxy: "http://127.0.0.1:7890"}
	s.wg.Add(1)
	go s.runJob(j)
	<-j.done
	for _, line := range j.LogBuf {
		if line == "--docker-proxy=http://127.0.0.1:7890" {
			return
		}
	}
	t.Fatalf("proxy did not reach subprocess: %v", j.LogBuf)
}
