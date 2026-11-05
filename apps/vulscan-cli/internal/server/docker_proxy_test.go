package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestDockerProxyDefaultsArePrivateAndSurviveRestart(t *testing.T) {
	isolatedModelConfig(t)
	root := t.TempDir()
	s, err := New("unused", root)
	if err != nil {
		t.Fatal(err)
	}
	// Keep real HTTP submissions queued; no repository, model or Docker runs.
	for n := 0; n < cap(s.sem); n++ {
		s.sem <- struct{}{}
	}
	service := httptest.NewServer(s.Handler())
	defer func() { service.Close(); s.mgr.cancelAll(); s.wg.Wait() }()
	alice, bob := realClient(t), realClient(t)
	for name, client := range map[string]*http.Client{"alice": alice, "bob": bob} {
		signIn(t, client, service.URL, "register", name)
		userModel(t, client, service.URL, "fixture-key-"+name)
	}
	check := func(client *http.Client, host, port string) {
		t.Helper()
		code, body, _ := httpCall(t, client, "GET", service.URL+"/", nil, "")
		if code != 200 {
			t.Fatalf("index: %d", code)
		}
		for id, want := range map[string]string{"docker-proxy-ip": host, "docker-proxy-port": port} {
			field := regexp.MustCompile(`<input[^>]*id="` + id + `"[^>]*value="([^"]*)"`).FindStringSubmatch(body)
			if len(field) != 2 || field[1] != want {
				t.Fatalf("%s: got %v, want %q", id, field, want)
			}
		}
	}
	submit := func(client *http.Client, host, port string, want int) string {
		t.Helper()
		token := currentAccount(t, client, service.URL)["csrf"].(string)
		code, _, headers := httpCall(t, client, "POST", service.URL+"/scan", url.Values{
			"repo": {"https://example.com/fixture.git"}, "provider": {"configured"},
			"docker_proxy_ip": {host}, "docker_proxy_port": {port},
		}, token)
		if code != want {
			t.Fatalf("submit: %d, want %d", code, want)
		}
		if code != http.StatusSeeOther {
			return ""
		}
		id := filepath.Base(headers.Get("Location"))
		j, ok := s.mgr.get(id)
		if !ok || j.dynamicTest {
			t.Fatal("proxy settings enabled dynamic tests or lost the queued job")
		}
		j.Cancel()
		<-j.done
		return id
	}
	deleteJob := func(client *http.Client, id string) {
		t.Helper()
		token := currentAccount(t, client, service.URL)["csrf"].(string)
		code, _, _ := httpCall(t, client, "DELETE", service.URL+"/scan/"+id, nil, token)
		if code != http.StatusNoContent {
			t.Fatalf("delete: %d", code)
		}
	}
	check(alice, "", "")
	owner := s.accounts.resolve(sessionValue(t, alice, service.URL)).User.ID
	s.mgr.add(&Job{ID: "old-proxy", OwnerID: owner, Status: StatusDone,
		StartedAt: time.Now().Add(-2 * time.Hour), dockerProxy: "http://127.0.0.1:7890"})
	check(alice, "127.0.0.1", "7890")
	check(bob, "", "") // Existing history must not initialize another user's proxy.
	s.mgr.add(&Job{ID: "old-empty", OwnerID: owner, Status: StatusDone, StartedAt: time.Now().Add(-time.Hour)})
	check(alice, "", "") // The latest empty choice must not revive an older proxy.
	s.mgr.remove("old-empty")
	s.mgr.remove("old-proxy")
	first := submit(alice, "127.0.0.1", "7891", http.StatusSeeOther)
	submit(bob, "::1", "7892", http.StatusSeeOther)
	check(alice, "127.0.0.1", "7891")
	check(bob, "::1", "7892")
	submit(alice, "127.0.0.1", "", http.StatusBadRequest)
	check(alice, "127.0.0.1", "7891")
	service.Close()
	s.wg.Wait()
	s, err = New("unused", root)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < cap(s.sem); n++ {
		s.sem <- struct{}{}
	}
	service = httptest.NewServer(s.Handler())
	check(alice, "127.0.0.1", "7891")
	check(bob, "::1", "7892")
	alice = realClient(t)
	signIn(t, alice, service.URL, "login", "alice")
	check(alice, "127.0.0.1", "7891")
	deleteJob(alice, first)
	check(alice, "127.0.0.1", "7891")
	cleared := submit(alice, "", "", http.StatusSeeOther)
	deleteJob(alice, cleared)
	check(alice, "", "")
	check(bob, "::1", "7892")
	restored, err := openAccounts(root)
	if err != nil {
		t.Fatal(err)
	}
	u := restored.resolve(sessionValue(t, alice, service.URL))
	if u == nil || u.User.DockerProxy == nil || *u.User.DockerProxy != "" {
		t.Fatal("explicitly cleared proxy was not persisted")
	}
}

func TestDockerProxyPreferenceWriteFailureKeepsPreviousValue(t *testing.T) {
	a, err := openAccounts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a.state.Users["fixture"] = account{ID: "fixture"}
	if err := a.saveScanDefaults("fixture", "http://127.0.0.1:7890", scanOptions{DynamicTest: true}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.dir, "accounts.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.saveScanDefaults("fixture", "http://127.0.0.1:7891", scanOptions{DynamicTest: false}); err == nil {
		t.Fatal("failed persistence was reported as success")
	}
	if got := a.state.Users["fixture"].DockerProxy; got == nil || *got != "http://127.0.0.1:7890" {
		t.Fatal("failed persistence changed the visible preference")
	}
	if got := a.state.Users["fixture"].ScanOptions; got == nil || !got.DynamicTest {
		t.Fatal("failed persistence changed the visible scan options")
	}
}

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

func TestTeachingScanOptionPersistsAcrossRestart(t *testing.T) {
	isolatedModelConfig(t)
	for _, enabled := range []bool{false, true} {
		s, err := New("unused", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		for n := 0; n < cap(s.sem); n++ {
			s.sem <- struct{}{}
		}
		form := url.Values{"csrf": {s.csrfToken}, "repo": {"/authorized/project"}, "provider": {"configured"}}
		if enabled {
			form.Set("include_intentional", "on")
		}
		w := httptest.NewRecorder()
		s.handleStartScan(w, modelRequest(t, form))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		j := s.mgr.all()[0]
		j.Cancel()
		<-j.done
		reloaded, err := New("unused", s.outDir)
		if err != nil {
			t.Fatal(err)
		}
		restored, ok := reloaded.mgr.get(j.ID)
		if !ok || j.includeIntentional != enabled || restored.includeIntentional != enabled {
			t.Fatalf("teaching scan option lost: enabled=%t", enabled)
		}
	}
}

func TestRunJobForwardsProxyToActualProcess(t *testing.T) {
	t.Setenv("VULSCAN_DOCKER_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	dir := t.TempDir()
	script := filepath.Join(dir, "python-stub")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >&2\nexit 2\n"), 0700); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: dir, pythonPath: script, mgr: newManager(dir), sem: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	j := &Job{ID: "aabbccddeeff0011", Repo: dir, Status: StatusRunning, ctx: ctx, Cancel: cancel,
		done: make(chan struct{}), dynamicTest: true, dockerProxy: "http://127.0.0.1:7890", includeIntentional: true}
	s.wg.Add(1)
	go s.runJob(j)
	<-j.done
	proxyForwarded, intentionalForwarded := false, false
	for _, line := range j.LogBuf {
		if line == "--docker-proxy=http://127.0.0.1:7890" {
			proxyForwarded = true
		}
		if line == "--include-intentional" {
			intentionalForwarded = true
		}
	}
	if !proxyForwarded || !intentionalForwarded {
		t.Fatalf("scan options did not reach subprocess: %v", j.LogBuf)
	}
}
