package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/config"
)

const testPassword = "Strong-test-password-2026"

func realClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func httpCall(t *testing.T, c *http.Client, method, uri string, form url.Values, token string) (int, string, http.Header) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequest(method, uri, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if token != "" {
		r.Header.Set("X-CSRF-Token", token)
	}
	resp, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(data), resp.Header
}
func signIn(t *testing.T, c *http.Client, base, mode, name string) {
	t.Helper()
	code, body, _ := httpCall(t, c, "GET", base+"/"+mode, nil, "")
	if code != 200 {
		t.Fatalf("auth page %s: %d %s", mode, code, body)
	}
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(body)
	if len(m) != 2 {
		t.Fatal("missing guest CSRF")
	}
	values := url.Values{"username": {name}, "password": {testPassword}, "csrf": {m[1]}}
	code, body, _ = httpCall(t, c, "POST", base+"/"+mode, values, "")
	if code != 303 {
		t.Fatalf("%s: %d %s", mode, code, body)
	}
}
func currentAccount(t *testing.T, c *http.Client, base string) map[string]any {
	t.Helper()
	code, body, _ := httpCall(t, c, "GET", base+"/account", nil, "")
	var data map[string]any
	if code != 200 || json.Unmarshal([]byte(body), &data) != nil {
		t.Fatalf("account: %d %s", code, body)
	}
	return data
}
func userModel(t *testing.T, c *http.Client, base, key string) {
	t.Helper()
	token := currentAccount(t, c, base)["csrf"].(string)
	code, body, _ := httpCall(t, c, "POST", base+"/settings", url.Values{"provider": {"deepseek"}, "model": {"deepseek-flash"}, "api_key": {key}}, token)
	if code != 303 {
		t.Fatalf("save model: %d %s", code, body)
	}
	code, body, _ = httpCall(t, c, "GET", base+"/settings", nil, "")
	if code != 200 || strings.Contains(body, key) || !strings.Contains(body, "已保存密钥") {
		t.Fatalf("settings exposed key or failed: %d", code)
	}
}

func TestDirectRegistrationWithoutAdministrator(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("DEEPSEEK_API_KEY", "operator-environment-key")
	if err := config.Save(&config.Config{APIKey: "operator-cli-private-key"}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	const legacyID = "1111222233334444"
	legacyDir := filepath.Join(root, legacyID)
	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"repo":"unowned-private-history","status":"done"}`)
	if err := os.WriteFile(filepath.Join(legacyDir, "meta.json"), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New("unused", root)
	if err != nil {
		t.Fatal(err)
	}
	service := httptest.NewServer(s.Handler())
	defer func() { service.Close() }()
	alice, bob := realClient(t), realClient(t)
	req, _ := http.NewRequest("GET", service.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	response, err := alice.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 303 || response.Header.Get("Location") != "/register?next=%2F" {
		t.Fatal("first visit did not open registration")
	}
	code, body, _ := httpCall(t, alice, "GET", service.URL+"/register", nil, "")
	if code != 200 || !strings.Contains(body, "注册并登录") || strings.Contains(body, "初始化口令") || strings.Contains(body, "创建管理员") {
		t.Fatal("registration still requires administrator setup")
	}
	for _, method := range []string{"GET", "POST"} {
		code, _, _ = httpCall(t, alice, method, service.URL+"/setup", nil, "")
		if code != 404 {
			t.Fatal("obsolete administrator setup is still reachable")
		}
	}
	var registrations sync.WaitGroup
	for name, client := range map[string]*http.Client{"alice": alice, "bob": bob} {
		registrations.Add(1)
		go func() { defer registrations.Done(); signIn(t, client, service.URL, "register", name) }()
	}
	registrations.Wait()
	if s.accounts.state.AdminID != "" || len(s.accounts.state.Users) != 2 {
		t.Fatal("registration created an administrator or lost a concurrent account")
	}
	for _, client := range []*http.Client{alice, bob} {
		if currentAccount(t, client, service.URL)["admin"] != false {
			t.Fatal("registration granted legacy administrator access")
		}
		code, body, _ = httpCall(t, client, "GET", service.URL+"/", nil, "")
		if code != 200 || strings.Contains(body, "unowned-private-history") {
			t.Fatal("unowned history leaked to a new registration")
		}
		for _, path := range []string{"/scan/", "/report/", "/summary/", "/disclosures/"} {
			code, _, _ = httpCall(t, client, "GET", service.URL+path+legacyID, nil, "")
			if code != 404 {
				t.Fatalf("unowned history exposed at %s: %d", path, code)
			}
		}
		u := s.accounts.resolve(sessionValue(t, client, service.URL))
		cfg, err := config.LoadFrom(u.ConfigPath)
		if err != nil || cfg.APIKey != "" || len(cfg.ProviderNames()) != 0 {
			t.Fatal("registration inherited the service model configuration")
		}
	}
	if _, err = os.Stat(filepath.Join(s.accounts.dir, "bootstrap-token")); !os.IsNotExist(err) {
		t.Fatal("fresh registration still creates an initialization token")
	}
	// Stale tokens from the old release no longer control service startup.
	if err = os.WriteFile(filepath.Join(s.accounts.dir, "bootstrap-token"), []byte("obsolete"), 0600); err != nil {
		t.Fatal(err)
	}
	service.Close()
	restarted, err := New("unused", root)
	if err != nil {
		t.Fatal(err)
	}
	service = httptest.NewServer(restarted.Handler())
	for name, client := range map[string]*http.Client{"alice": alice, "bob": bob} {
		if currentAccount(t, client, service.URL)["username"] != name {
			t.Fatal("account or session lost after restarting without an administrator")
		}
	}
	if saved, err := os.ReadFile(filepath.Join(legacyDir, "meta.json")); err != nil || string(saved) != string(legacy) {
		t.Fatal("unowned history was changed or removed")
	}
	operator, err := config.Load()
	if err != nil || operator.APIKey != "operator-cli-private-key" {
		t.Fatal("registration changed the service configuration")
	}
}

func TestMultiUserConcurrentHTTPAndRestart(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ANTHROPIC_API_KEY", "operator-anthropic-secret")
	t.Setenv("OPENAI_API_KEY", "operator-openai-secret")
	t.Setenv("DEEPSEEK_API_KEY", "")
	t.Setenv("DOCKER_CONFIG", "/operator/docker-config")
	root := t.TempDir()
	t.Setenv("VULSCAN_TEST_ROOT", root)
	gitDir := t.TempDir()
	gitBytes, err := os.ReadFile("testdata/multiuser/git.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(gitDir, "git"), gitBytes, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", gitDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	script, err := filepath.Abs("testdata/multiuser/scanner.py")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(root, "webui")
	const legacyID = "1111222233334444"
	legacyDir := filepath.Join(dataDir, legacyID)
	if err = os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(legacyDir, "meta.json"), []byte(`{"repo":"legacy-private-project","status":"done"}`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(script, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	// Existing installations retain their already-created legacy owner. New
	// registrations below must neither replace that owner nor inherit its data.
	legacyUser := account{ID: secretToken()[:32], Username: "admin", Salt: secretToken(), CreatedAt: time.Now().UTC()}
	legacyUser.PasswordHash = passwordKey(testPassword, legacyUser.Salt)
	if err = s.createUserConfig(legacyUser.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.accounts.updateLocked(func(st *accountState) {
		st.Users[legacyUser.ID] = legacyUser
		st.AdminID = legacyUser.ID
	}); err != nil {
		t.Fatal(err)
	}
	service := httptest.NewServer(s.Handler())
	defer func() { service.Close() }()
	base := service.URL
	admin := realClient(t)
	signIn(t, admin, base, "login", "admin")
	code, _, _ := httpCall(t, admin, "GET", base+"/scan/"+legacyID, nil, "")
	if code != 200 {
		t.Fatal("legacy task not inherited")
	}
	alice, bob := realClient(t), realClient(t)
	var registrations sync.WaitGroup
	for name, client := range map[string]*http.Client{"alice": alice, "bob": bob} {
		registrations.Add(1)
		go func() { defer registrations.Done(); signIn(t, client, base, "register", name) }()
	}
	registrations.Wait()
	userModel(t, alice, base, "alice-private-model-key")
	userModel(t, bob, base, "bob-private-model-key")
	for _, client := range []*http.Client{alice, bob} {
		code, body, _ := httpCall(t, client, "GET", base+"/", nil, "")
		if code != 200 || strings.Contains(body, "legacy-private-project") || strings.Contains(body, legacyID) {
			t.Fatal("legacy data leaked")
		}
		code, _, _ = httpCall(t, client, "GET", base+"/scan/"+legacyID, nil, "")
		if code != 404 {
			t.Fatal("legacy IDOR")
		}
		code, _, _ = httpCall(t, client, "GET", base+"/internal/status", nil, "")
		if code != 401 {
			t.Fatal("operator status exposed")
		}
	}
	clients := []*http.Client{alice, bob}
	tokens := []string{currentAccount(t, alice, base)["csrf"].(string), currentAccount(t, bob, base)["csrf"].(string)}
	ids := make([]string, 2)
	var starts sync.WaitGroup
	for i, client := range clients {
		starts.Add(1)
		go func() {
			defer starts.Done()
			code, body, headers := httpCall(t, client, "POST", base+"/scan", url.Values{"repo": {"https://192.0.2.20/project-" + []string{"alice", "bob"}[i]}, "provider": {"configured"}}, tokens[i])
			if code != 303 {
				t.Errorf("start: %d %s", code, body)
				return
			}
			ids[i] = strings.TrimPrefix(headers.Get("Location"), "/scan/")
		}()
	}
	starts.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for {
		files, _ := filepath.Glob(filepath.Join(root, "*.started.json"))
		if len(files) == 2 {
			break
		}
		if time.Now().After(deadline) {
			for _, j := range s.mgr.all() {
				j.mu.Lock()
				t.Log(j.Status, j.LogBuf)
				j.mu.Unlock()
			}
			t.Fatal("two scanner subprocesses did not run concurrently")
		}
		time.Sleep(50 * time.Millisecond)
	}
	owners := map[string]bool{}
	for i, id := range ids {
		b, err := os.ReadFile(filepath.Join(root, id+".started.json"))
		if err != nil {
			t.Fatal(err)
		}
		var trace map[string]any
		if json.Unmarshal(b, &trace) != nil {
			t.Fatal("trace")
		}
		key := []string{"alice-private-model-key", "bob-private-model-key"}[i]
		digest := sha256.Sum256([]byte(key))
		if trace["key_sha256"] != hex.EncodeToString(digest[:]) || trace["inherited_anthropic"] != "" || trace["inherited_openai"] != "" || trace["dotenv_disabled"] != "1" || trace["docker_config"] != "/operator/docker-config" {
			t.Fatalf("model/environment isolation failed: %s", b)
		}
		owner := trace["docker_owner"].(string)
		if owners[owner] {
			t.Fatal("Docker owners shared")
		}
		owners[owner] = true
		code, body, _ := httpCall(t, clients[i], "GET", base+"/scan/"+id+"/snapshot", nil, "")
		var snap jobSnapshot
		json.Unmarshal([]byte(body), &snap)
		if code != 200 || snap.Counts["candidates"] == nil || *snap.Counts["candidates"] != 1 {
			t.Fatalf("duplicate events counted: %d %s", code, body)
		}
		for _, path := range []string{"/scan/" + id, "/scan/" + id + "/snapshot", "/scan/" + id + "/events", "/scan/" + id + "/logs", "/scan/" + id + "/logs.txt", "/report/" + id, "/summary/" + id, "/disclosures/" + id, "/disclosure/" + id + "/DISCLOSURE_01.md"} {
			code, _, _ = httpCall(t, clients[1-i], "GET", base+path, nil, "")
			if code != 404 {
				t.Errorf("IDOR %s: %d", path, code)
			}
		}
		for _, action := range []struct{ method, path string }{{"POST", "/scan/" + id + "/cancel"}, {"DELETE", "/scan/" + id}} {
			code, _, _ = httpCall(t, clients[1-i], action.method, base+action.path, nil, tokens[1-i])
			if code != 404 {
				t.Errorf("mutation IDOR: %d", code)
			}
		}
		// Establish a real, streamed SSE connection, then cancel only that read.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", base+"/scan/"+id+"/events", nil)
		resp, err := clients[i].Do(req)
		if err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		resp.Body.Close()
		cancel()
		if err != nil || !strings.Contains(line, "event: snapshot") {
			t.Fatal("SSE did not stream")
		}
	}
	if err = os.WriteFile(filepath.Join(root, "release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if !s.waitForJobs(10 * time.Second) {
		t.Fatal("jobs did not finish")
	}
	for _, id := range ids {
		j, _ := s.mgr.get(id)
		j.mu.Lock()
		if j.Status != StatusDone {
			t.Errorf("job failed: %s %v", j.Status, j.LogBuf)
		}
		j.mu.Unlock()
	}
	service.Close()
	recovered, err := New(script, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	service = httptest.NewServer(recovered.Handler())
	base = service.URL
	code, _, _ = httpCall(t, admin, "GET", base+"/scan/"+legacyID, nil, "")
	if code != 200 {
		t.Fatal("existing legacy owner lost access after restart")
	}
	// The listener may change port; host-only session cookies remain valid.
	for i, c := range clients {
		if currentAccount(t, c, base)["username"] != []string{"alice", "bob"}[i] {
			t.Fatal("session lost across restart")
		}
		code, body, _ := httpCall(t, c, "GET", base+"/", nil, "")
		if code != 200 || !strings.Contains(body, ids[i]) || strings.Contains(body, ids[1-i]) {
			t.Fatal("restored history isolation")
		}
		for _, path := range []string{"/report/" + ids[i], "/summary/" + ids[i], "/disclosures/" + ids[i], "/disclosure/" + ids[i] + "/DISCLOSURE_01.md", "/scan/" + ids[i] + "/logs.txt"} {
			code, _, _ = httpCall(t, c, "GET", base+path, nil, "")
			if code != 200 {
				t.Errorf("restored artifact %s: %d", path, code)
			}
		}
		code, _, _ = httpCall(t, c, "POST", base+"/scan/"+ids[i]+"/cancel", nil, "")
		if code != 403 {
			t.Fatal("missing CSRF accepted")
		}
		code, _, _ = httpCall(t, c, "POST", base+"/scan", url.Values{"repo": {"/var/lib/vulscan/.vulscan/webui"}}, tokens[i])
		if code != 400 {
			t.Fatal("member local filesystem scan accepted")
		}
	}
	code, _, _ = httpCall(t, alice, "DELETE", base+"/scan/"+ids[0], nil, tokens[0])
	if code != 204 {
		t.Fatal("owner delete failed")
	}
	code, _, _ = httpCall(t, bob, "GET", base+"/scan/"+ids[1]+"/snapshot", nil, "")
	if code != 200 {
		t.Fatal("delete affected other user")
	}
	code, _, _ = httpCall(t, alice, "POST", base+"/logout", nil, tokens[0])
	if code != 303 {
		t.Fatal("logout")
	}
	code, _, _ = httpCall(t, alice, "GET", base+"/account", nil, "")
	if code != 401 {
		t.Fatal("logout not revoked")
	}
	// Disk stores password derivatives and token hashes, never raw passwords/cookies.
	stored, err := os.ReadFile(filepath.Join(dataDir, ".access/accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), testPassword) {
		t.Fatal("plaintext password persisted")
	}
	for _, c := range bob.Jar.Cookies(mustURL(t, base)) {
		if c.Name == sessionCookie && strings.Contains(string(stored), c.Value) {
			t.Fatal("session token persisted unhashed")
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, e := url.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	return u
}

func TestAccountSecurityAndSessionRevocation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	s, err := New("unused", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := httptest.NewServer(s.Handler())
	defer service.Close()
	base := service.URL
	client := realClient(t)
	// Direct registration still rejects login CSRF and session fixation.
	code, _, _ := httpCall(t, client, "POST", base+"/register", url.Values{"username": {"attacker"}, "password": {testPassword}}, "")
	if code != 403 || s.accounts.hasUsers() {
		t.Fatal("registration accepted without CSRF")
	}
	signIn(t, client, base, "register", "member")
	second := realClient(t)
	signIn(t, second, base, "login", "MEMBER")
	for _, c := range []*http.Client{client, second} {
		if currentAccount(t, c, base)["username"] != "member" {
			t.Fatal("case insensitive account failed")
		}
	}
	firstToken := currentAccount(t, client, base)["csrf"].(string)
	otherToken := currentAccount(t, second, base)["csrf"].(string)
	if firstToken == otherToken {
		t.Fatal("CSRF tokens shared between sessions")
	}
	code, _, _ = httpCall(t, client, "POST", base+"/logout", nil, otherToken)
	if code != 403 {
		t.Fatal("other session CSRF accepted")
	}
	for _, origin := range []string{"http://evil.example", "https://" + strings.TrimPrefix(base, "http://")} {
		r, _ := http.NewRequest("POST", base+"/logout", nil)
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", firstToken)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatal("foreign origin accepted")
		}
	}
	// Revocation terminates an already established SSE stream, not just new GETs.
	u := s.accounts.resolve(sessionValue(t, second, base))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	j := &Job{ID: "aabbccdd11223344", OwnerID: u.User.ID, Repo: "fixture", Status: StatusRunning, ctx: ctx, StartedAt: time.Now()}
	s.mgr.add(j)
	resp, err := second.Get(base + "/scan/" + j.ID + "/events")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(resp.Body)
	if line, _ := reader.ReadString('\n'); !strings.Contains(line, "event: snapshot") {
		t.Fatal("SSE not open")
	}
	code, body, _ := httpCall(t, client, "POST", base+"/settings", url.Values{"action": {"password"}, "current_password": {testPassword}, "new_password": {"Another-strong-password-2026"}}, firstToken)
	if code != 303 {
		t.Fatalf("password update: %d %s", code, body)
	}
	if _, err = io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	code, _, _ = httpCall(t, second, "GET", base+"/account", nil, "")
	if code != 401 {
		t.Fatal("password change did not revoke other session")
	}
	if currentAccount(t, client, base)["username"] != "member" {
		t.Fatal("current session unexpectedly revoked")
	}
	oldCookie := sessionValue(t, client, base)
	code, _, _ = httpCall(t, client, "POST", base+"/logout", nil, firstToken)
	if code != 303 {
		t.Fatal("logout failed")
	}
	restarted, err := New("unused", s.outDir)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.accounts.resolve(oldCookie) != nil {
		t.Fatal("logout resurrected on restart")
	}
	for _, name := range []string{"accounts.json", "operator-token"} {
		info, err := os.Stat(filepath.Join(s.accounts.dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("secret permissions: %s %v", name, err)
		}
	}
	// Operator requests carry a separate, server-local credential; user cookies
	// are never sufficient, including those of the administrator.
	req, _ := http.NewRequest("GET", base+"/internal/status", nil)
	req.Header.Set("Authorization", "Bearer "+s.accounts.operatorToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var status map[string]any
	json.NewDecoder(res.Body).Decode(&status)
	if res.StatusCode != 200 || status["running"] != float64(1) {
		t.Fatalf("operator queue status: %v", status)
	}
}

func sessionValue(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	for _, cookie := range c.Jar.Cookies(mustURL(t, base)) {
		if cookie.Name == sessionCookie {
			return cookie.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func TestHTTPSCookieAndAuthStoreFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	s, err := New("unused", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := httptest.NewTLSServer(s.Handler())
	defer service.Close()
	if err = s.ConfigureExternalURL(service.URL); err != nil {
		t.Fatal(err)
	}
	client := realClient(t)
	client.Transport = service.Client().Transport
	signIn(t, client, service.URL, "register", "member")
	if currentAccount(t, client, service.URL)["username"] != "member" {
		t.Fatal("TLS session failed")
	}
	w := httptest.NewRecorder()
	u := s.accounts.resolve(sessionValue(t, client, service.URL))
	if err = s.issueSession(w, u.User); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.Path != "/" {
			t.Fatal("insecure session cookie")
		}
	}
	// Canonical reverse-proxy domains are opt-in. Forwarded headers cannot
	// enable a different host or bypass the scheme check.
	if err = s.ConfigureExternalURL("http://scan.example.com"); err == nil {
		t.Fatal("public HTTP origin accepted")
	}
	if err = s.ConfigureExternalURL("https://scan.example.com"); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]int{"scan.example.com": 200, "attacker.example.com": 403} {
		req := httptest.NewRequest("GET", "/login", nil)
		req.Host = host
		req.Header.Set("X-Forwarded-Host", "scan.example.com")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("host %s: %d", host, rec.Code)
		}
	}
	if err = os.WriteFile(filepath.Join(s.accounts.dir, "accounts.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = New("unused", s.outDir); err == nil {
		t.Fatal("corrupt account database silently reset")
	}
}
