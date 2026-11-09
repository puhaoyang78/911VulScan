package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
)

// The securityHeaders middleware must reject a non-loopback Host on EVERY route
// (DNS-rebinding guard), while loopback and private IP Hosts pass through.
func TestMiddlewareRejectsRebindingHost(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := securityHeaders(ok)
	for _, host := range []string{"evil.example.com", "evil.com:8080", "attacker.test", "127.0.0.1.evil.com:8080", "10.10.249.210.evil.com:8080", "8.8.8.8:8080", "0.0.0.0:8080"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Errorf("foreign Host %q = %d, want 403 (rebinding read not closed)", host, rec.Code)
		}
	}
	// Loopback and private IPv4 literals pass; DNS names and public IPs do not.
	for _, host := range []string{"127.0.0.1:8080", "localhost:8080", "LOCALHOST:8080", "[::1]:8080", "127.0.0.2:8080", "127.0.0.9:8080", "10.10.249.210:8080", "192.168.1.30:8080", "172.16.0.2:8080"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == 403 {
			t.Errorf("loopback Host %q wrongly 403'd", host)
		}
	}
}

func TestOpenerPolicyMatchesBrowserOrigin(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	for _, tc := range []struct {
		name, target, external, policy string
	}{
		{"loopback", "http://127.0.0.1:8080/", "", "same-origin"},
		{"localhost", "http://LOCALHOST:8080/", "", "same-origin"},
		{"other loopback", "http://127.0.0.2:8080/", "", "same-origin"},
		{"LAN HTTP", "http://192.168.1.30:8080/", "", ""},
		{"LAN HTTPS", "https://192.168.1.30:8080/", "", "same-origin"},
		{"HTTPS proxy", "http://scan.example.com/", "https://scan.example.com", "same-origin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if tc.external != "" {
				req = req.WithContext(context.WithValue(req.Context(), externalOriginKey{}, tc.external))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			if got := rec.Header().Get("Cross-Origin-Opener-Policy"); got != tc.policy {
				t.Errorf("opener policy = %q, want %q", got, tc.policy)
			}
			if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'none'") || !strings.Contains(got, "frame-ancestors 'none'") {
				t.Errorf("CSP was relaxed: %q", got)
			}
			if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("frame protection = %q", got)
			}
		})
	}
}

// sameOriginOK (the CSRF gate for mutations) must reject a missing token's
// preconditions: foreign Host, cross-site Sec-Fetch-Site, and a foreign Origin.
func TestSameOriginOKRejections(t *testing.T) {
	mk := func(host, sfs, origin string) *http.Request {
		r := httptest.NewRequest("POST", "/scan", nil)
		r.Host = host
		if sfs != "" {
			r.Header.Set("Sec-Fetch-Site", sfs)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}
	if sameOriginOK(mk("evil.com", "", "")) {
		t.Error("foreign Host accepted by sameOriginOK")
	}
	if sameOriginOK(mk("127.0.0.1:8080", "cross-site", "")) {
		t.Error("cross-site Sec-Fetch-Site accepted")
	}
	if sameOriginOK(mk("127.0.0.1:8080", "", "http://evil.com")) {
		t.Error("foreign Origin accepted")
	}
	if !sameOriginOK(mk("127.0.0.1:8080", "same-origin", "http://127.0.0.1:8080")) {
		t.Error("legitimate same-origin request wrongly rejected")
	}
	if !sameOriginOK(mk("10.10.249.210:8080", "same-origin", "http://10.10.249.210:8080")) {
		t.Error("LAN same-origin request wrongly rejected")
	}
	if sameOriginOK(mk("10.10.249.210:8080", "cross-site", "")) {
		t.Error("cross-site LAN request accepted")
	}
	if sameOriginOK(mk("10.10.249.210:8080", "", "http://10.10.249.211:8080")) {
		t.Error("foreign LAN Origin accepted")
	}
}

// An http(s) repo URL carrying userinfo must be rejected (it would be logged
// verbatim in meta.json/logs.txt/SSE/argv). Loopback Host + valid CSRF so the
// request reaches the credential check.
func TestRejectCredsInRepoURL(t *testing.T) {
	s := &Server{outDir: t.TempDir(), mgr: newManager(t.TempDir()), csrfToken: "tok", sem: make(chan struct{}, 4), shutdownDone: make(chan struct{})}
	req := httptest.NewRequest("POST", "/scan", formBody("csrf=tok&repo=https://user:secret@example.com/r.git"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.handleStartScan(rec, req)
	if rec.Code != 400 {
		t.Errorf("repo URL with credentials = %d, want 400", rec.Code)
	}
	if n := len(s.mgr.all()); n != 0 {
		t.Errorf("credential-bearing URL created %d job(s)", n)
	}
	// A malformed credential URL (bad %-escape) must ALSO be rejected (fail closed),
	// not slip past url.Parse into the logs.
	req2 := httptest.NewRequest("POST", "/scan", formBody("csrf=tok&repo=https://user:sec%ZZ@example.com/r.git"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Host = "127.0.0.1"
	rec2 := httptest.NewRecorder()
	s.handleStartScan(rec2, req2)
	if rec2.Code != 400 {
		t.Errorf("malformed credential URL = %d, want 400 (fail closed)", rec2.Code)
	}
}

func TestExplicitLANListenerUsesIPv4(t *testing.T) {
	srv := &Server{mgr: newManager(t.TempDir()), shutdownDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	addr, err := srv.Start(ctx, "0.0.0.0:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if !strings.HasPrefix(addr, "http://0.0.0.0:") {
		t.Errorf("LAN listener address = %q, want IPv4 wildcard", addr)
	}
	cancel()
	srv.WaitShutdown()
}

func TestRequestedListenerNeverChangesOccupiedPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	srv := &Server{mgr: newManager(t.TempDir()), shutdownDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	url, err := srv.Start(ctx, listener.Addr().String())
	if err == nil {
		cancel()
		srv.WaitShutdown()
		t.Fatalf("occupied address silently changed to %q", url)
	}
	if url != "" || !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("occupied address: url=%q err=%v", url, err)
	}
	// A failed bind must leave the same server usable for an explicit retry.
	url, err = srv.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Errorf("retry listener = %q", url)
	}
	cancel()
	srv.WaitShutdown()
}
