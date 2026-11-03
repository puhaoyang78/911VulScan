package server

import (
	"net/http"
	"testing"
	"time"
)

// Existing rendering/CSP/SSE fixtures run as an explicitly seeded administrator.
// Multi-user tests use Handler directly and real cookie jars, without this helper.
func testHandler(t *testing.T, s *Server) http.Handler {
	t.Helper()
	if s.accounts == nil {
		var err error
		if s.outDir == "" {
			s.outDir = t.TempDir()
		}
		s.accounts, err = openAccounts(s.outDir)
		if err != nil {
			t.Fatal(err)
		}
	}
	const id = "0123456789abcdef0123456789abcdef"
	if !s.accounts.ready() {
		if err := s.importAdminConfig(id); err != nil {
			t.Fatal(err)
		}
		s.accounts.state.AdminID = id
		s.accounts.state.Users[id] = account{ID: id, Username: "fixture-admin"}
	}
	token := secretToken()
	csrf := s.csrfToken
	if csrf == "" {
		csrf = "tok"
	}
	s.accounts.state.Sessions[tokenHash(token)] = loginSession{UserID: s.accounts.state.AdminID, CSRF: csrf, Expires: time.Now().Add(time.Hour)}
	h := s.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		h.ServeHTTP(w, r)
	})
}
