package server

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const sessionCookie = "vulscan_session"
const guestCookie = "vulscan_form"
const sessionLifetime = 7 * 24 * time.Hour
const passwordIterations = 600000

type account struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Salt         string    `json:"salt"`
	CreatedAt    time.Time `json:"created_at"`
}

type loginSession struct {
	UserID  string    `json:"user_id"`
	CSRF    string    `json:"csrf"`
	Expires time.Time `json:"expires"`
}

type accountState struct {
	Version int `json:"version"`
	// Retain the legacy owner on existing installations; registration never grants it.
	AdminID  string                  `json:"admin_id,omitempty"`
	Users    map[string]account      `json:"users"`
	Sessions map[string]loginSession `json:"sessions"`
}

// One service process owns this store, like the existing job manager. Secrets
// and sessions are atomically persisted before becoming visible to requests.
type accountStore struct {
	mu            sync.Mutex
	state         accountState
	dir           string
	operatorToken string
	passwordSlots chan struct{}
	requests      map[string]authWindow
}
type authWindow struct {
	Start time.Time
	Count int
}
type identity struct {
	User       account
	Session    loginSession
	TokenHash  string
	ConfigPath string
	Admin      bool
}
type identityKey struct{}
type externalOriginKey struct{}

func secretToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("secure random source: " + err.Error())
	}
	return hex.EncodeToString(b)
}
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func writePrivateJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(path, append(data, '\n'))
}
func writePrivateFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func openAccounts(outDir string) (*accountStore, error) {
	dir := filepath.Join(outDir, ".access")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	a := &accountStore{dir: dir, passwordSlots: make(chan struct{}, 4), requests: map[string]authWindow{},
		state: accountState{Version: 1, Users: map[string]account{}, Sessions: map[string]loginSession{}}}
	data, err := os.ReadFile(filepath.Join(dir, "accounts.json"))
	if err == nil {
		if err = json.Unmarshal(data, &a.state); err != nil {
			return nil, fmt.Errorf("账号文件损坏，拒绝重新初始化：%w", err)
		}
		if a.state.Version != 1 || a.state.Users == nil || a.state.Sessions == nil {
			return nil, errors.New("账号文件格式不支持")
		}
		if a.state.AdminID != "" && a.state.Users[a.state.AdminID].ID == "" {
			return nil, errors.New("历史任务的归属账号不存在")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	path := filepath.Join(dir, "operator-token")
	data, err = os.ReadFile(path)
	if os.IsNotExist(err) {
		data = []byte(secretToken())
		err = writePrivateFile(path, data)
	}
	if err != nil {
		return nil, err
	}
	a.operatorToken = strings.TrimSpace(string(data))
	if len(a.operatorToken) != 64 {
		return nil, errors.New("operator-token 格式无效")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return a, nil
}

// updateLocked commits a copy so disk failures cannot grant an unpersisted login
// or report a successful logout while leaving its session valid on restart.
func (a *accountStore) updateLocked(change func(*accountState)) error {
	next := a.state
	next.Users = make(map[string]account, len(a.state.Users))
	for k, v := range a.state.Users {
		next.Users[k] = v
	}
	next.Sessions = make(map[string]loginSession, len(a.state.Sessions))
	for k, v := range a.state.Sessions {
		if time.Now().Before(v.Expires) {
			next.Sessions[k] = v
		}
	}
	change(&next)
	if err := writePrivateJSON(filepath.Join(a.dir, "accounts.json"), next); err != nil {
		return err
	}
	a.state = next
	return nil
}

func (a *accountStore) hasUsers() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.state.Users) > 0
}
func (a *accountStore) resolve(token string) *identity {
	if len(token) != 64 {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	hash := tokenHash(token)
	s, ok := a.state.Sessions[hash]
	u, exists := a.state.Users[s.UserID]
	if !ok || !exists || !time.Now().Before(s.Expires) {
		return nil
	}
	return &identity{User: u, Session: s, TokenHash: hash, ConfigPath: a.configPath(u.ID), Admin: u.ID == a.state.AdminID}
}
func (a *accountStore) configPath(id string) string {
	return filepath.Join(a.dir, "users", id, "vulscan", "config.json")
}
func who(r *http.Request) *identity { u, _ := r.Context().Value(identityKey{}).(*identity); return u }
func (s *Server) csrfFor(r *http.Request) string {
	if u := who(r); u != nil {
		return u.Session.CSRF
	}
	// Direct handler unit tests predate sessions; the public router always
	// authenticates first and never exposes this instance token.
	return s.csrfToken
}
func (s *Server) sessionAlive(r *http.Request) bool {
	u := who(r)
	if u == nil {
		return s.accounts == nil
	} // internal, direct handler calls only
	s.accounts.mu.Lock()
	defer s.accounts.mu.Unlock()
	ss, ok := s.accounts.state.Sessions[u.TokenHash]
	return ok && time.Now().Before(ss.Expires)
}
func (s *Server) owns(r *http.Request, j *Job) bool {
	u := who(r)
	if u == nil {
		return false
	}
	return j.OwnerID == u.User.ID || (j.OwnerID == "" && u.Admin)
}

func (s *Server) authenticated(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.accounts == nil {
			http.Error(w, "账号服务尚未初始化", 503)
			return
		}
		cookie, err := r.Cookie(sessionCookie)
		var u *identity
		if err == nil {
			u = s.accounts.resolve(cookie.Value)
		}
		w.Header().Set("Cache-Control", "no-store")
		if u == nil {
			if r.Method == "GET" && strings.Contains(r.Header.Get("Accept"), "text/html") {
				target := "/login"
				if !s.accounts.hasUsers() {
					target = "/register"
				}
				http.Redirect(w, r, target+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			} else {
				http.Error(w, "登录已失效，请重新登录", http.StatusUnauthorized)
			}
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, u))
		if id := r.PathValue("id"); id != "" {
			j, ok := s.mgr.get(id)
			if !ok || !s.owns(r, j) {
				http.NotFound(w, r)
				return
			}
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if !sameOriginOK(r) {
				http.Error(w, "已拒绝跨站请求", 403)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "表单无效或过大", 400)
				return
			}
			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				token = r.FormValue("csrf")
			}
			if subtle.ConstantTimeCompare([]byte(token), []byte(u.Session.CSRF)) != 1 {
				http.Error(w, "安全令牌失效，请刷新页面", 403)
				return
			}
		}
		h(w, r)
	}
}

func (s *Server) cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(s.externalURL, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}
func (s *Server) guestCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(guestCookie); err == nil && s.validGuest(c.Value) {
		return c.Value
	}
	token := secretToken()
	mac := hmac.New(sha256.New, []byte(s.accounts.operatorToken))
	mac.Write([]byte(token))
	token += "." + hex.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, s.cookie(guestCookie, token, 3600))
	return token
}
func (s *Server) validGuest(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(parts[0]) != 64 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(s.accounts.operatorToken))
	mac.Write([]byte(parts[0]))
	return hmac.Equal([]byte(parts[1]), []byte(hex.EncodeToString(mac.Sum(nil))))
}

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,31}$`)

func passwordKey(password, salt string) string {
	key, err := pbkdf2.Key(sha256.New, password, []byte(salt), passwordIterations, 32)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(key)
}
func (a *accountStore) allowAuth(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, v := range a.requests {
		if now.Sub(v.Start) > time.Minute {
			delete(a.requests, k)
		}
	}
	v, exists := a.requests[host]
	if !exists {
		if len(a.requests) >= 4096 {
			return false
		}
		v.Start = now
	}
	v.Count++
	a.requests[host] = v
	return v.Count <= 30
}

type authPageData struct {
	Mode, Title, CSRF, Nonce, Error, Username, Next string
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	mode := strings.TrimPrefix(r.URL.Path, "/")
	if r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "表单无效或过大", 400)
			return
		}
	}
	next := r.URL.Query().Get("next")
	if r.Method == "POST" {
		next = r.FormValue("next")
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") {
		next = "/"
	}
	d := authPageData{Mode: mode, Title: map[string]string{"login": "登录工作台", "register": "创建账号"}[mode], CSRF: s.guestCSRF(w, r), Nonce: nonceFrom(r), Next: next}
	code := 200
	if r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "表单无效或过大", 400)
			return
		}
		c, err := r.Cookie(guestCookie)
		if err != nil || !sameOriginOK(r) || !s.validGuest(c.Value) || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.FormValue("csrf"))) != 1 {
			http.Error(w, "安全令牌失效，请刷新页面", 403)
			return
		}
		if !s.accounts.allowAuth(r.RemoteAddr) {
			http.Error(w, "操作过于频繁，请一分钟后重试", 429)
			return
		}
		select {
		case s.accounts.passwordSlots <- struct{}{}:
			defer func() { <-s.accounts.passwordSlots }()
		default:
			http.Error(w, "登录请求繁忙，请稍后重试", 429)
			return
		}
		d.Username = strings.ToLower(strings.TrimSpace(r.FormValue("username")))
		password := r.FormValue("password")
		if !usernamePattern.MatchString(d.Username) || len(password) > 128 || utf8.RuneCountInString(password) < 12 {
			d.Error = "账号需为 3–32 位字母、数字或 ._-，密码需为 12 位以上且不超过 128 字节。"
			code = 400
		} else if mode == "login" {
			s.accounts.mu.Lock()
			var user account
			for _, u := range s.accounts.state.Users {
				if u.Username == d.Username {
					user = u
					break
				}
			}
			s.accounts.mu.Unlock()
			// Equal work for unknown accounts; never persist the supplied password.
			salt := user.Salt
			if salt == "" {
				salt = strings.Repeat("0", 64)
			}
			if subtle.ConstantTimeCompare([]byte(passwordKey(password, salt)), []byte(user.PasswordHash)) != 1 || user.ID == "" {
				d.Error = "账号或密码错误。"
				code = 400
			} else if err := s.issueSession(w, user); err != nil {
				d.Error = "无法保存登录状态，请检查磁盘和权限。"
				code = 500
			}
		} else {
			u := account{ID: secretToken()[:32], Username: d.Username, Salt: secretToken(), CreatedAt: time.Now().UTC()}
			u.PasswordHash = passwordKey(password, u.Salt)
			s.accounts.mu.Lock()
			for _, existing := range s.accounts.state.Users {
				if existing.Username == u.Username {
					d.Error = "该账号已注册。"
					code = 409
				}
			}
			if code == 200 {
				err = s.createUserConfig(u.ID)
				if err == nil {
					err = s.accounts.updateLocked(func(st *accountState) { st.Users[u.ID] = u })
				}
				if err != nil {
					d.Error = "账号保存失败，请检查磁盘和权限。"
					code = 500
				}
			}
			s.accounts.mu.Unlock()
			if code == 200 {
				if err = s.issueSession(w, u); err != nil {
					d.Error = "账号已创建，请重新登录。"
					code = 500
				}
			}
		}
		if code == 200 {
			http.SetCookie(w, s.cookie(guestCookie, "", -1))
			http.Redirect(w, r, next, 303)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if err := s.tmplAuth.Execute(w, d); err != nil {
		return
	}
}

func (s *Server) issueSession(w http.ResponseWriter, user account) error {
	userID := user.ID
	token := secretToken()
	session := loginSession{UserID: userID, CSRF: secretToken(), Expires: time.Now().Add(sessionLifetime)}
	s.accounts.mu.Lock()
	if s.accounts.state.Users[userID].PasswordHash != user.PasswordHash {
		s.accounts.mu.Unlock()
		return errors.New("密码已变更，请重新登录")
	}
	err := s.accounts.updateLocked(func(st *accountState) {
		// Bound sessions per account, evicting the oldest only when necessary.
		for {
			count, oldest := 0, ""
			for k, v := range st.Sessions {
				if v.UserID == userID {
					count++
					if oldest == "" || v.Expires.Before(st.Sessions[oldest].Expires) {
						oldest = k
					}
				}
			}
			if count < 10 {
				break
			}
			delete(st.Sessions, oldest)
		}
		st.Sessions[tokenHash(token)] = session
	})
	s.accounts.mu.Unlock()
	if err == nil {
		http.SetCookie(w, s.cookie(sessionCookie, token, int(sessionLifetime.Seconds())))
	}
	return err
}
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.accounts.mu.Lock()
	err := s.accounts.updateLocked(func(st *accountState) { delete(st.Sessions, who(r).TokenHash) })
	s.accounts.mu.Unlock()
	if err != nil {
		http.Error(w, "退出失败，请重试", 500)
		return
	}
	http.SetCookie(w, s.cookie(sessionCookie, "", -1))
	http.Redirect(w, r, "/login", 303)
}
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := who(r)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]any{"username": u.User.Username, "admin": u.Admin, "csrf": u.Session.CSRF})
}

func (s *Server) changePassword(u *identity, old, password string) error {
	if len(old) > 128 || utf8.RuneCountInString(password) < 12 || len(password) > 128 {
		return errors.New("新密码需为 12 位以上且不超过 128 字节。")
	}
	select {
	case s.accounts.passwordSlots <- struct{}{}:
		defer func() { <-s.accounts.passwordSlots }()
	default:
		return errors.New("请求繁忙，请稍后重试。")
	}
	s.accounts.mu.Lock()
	current := s.accounts.state.Users[u.User.ID]
	s.accounts.mu.Unlock()
	if subtle.ConstantTimeCompare([]byte(passwordKey(old, current.Salt)), []byte(current.PasswordHash)) != 1 {
		return errors.New("当前密码错误。")
	}
	updated := current
	updated.Salt = secretToken()
	updated.PasswordHash = passwordKey(password, updated.Salt)
	s.accounts.mu.Lock()
	defer s.accounts.mu.Unlock()
	if s.accounts.state.Users[current.ID].PasswordHash != current.PasswordHash {
		return errors.New("密码已变更，请重新登录。")
	}
	return s.accounts.updateLocked(func(st *accountState) {
		st.Users[current.ID] = updated
		for k, v := range st.Sessions {
			if v.UserID == current.ID && k != u.TokenHash {
				delete(st.Sessions, k)
			}
		}
	})
}
func (s *Server) handleOperatorStatus(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !hostIsLoopback(host) || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.accounts.operatorToken)) != 1 {
		http.Error(w, "未授权", 401)
		return
	}
	count := 0
	for _, j := range s.mgr.all() {
		j.mu.Lock()
		if scanActive(j.Status) {
			count++
		}
		j.mu.Unlock()
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"application": "911VulScan", "running": count})
}

// ConfigureExternalURL pins the browser origin when HTTPS is terminated by a
// reverse proxy. Forwarded headers are intentionally not trusted.
func (s *Server) ConfigureExternalURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("external-url 必须是 http(s)://主机[:端口]，不含路径或凭据")
	}
	if u.Scheme == "http" && !hostHeaderIsLocalNetwork(&http.Request{Host: u.Host}) {
		return errors.New("域名或公网访问必须使用 HTTPS")
	}
	s.externalURL = u.Scheme + "://" + u.Host
	return nil
}
