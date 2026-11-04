package server

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/config"
)

func modelConfigFor(r *http.Request) (*config.Config, error) {
	if u := who(r); u != nil {
		return config.LoadFrom(u.ConfigPath)
	}
	return config.Load() // CLI-compatible direct handler tests; HTTP requires a session.
}

// Keep Docker's service HOME/config and global resource locks. Only the model
// config namespace and credentials change per invocation, never os.Setenv.
func modelEnvironment(r *http.Request, cfg *config.Config, overrides map[string]string) map[string]string {
	u := who(r)
	if u == nil {
		return overrides
	}
	env := map[string]string{}
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		upper := strings.ToUpper(key)
		if strings.Contains(upper, "API_KEY") || strings.HasSuffix(upper, "_TOKEN") || strings.HasPrefix(upper, "AWS_") || upper == "GOOGLE_APPLICATION_CREDENTIALS" || strings.HasSuffix(upper, "_BASE_URL") {
			env[key] = ""
		}
	}
	env["XDG_CONFIG_HOME"] = filepath.Dir(filepath.Dir(u.ConfigPath))
	env["PYTHON_DOTENV_DISABLED"] = "1"
	env["VULSCAN_LOCAL_CLAUDE"] = "false"
	for k, v := range overrides {
		env[k] = v
	}
	if cfg.APIKey != "" {
		env["VULSCAN_REDACT_API_KEY_LEGACY"] = cfg.APIKey
	}
	// Provider keys loaded from JSON also need redaction, including later
	// summary/report subprocesses. These extra variables are not SDK inputs.
	for _, name := range cfg.ProviderNames() {
		p, _ := cfg.GetProvider(name)
		if p.APIKey != "" {
			env["VULSCAN_REDACT_API_KEY_"+name] = p.APIKey
		}
	}
	return env
}

func (s *Server) createUserConfig(id string) error {
	return config.SaveTo(&config.Config{}, s.accounts.configPath(id))
}
func modelPhases(provider, model string) map[string]config.LLMPhaseRef {
	phases := map[string]config.LLMPhaseRef{}
	for _, name := range []string{"analyze", "enhance", "verify", "report", "dynamic_test", "llm_reach", "app_context"} {
		phases[name] = config.LLMPhaseRef{Provider: provider, Model: model}
	}
	return phases
}

type providerView struct {
	Name, Type, BaseURL string
	HasKey              bool
}
type settingsData struct {
	Username, CSRF, Nonce, Error, Success string
	Providers                             []providerView
	HasAPIKey                             bool
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	u := who(r)
	d := settingsData{Username: u.User.Username, CSRF: u.Session.CSRF, Nonce: nonceFrom(r)}
	// Serialise a whole read/edit/atomic-save transaction, including different
	// tabs, to retain existing profiles and key rotations without lost updates.
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cfg, err := modelConfigFor(r)
	if err != nil {
		http.Error(w, "个人模型配置无法读取，请联系管理员检查文件", 500)
		return
	}
	code := 200
	if r.Method == "POST" {
		if r.FormValue("action") == "password" {
			old, newPassword := r.FormValue("current_password"), r.FormValue("new_password")
			if err = s.changePassword(u, old, newPassword); err != nil {
				d.Error = err.Error()
				code = 400
			} else {
				http.Redirect(w, r, "/settings?password_saved=1", 303)
				return
			}
		} else {
			kind := r.FormValue("provider")
			model := strings.TrimSpace(r.FormValue("model"))
			endpoint := strings.TrimSpace(r.FormValue("base_url"))
			key := strings.TrimSpace(r.FormValue("api_key"))
			allowed := map[string]bool{"deepseek": true, "openai": true, "anthropic": true, "google": true}
			if !allowed[kind] || model == "" || len(model) > 160 || strings.ContainsAny(model, "\r\n\x00") || len(key) > 2048 || strings.ContainsAny(key, "\r\n\x00") {
				d.Error = "请选择服务商并填写有效的模型名称和密钥。"
				code = 400
			}
			if endpoint != "" {
				parsed, e := url.Parse(endpoint)
				if e != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme == "http" && !hostHeaderIsLocalNetwork(&http.Request{Host: parsed.Host})) {
					d.Error = "服务地址需使用 HTTPS；本机或内网 IP 可使用 HTTP，不得包含凭据或查询参数。"
					code = 400
				}
			}
			if code == 200 {
				p, _ := cfg.GetProvider(kind)
				if key == "" {
					key = p.APIKey
				}
				if r.FormValue("clear_key") == "on" {
					key = ""
				}
				cfg.WriteLLMConfig("web-"+kind, modelPhases(kind, model), map[string]config.ProviderEntry{kind: {Type: kind, APIKey: key, BaseURL: endpoint}}, true)
				if err = config.SaveTo(cfg, u.ConfigPath); err != nil {
					d.Error = "配置保存失败，请检查磁盘和权限。"
					code = 500
				} else {
					http.Redirect(w, r, "/settings?saved=1", 303)
					return
				}
			}
		}
	}
	if r.URL.Query().Get("saved") == "1" {
		d.Success = "模型配置已保存。"
	}
	if r.URL.Query().Get("password_saved") == "1" {
		d.Success = "密码已更新，其他登录会话已退出。"
	}
	names := cfg.ProviderNames()
	sort.Strings(names)
	for _, name := range names {
		p, _ := cfg.GetProvider(name)
		d.Providers = append(d.Providers, providerView{Name: name, Type: p.Type, BaseURL: p.BaseURL, HasKey: p.APIKey != ""})
	}
	if p, ok := cfg.GetProvider("deepseek"); ok {
		d.HasAPIKey = p.APIKey != ""
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	s.tmplSettings.Execute(w, d)
}
