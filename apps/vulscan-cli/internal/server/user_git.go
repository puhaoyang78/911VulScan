package server

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

type restrictedGitKey struct{}

// A Web member must not borrow the service account's Git credentials, URL
// rewrites or SSH keys to clone somebody else's private repository.
func restrictGit(ctx context.Context, cmd *exec.Cmd) {
	home, _ := ctx.Value(restrictedGitKey{}).(string)
	if home == "" {
		return
	}
	env := []string{}
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(key, "GIT_") || strings.HasPrefix(key, "SSH_") || key == "HOME" {
			continue
		}
		env = append(env, item)
	}
	cmd.Env = append(env, "HOME="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "GIT_CONFIG_COUNT=2", "GIT_CONFIG_KEY_0=credential.helper", "GIT_CONFIG_VALUE_0=", "GIT_CONFIG_KEY_1=http.extraHeader", "GIT_CONFIG_VALUE_1=")
}
