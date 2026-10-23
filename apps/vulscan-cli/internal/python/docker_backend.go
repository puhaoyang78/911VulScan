package python

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Persist only a digest, never Docker credentials, endpoints or provider keys.
// Include context metadata because the default context or its endpoint can be
// changed without changing environment variables between invocations.
func dockerBackendFingerprint(env []string) (string, error) {
	values := make(map[string]string)
	for _, item := range env {
		if key, value, ok := strings.Cut(item, "="); ok {
			values[key] = value
		}
	}
	h := sha256.New()
	for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION", "BUILDX_BUILDER"} {
		fmt.Fprintf(h, "%s=%q\n", key, values[key])
	}
	config := values["DOCKER_CONFIG"]
	if config == "" {
		home := values["HOME"]
		if home == "" {
			home = values["USERPROFILE"]
		}
		if home == "" {
			var err error
			home, err = os.UserHomeDir()
			if err != nil {
				return "", err
			}
		}
		config = filepath.Join(home, ".docker")
	}
	files, err := filepath.Glob(filepath.Join(config, "contexts", "meta", "*", "meta.json"))
	if err != nil {
		return "", err
	}
	files = append(files, filepath.Join(config, "config.json"))
	sort.Strings(files)
	if len(files) > 1024 {
		return "", fmt.Errorf("too many Docker context metadata files")
	}
	for _, path := range files {
		fmt.Fprintf(h, "file=%q\n", path)
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			fmt.Fprintln(h, "missing")
			continue
		}
		if err != nil {
			return "", fmt.Errorf("read Docker context identity: %w", err)
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			file.Close()
			return "", fmt.Errorf("Docker context metadata is not a regular file")
		}
		// Hash bounded contents; credentials in config.json never leave this hash.
		n, err := io.Copy(h, io.LimitReader(file, 1024*1024+1))
		file.Close()
		if err != nil {
			return "", err
		}
		if n > 1024*1024 {
			return "", fmt.Errorf("Docker context metadata is too large")
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (d *dockerInvocation) recordBackend(env []string) error {
	fingerprint, err := dockerBackendFingerprint(env)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d.registry, ".backend"), []byte(fingerprint), 0600)
}

func (d *dockerInvocation) matchingBackend(env []string) bool {
	expected, err := dockerBackendFingerprint(env)
	if err != nil {
		return false
	}
	path := filepath.Join(d.registry, ".backend")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != 64 {
		return false
	}
	data, err := os.ReadFile(path)
	return err == nil && string(data) == expected
}
