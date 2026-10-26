package ui

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestDesignAssetsPinnedAndEmbedded(t *testing.T) {
	raw, err := os.ReadFile("design/SOURCES.txt")
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^([0-9a-f]{64})  (\S+)\r?$`).FindAllStringSubmatch(string(raw), -1) {
		pins[m[2]] = m[1]
	}
	if len(pins) < 10 {
		t.Fatal("font licenses and all design assets must be recorded")
	}
	for name, want := range pins {
		b, err := FS.ReadFile("design/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != want {
			t.Errorf("%s: actual bytes differ from verified source record", name)
		}
		if len(b) == 0 {
			t.Errorf("empty asset: %s", name)
		}
	}
	if err := fs.WalkDir(FS, "design", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && pins[strings.TrimPrefix(path, "design/")] == "" {
			t.Errorf("unpinned design asset %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("design")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "SOURCES.txt" && pins[e.Name()] == "" {
			t.Errorf("unregistered design file %s", e.Name())
		}
	}
}

func TestInlineDesignIsOfflineAndCannotBreakOut(t *testing.T) {
	css := string(InlineDesignCSS())
	if strings.Contains(css, "/assets/") || strings.Contains(strings.ToLower(css), "</style") {
		t.Fatal("standalone CSS depends on server or breaks out of style")
	}
	if strings.Count(css, "data:font/woff2;base64,") != 2 {
		t.Fatal("actual local font bytes are not inlined")
	}
	for _, m := range regexp.MustCompile(`url\(['"]?([^)'" ]+)`).FindAllStringSubmatch(css, -1) {
		if !strings.HasPrefix(m[1], "data:") {
			t.Errorf("runtime external CSS resource: %s", m[1])
		}
	}
	for _, script := range []string{"shell.js", "highlight-11.11.1.min.js", "reader.js", "report.js"} {
		b, err := InlineJS(script)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(b)), "</script") {
			t.Fatalf("%s breaks out of script", script)
		}
	}
}
