// Modified 2026-10-23 for the VulScan-only product namespace.
package server

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	uifiles "github.com/puhaoyang78/911VulScan/apps/vulscan-cli/ui"
)

func TestHandleDesignAndApplicationAssets(t *testing.T) {
	h := (&Server{}).Handler()
	for _, name := range []string{"tabler-1.4.0.min.css", "workbench.css", "index.css", "report.css", "shell.js", "scan.js", "reader.js", "documents.js", "report.js", "highlight-11.11.1.min.js", "inter-latin-wght-5.2.5.woff2", "jetbrains-mono-latin-400-5.2.5.woff2"} {
		want, mime, err := uifiles.Asset(name)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("GET", "/assets/"+name, nil)
		req.Host = "localhost:8080"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), want) || rec.Header().Get("Content-Type") != mime || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("asset response differs from embed: %s", name)
		}
	}
	for _, name := range []string{"SOURCES.txt", "embed.go", "unknown.js"} {
		req := httptest.NewRequest("GET", "/assets/"+name, nil)
		req.Host = "localhost"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 404 {
			t.Errorf("unexpected asset access: %s", name)
		}
	}
}

// #577: /assets serves ONLY the vendored ui scripts, by exact versioned
// name. The route is the serving half of the vendored-script governance:
// every script the embedded pages reference must be served byte-identically
// from the embed, the pre-#577 versionless names must be GONE (404, not
// aliased — an alias would defeat the versioned-name notifier), and the
// response carries the JS content type + nosniff (the blobs are external
// scripts, never inlined template.JS — the breakout class has no reach
// here).
func TestHandleAssetServesVersionedVendor(t *testing.T) {
	h := (&Server{}).Handler()

	served := 0
	err := fs.WalkDir(uifiles.FS, "vendor", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := path.Base(p)
		if !strings.HasSuffix(name, ".js") {
			return nil // SOURCES.txt — the provenance record, not a script
		}
		want, err := uifiles.FS.ReadFile(p)
		if err != nil {
			return err
		}
		req := httptest.NewRequest(http.MethodGet, "/assets/"+name, nil)
		req.Host = "localhost:8080" // the rebinding guard 403s non-loopback Hosts
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET /assets/%s = %d, want 200 (the embedded pages reference this script)", name, rec.Code)
			return nil
		}
		if !bytes.Equal(rec.Body.Bytes(), want) {
			t.Errorf("GET /assets/%s: served bytes differ from the embedded bytes — the serving path diverged from the pinned blob", name)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
			t.Errorf("GET /assets/%s Content-Type = %q, want application/javascript; charset=utf-8", name, ct)
		}
		if xo := rec.Header().Get("X-Content-Type-Options"); xo != "nosniff" {
			t.Errorf("GET /assets/%s: X-Content-Type-Options = %q, want nosniff (securityHeaders must cover the asset route)", name, xo)
		}
		served++
		return nil
	})
	if err != nil {
		t.Fatalf("walking the embedded vendor dir: %v", err)
	}
	if served == 0 {
		t.Fatal("no vendored scripts found in the embed")
	}

	// The retired pre-#577 versionless names, and every SUPERSEDED
	// versioned name (marked-12.0.2 by the 18.x re-vendor; marked-18.0.12
	// by the 18.0.13 patch bump; marked-18.0.13 by the 18.1.1 minor bump;
	// dompurify-3.4.15 by the 3.4.17 patch bump): 404, never aliased.
	for _, name := range []string{"marked.min.js", "purify.min.js", "marked-12.0.2.min.js", "marked-18.0.12.min.js", "marked-18.0.13.min.js", "dompurify-3.4.15.min.js"} {
		req := httptest.NewRequest(http.MethodGet, "/assets/"+name, nil)
		req.Host = "localhost:8080"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET /assets/%s = %d, want 404 (the versionless name must be retired, not aliased — an alias hides the version from the notifier)", name, rec.Code)
		}
	}
}

// The handleAsset allowlist and the embedded vendor set must agree EXACTLY:
// a case literal with no embedded file is a dead 200-route (harmless at
// runtime — ReadFile 404s — but it means the five-way rename consistency
// net drifted: embed list, page tags, pin table, this allowlist, and the
// renovate reference files are supposed to move together in one commit).
func TestHandleAssetAllowlistMatchesEmbeddedVendor(t *testing.T) {
	count := 0
	err := fs.WalkDir(uifiles.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := path.Ext(p)
		if ext != ".js" && ext != ".css" && ext != ".woff2" {
			return nil
		}
		if !strings.HasPrefix(p, "vendor/") && !strings.HasPrefix(p, "static/") && !strings.HasPrefix(p, "design/") {
			return nil
		}
		want, err := uifiles.FS.ReadFile(p)
		if err != nil {
			return err
		}
		got, _, err := uifiles.Asset(path.Base(p))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("embedded resource is not served exactly: %s", p)
		}
		count++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count < 13 {
		t.Fatal("resource inventory is incomplete")
	}
	for _, name := range []string{"../embed.go", "/etc/passwd", "SOURCES.txt", "Tabler-LICENSE.txt", "marked.min.js"} {
		if _, _, err := uifiles.Asset(name); err == nil {
			t.Errorf("unexpected allowlisted asset %s", name)
		}
	}
}
