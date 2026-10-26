// Modified 2026-10-23 for the VulScan-only product namespace.
// Package ui provides the embedded web UI templates for the vulscan serve command.
package ui

import (
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"path"
	"strings"
)

//go:embed index.html scan.html summary.html disclosure.html vendor/marked-18.1.1.min.js vendor/dompurify-3.4.17.min.js
//go:embed static/*.css static/*.js design/*.css design/*.js design/*.woff2 design/*LICENSE.txt
var FS embed.FS

// Asset only exposes actual embedded scripts/styles/fonts. A URL cannot name a
// directory, source file, license record, or arbitrary filesystem path.
func Asset(name string) ([]byte, string, error) {
	if path.Base(name) != name || strings.ContainsAny(name, "/\\") {
		return nil, "", fmt.Errorf("invalid asset")
	}
	mime := map[string]string{".js": "application/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".woff2": "font/woff2"}[path.Ext(name)]
	if mime == "" {
		return nil, "", fmt.Errorf("invalid asset type")
	}
	for _, dir := range []string{"vendor/", "design/", "static/"} {
		if b, err := FS.ReadFile(dir + name); err == nil {
			return b, mime, nil
		}
	}
	return nil, "", fmt.Errorf("unknown asset %q", name)
}

// InlineDesignCSS embeds the same visual foundation and actual font bytes in
// exported file:// reports. There is no dependency on the server's /assets.
func InlineDesignCSS() template.CSS {
	var all strings.Builder
	for _, name := range []string{"tabler-1.4.0.min.css", "workbench.css", "report.css"} {
		b, _, err := Asset(name)
		if err != nil {
			panic(err)
		}
		all.Write(b)
		all.WriteString("\n")
	}
	css := all.String()
	for _, font := range []string{"inter-latin-wght-5.2.5.woff2", "jetbrains-mono-latin-400-5.2.5.woff2"} {
		b, _, err := Asset(font)
		if err != nil {
			panic(err)
		}
		css = strings.ReplaceAll(css, "/assets/"+font, "data:font/woff2;base64,"+base64.StdEncoding.EncodeToString(b))
	}
	return template.CSS(css)
}

func InlineJS(name string) (template.JS, error) {
	b, mime, err := Asset(name)
	if err != nil || mime != "application/javascript; charset=utf-8" {
		return "", fmt.Errorf("unknown UI script %q", name)
	}
	return template.JS(b), nil
}

// Standalone HTML distributes the actual font files, so retain their license
// texts in that same file as well as in the source package and embedded binary.
func LicensesText() string {
	var out strings.Builder
	for _, name := range []string{"Tabler-LICENSE.txt", "Highlight-LICENSE.txt", "Inter-LICENSE.txt", "Inter-UPSTREAM-LICENSE.txt", "JetBrainsMono-LICENSE.txt", "JetBrainsMono-UPSTREAM-LICENSE.txt"} {
		b, err := FS.ReadFile("design/" + name)
		if err != nil {
			panic(err)
		}
		out.WriteString(name + "\n\n")
		out.Write(b)
		out.WriteString("\n\n")
	}
	return out.String()
}
