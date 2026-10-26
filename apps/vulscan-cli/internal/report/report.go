package report

import (
	"embed"
	"encoding/json"
	"fmt"
	uifiles "github.com/puhaoyang78/911VulScan/apps/vulscan-cli/ui"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/html"
)

//go:embed templates/*.gohtml
var templateFS embed.FS

// #332: the report templates' third-party scripts (tailwindcss, chart.js,
// chartjs-plugin-datalabels) are VENDORED at pinned versions — the CDN tags
// carried no SRI, chart.js no version at all, and cdn.tailwindcss.com is a
// mutable runtime generator. The report is served AND written to disk for
// direct file:// opening, so the scripts are INLINED at render time (template
// func returning template.JS): self-contained in every mode — served,
// standalone, air-gapped — with no route coupling.
//
//go:embed vendor/report.css vendor/chart-4.5.1.umd.min.js vendor/chartjs-plugin-datalabels-2.2.0.min.js
var vendorFS embed.FS

// vendorScripts holds the embedded script contents. go:embed validates the
// directive's patterns at COMPILE time (a missing vendored file fails the
// build); a wrong name in a TEMPLATE is a render-time failure — vendorJS
// fails loud when the literal names nothing embedded (see below), so the
// map is built once and a stale literal cannot pass silently.
var vendorScripts = func() map[string]template.JS {
	m := make(map[string]template.JS, 2)
	for _, n := range []string{
		"chart-4.5.1.umd.min.js",
		"chartjs-plugin-datalabels-2.2.0.min.js",
	} {
		b, err := vendorFS.ReadFile("vendor/" + n)
		if err != nil {
			panic("vendored report script missing: " + n)
		}
		m[n] = template.JS(b)
	}
	return m
}()

var (
	overviewTmpl *template.Template
	reskinTmpl   *template.Template
)

func init() {
	funcMap := template.FuncMap{
		"designCSS":      uifiles.InlineDesignCSS,
		"designLicenses": uifiles.LicensesText,
		"designJS":       uifiles.InlineJS,
		"findingView": func(d ReportData, f Finding) map[string]any {
			return map[string]any{"Finding": f, "FileURL": d.FileURL(f.File)}
		},
		"dynamicLabel":      dynamicLabel,
		"dynamicGroupLabel": dynamicGroupLabel,
		"verdictColor":      verdictColor,
		"displayLabel":      displayLabel,
		"displayLabels":     displayLabels,
		"toJSON": func(v any) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"even": func(i int) bool {
			return i%2 == 0
		},
		// #332: inline a vendored, pinned script by file name — the rendered
		// report carries its own dependencies (no CDN, no SRI negotiation).
		// Wave r1 (three axes): return an ERROR on an unknown name — a map
		// miss returned the zero template.JS and the report rendered
		// unstyled/chartless SILENTLY (go:embed validates the directive's
		// patterns, not the string literal a template passes; a rename that
		// missed one of the template call sites compiled clean). template
		// execution now fails loud instead.
		"vendorJS": func(name string) (template.JS, error) {
			js, ok := vendorScripts[name]
			if !ok {
				return "", fmt.Errorf("report: no vendored script %q (vendor/ is missing the file, or the template's literal is stale)", name)
			}
			return js, nil
		},
		// #540: the prebuilt CSS embed — same fail-loud contract as vendorJS
		// (an unknown name fails the render, not a silently unstyled report).
		"vendorCSS": func(name string) (template.CSS, error) {
			b, err := vendorFS.ReadFile("vendor/" + name)
			if err != nil {
				return "", fmt.Errorf("report: no vendored CSS %q (vendor/ is missing the file, or the template's literal is stale)", name)
			}
			return template.CSS(b), nil
		},
	}

	overviewTmpl = template.Must(
		template.New("overview.gohtml").Funcs(funcMap).ParseFS(templateFS, "templates/overview.gohtml", "templates/document.gohtml"),
	)

	reskinTmpl = template.Must(
		template.New("report-reskin.gohtml").Funcs(funcMap).ParseFS(templateFS, "templates/report-reskin.gohtml", "templates/document.gohtml"),
	)
}

// RenderOverview renders the HTML overview report to the given writer.
func RenderOverview(data ReportData, w io.Writer) error {
	return overviewTmpl.Execute(w, data)
}

// GenerateOverview renders the HTML overview report to a file.
func GenerateOverview(data ReportData, outputPath string) error {
	return generateToFile(overviewTmpl, data, outputPath)
}

// RenderReskin preserves the alternate report entry point with the shared reader.
func RenderReskin(data ReportData, w io.Writer) error {
	return reskinTmpl.Execute(w, data)
}

// GenerateReskin renders the shared standalone HTML report to a file.
func GenerateReskin(data ReportData, outputPath string) error {
	return generateToFile(reskinTmpl, data, outputPath)
}

// generateToFile renders a template to a file, creating parent directories as needed.
func generateToFile(tmpl *template.Template, data ReportData, outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

// ExistingRemediation preserves authored guidance when an older static report
// is presented with the current template. The new render applies SafeRemediation
// again; no HTML from the old document becomes trusted script or application UI.
func ExistingRemediation(r io.Reader) (string, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return "", err
	}
	var find func(*html.Node) *html.Node
	find = func(n *html.Node) *html.Node {
		for _, attr := range n.Attr {
			if attr.Key == "class" {
				for _, class := range strings.Fields(attr.Val) {
					if class == "remediation-content" {
						return n
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if found := find(c); found != nil {
				return found
			}
		}
		return nil
	}
	var out strings.Builder
	if n := find(doc); n != nil {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if err := html.Render(&out, c); err != nil {
				return "", err
			}
		}
	}
	return out.String(), nil
}
