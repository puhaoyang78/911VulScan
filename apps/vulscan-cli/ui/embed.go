// Modified 2026-10-23 for the VulScan-only product namespace.
// Package ui provides the embedded web UI templates for the vulscan serve command.
package ui

import "embed"

//go:embed index.html scan.html summary.html disclosure.html vendor/marked-18.1.1.min.js vendor/dompurify-3.4.17.min.js
var FS embed.FS
