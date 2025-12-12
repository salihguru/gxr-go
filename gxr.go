// Package gxr provides a Go x React SSR framework with automatic hydration.
//
// GXR enables building server-side rendered React applications using Go.
// Components marked with "use client" directive are automatically wrapped
// for client-side hydration.
//
// This is the Go runtime package. For the main framework, CLI tools, and
// documentation, see: https://github.com/salihguru/gxr
//
// Basic usage:
//
//	g, err := gxr.New()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	html, err := g.Render("pages/index.tsx", map[string]interface{}{
//	    "title": "Hello GXR",
//	})
package gxr

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zbysir/gojsx"
)

// Pre-compiled regex patterns for performance optimization.
// Compiling these once at package initialization avoids the overhead
// of re-compilation on every request.
var (
	// cleanupRegex matches inline hydration data scripts that should be removed
	cleanupRegex = regexp.MustCompile(`<script[^>]*data-hid-data="[^"]*"[^>]*>.*?</script>`)

	// dataRegex extracts hydration data from inline scripts
	dataRegex = regexp.MustCompile(`<script[^>]*data-hid-data="(\d+)"[^>]*>(.*?)</script>`)

	// scriptCloseRegex matches </script> tags (case-insensitive) for XSS prevention
	scriptCloseRegex = regexp.MustCompile(`(?i)</script>`)
)

// GXR is the main framework instance
type GXR struct {
	jsx         *gojsx.Jsx
	transformer *UseClientTransformer
	options     Options
}

// Options configures the GXR instance
type Options struct {
	// SourceDir is the root directory for TSX files (default: ".")
	SourceDir string
	// PublicPath is the URL path for static files (default: "/public")
	PublicPath string
}

// New creates a new GXR instance with default options
func New() (*GXR, error) {
	return NewWithOptions(Options{})
}

// NewWithOptions creates a new GXR instance with custom options
func NewWithOptions(opts Options) (*GXR, error) {
	if opts.SourceDir == "" {
		opts.SourceDir = "."
	}
	if opts.PublicPath == "" {
		opts.PublicPath = "/public"
	}

	transformer := &UseClientTransformer{
		inner: gojsx.NewEsBuildTransform(gojsx.EsBuildTransformOptions{}),
	}

	jsx, err := gojsx.NewJsx(gojsx.Option{
		Transformer: transformer,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create jsx runtime: %w", err)
	}

	g := &GXR{
		jsx:         jsx,
		transformer: transformer,
		options:     opts,
	}

	// Register React hooks mock for SSR
	g.registerReactMocks()

	return g, nil
}

// Render renders a TSX page with the given props.
// It includes panic recovery to prevent server crashes from component errors.
func (g *GXR) Render(page string, props map[string]interface{}) (html string, err error) {
	// Recover from panics in user component code to prevent server crashes
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("render panic recovered: %v", r)
			html = ""
		}
	}()

	cleanPage := filepath.Clean(page)
	pagePath := filepath.Join(g.options.SourceDir, cleanPage)

	absPath, err := filepath.Abs(pagePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}

	html, err = g.jsx.Render(absPath, props)
	if err != nil {
		return "", fmt.Errorf("failed to render page: %w", err)
	}

	// Inject hydration scripts
	html = g.injectHydrationScripts(html)

	return html, nil
}

// registerReactMocks registers mock implementations of React hooks for SSR
func (g *GXR) registerReactMocks() {
	g.jsx.RegisterModule("react", map[string]interface{}{
		"useState": func(initialValue any) interface{} {
			return []interface{}{initialValue, func(newValue any) {}}
		},
		"useEffect":   func(effect any, deps any) {},
		"useCallback": func(callback any, deps any) interface{} { return callback },
		"useMemo": func(factory any, deps any) interface{} {
			if fn, ok := factory.(func() interface{}); ok {
				return fn()
			}
			return nil
		},
		"useRef": func(initialValue any) interface{} {
			return map[string]interface{}{"current": initialValue}
		},
		"useContext": func(context any) interface{} { return nil },
		"createContext": func(defaultValue any) interface{} {
			return map[string]interface{}{"Provider": nil, "Consumer": nil}
		},
	})
}

// injectHydrationScripts injects hydration data and script before </body>
func (g *GXR) injectHydrationScripts(html string) string {
	// Check if there are any client components
	if !strings.Contains(html, "data-hid=") {
		return html
	}

	// Extract hydration data from inline scripts
	hydrationData := extractHydrationData(html)
	if hydrationData == "[]" {
		return html
	}

	// Remove inline hydration data scripts (using pre-compiled regex)
	html = cleanupRegex.ReplaceAllString(html, "")

	// Escape the hydration data to prevent XSS attacks.
	// If the JSON contains "</script>", it could break out of the script tag.
	safeHydrationData := escapeScriptContent(hydrationData)

	// Create script tags to inject
	scripts := fmt.Sprintf(`<script id="__HYDRATION_DATA__" type="application/json">%s</script>
<script type="module" src="%s/hydrate.js"></script>`, safeHydrationData, g.options.PublicPath)

	// Inject before </body>
	if idx := strings.LastIndex(html, "</body>"); idx != -1 {
		html = html[:idx] + scripts + "\n" + html[idx:]
	}

	return html
}

// escapeScriptContent escapes content to be safely embedded in a <script> tag.
// This prevents XSS attacks where malicious props could contain "</script>".
func escapeScriptContent(s string) string {
	// Replace </script> (case-insensitive) with escaped version.
	// In JSON, we can use Unicode escapes: </script> becomes <\/script>
	// This is safe because JSON parsers will decode \/ as /
	// Uses pre-compiled case-insensitive regex for performance.
	return scriptCloseRegex.ReplaceAllStringFunc(s, func(match string) string {
		// Preserve the original case but escape the forward slash
		return strings.Replace(match, "/", `\/`, 1)
	})
}

// extractHydrationData finds all hydration markers and builds JSON array
func extractHydrationData(html string) string {
	// Use pre-compiled regex for performance
	matches := dataRegex.FindAllStringSubmatch(html, -1)

	if len(matches) == 0 {
		return "[]"
	}

	var entries []string
	for _, match := range matches {
		entries = append(entries, match[2])
	}

	return "[" + strings.Join(entries, ",") + "]"
}
