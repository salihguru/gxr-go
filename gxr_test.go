package gxr

import (
	"strings"
	"testing"
)

// TestEscapeScriptContent tests the XSS prevention mechanism
func TestEscapeScriptContent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no script tag",
			input:    `{"id":1,"component":"Counter","props":{"count":0}}`,
			expected: `{"id":1,"component":"Counter","props":{"count":0}}`,
		},
		{
			name:     "lowercase script tag",
			input:    `{"data":"</script><script>alert('xss')</script>"}`,
			expected: `{"data":"<\/script><script>alert('xss')<\/script>"}`,
		},
		{
			name:     "uppercase script tag",
			input:    `{"data":"</SCRIPT><SCRIPT>alert('xss')</SCRIPT>"}`,
			expected: `{"data":"<\/SCRIPT><SCRIPT>alert('xss')<\/SCRIPT>"}`,
		},
		{
			name:     "mixed case script tag",
			input:    `{"data":"</ScRiPt><script>alert('xss')</sCRIPT>"}`,
			expected: `{"data":"<\/ScRiPt><script>alert('xss')<\/sCRIPT>"}`,
		},
		{
			name:     "multiple occurrences",
			input:    `</script></script></script>`,
			expected: `<\/script><\/script><\/script>`,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeScriptContent(tt.input)
			if result != tt.expected {
				t.Errorf("escapeScriptContent(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestExtractHydrationData tests the hydration data extraction
func TestExtractHydrationData(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected string
	}{
		{
			name:     "no hydration data",
			html:     `<html><body>Hello</body></html>`,
			expected: "[]",
		},
		{
			name:     "single hydration entry",
			html:     `<div><script type="application/json" data-hid-data="0">{"id":0,"component":"Counter","props":{}}</script></div>`,
			expected: `[{"id":0,"component":"Counter","props":{}}]`,
		},
		{
			name:     "multiple hydration entries",
			html:     `<script data-hid-data="0">{"id":0}</script><script data-hid-data="1">{"id":1}</script>`,
			expected: `[{"id":0},{"id":1}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHydrationData(tt.html)
			if result != tt.expected {
				t.Errorf("extractHydrationData() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestInjectHydrationScripts tests the full hydration injection pipeline
func TestInjectHydrationScripts(t *testing.T) {
	g := &GXR{
		options: Options{
			PublicPath: "/public",
		},
	}

	tests := []struct {
		name     string
		html     string
		contains []string
		notContains []string
	}{
		{
			name: "no client components",
			html: `<html><body>Hello</body></html>`,
			notContains: []string{"__HYDRATION_DATA__", "hydrate.js"},
		},
		{
			name: "with client component",
			html: `<html><body><div data-hid="0">Counter</div><script data-hid-data="0">{"id":0,"component":"Counter"}</script></body></html>`,
			contains: []string{
				`<script id="__HYDRATION_DATA__" type="application/json">`,
				`src="/public/hydrate.js"`,
			},
			notContains: []string{`data-hid-data="0"`}, // Inline script should be removed
		},
		{
			name: "XSS attempt in props - already escaped from transformer",
			// When the transformer properly escapes </script>, the Go side receives already-escaped content
			html: `<html><body><div data-hid="0">Counter</div><script data-hid-data="0">{"props":{"evil":"<\/script><script>alert(1)<\/script>"}}</script></body></html>`,
			contains: []string{
				`<\/script>`, // The escaped version should be preserved
				`__HYDRATION_DATA__`,
			},
			notContains: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := g.injectHydrationScripts(tt.html)
			
			for _, s := range tt.contains {
				if !strings.Contains(result, s) {
					t.Errorf("Result should contain %q, but got:\n%s", s, result)
				}
			}
			
			for _, s := range tt.notContains {
				if strings.Contains(result, s) {
					t.Errorf("Result should NOT contain %q, but got:\n%s", s, result)
				}
			}
		})
	}
}

// TestNewWithOptions tests the options initialization
func TestNewWithOptions(t *testing.T) {
	tests := []struct {
		name            string
		opts            Options
		wantSourceDir   string
		wantPublicPath  string
	}{
		{
			name:           "default options",
			opts:           Options{},
			wantSourceDir:  ".",
			wantPublicPath: "/public",
		},
		{
			name:           "custom options",
			opts:           Options{SourceDir: "./client", PublicPath: "/assets"},
			wantSourceDir:  "./client",
			wantPublicPath: "/assets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := NewWithOptions(tt.opts)
			if err != nil {
				t.Fatalf("NewWithOptions() error = %v", err)
			}
			
			if g.options.SourceDir != tt.wantSourceDir {
				t.Errorf("SourceDir = %q, want %q", g.options.SourceDir, tt.wantSourceDir)
			}
			if g.options.PublicPath != tt.wantPublicPath {
				t.Errorf("PublicPath = %q, want %q", g.options.PublicPath, tt.wantPublicPath)
			}
		})
	}
}

// BenchmarkExtractHydrationData benchmarks the hydration extraction with pre-compiled regex
func BenchmarkExtractHydrationData(b *testing.B) {
	html := `<html><body>
		<div data-hid="0">Counter 1</div>
		<script data-hid-data="0">{"id":0,"component":"Counter","props":{"count":1}}</script>
		<div data-hid="1">Counter 2</div>
		<script data-hid-data="1">{"id":1,"component":"Counter","props":{"count":2}}</script>
		<div data-hid="2">Counter 3</div>
		<script data-hid-data="2">{"id":2,"component":"Counter","props":{"count":3}}</script>
	</body></html>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractHydrationData(html)
	}
}

// BenchmarkEscapeScriptContent benchmarks the XSS escaping function
func BenchmarkEscapeScriptContent(b *testing.B) {
	// Simulate a realistic JSON payload with potential XSS content
	data := `[{"id":0,"component":"Counter","props":{"text":"Hello </script> world"}},{"id":1,"component":"Button","props":{"label":"Click </SCRIPT> me"}}]`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		escapeScriptContent(data)
	}
}

// BenchmarkInjectHydrationScripts benchmarks the full injection pipeline
func BenchmarkInjectHydrationScripts(b *testing.B) {
	g := &GXR{
		options: Options{
			PublicPath: "/public",
		},
	}

	html := `<html><body>
		<div data-hid="0">Counter</div>
		<script data-hid-data="0">{"id":0,"component":"Counter","props":{"count":0}}</script>
	</body></html>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.injectHydrationScripts(html)
	}
}
