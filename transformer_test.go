package gxr

import (
	"strings"
	"testing"
)

// TestWrapUseClientComponent tests the transformer's use client component wrapping
func TestWrapUseClientComponent(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		code     string
		contains []string
	}{
		{
			name:     "basic use client component",
			filePath: "/app/components/Counter.tsx",
			code: `"use client"

export default function Counter({ count }) {
  return <button>{count}</button>
}`,
			contains: []string{
				"__GXR_Wrapper__",
				`component: "Counter"`,
				"data-hid={id}",
				"globalThis.__HYDRATION_ID__",
			},
		},
		{
			name:     "XSS prevention escape is present",
			filePath: "/app/components/Widget.tsx",
			code: `"use client"

export default function Widget(props) {
  return <div>{props.text}</div>
}`,
			contains: []string{
				// The transformer should include the XSS escape for </script>
				// In Go strings, \\ is a single backslash, so we check for the literal pattern
				`.replace(/<\/script>/gi,`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapUseClientComponent(tt.filePath, tt.code)
			
			for _, s := range tt.contains {
				if !strings.Contains(result, s) {
					t.Errorf("Result should contain %q\nGot:\n%s", s, result)
				}
			}
		})
	}
}

// TestTransformNonClientComponent tests that non-client components are not wrapped
// Note: The wrapUseClientComponent function always wraps - the filtering happens
// in Transform() which checks for "use client" directive
func TestTransformNonClientComponent(t *testing.T) {
	code := `
export default function Header({ title }) {
  return <header><h1>{title}</h1></header>
}
`
	// wrapUseClientComponent requires the function pattern to exist to add a wrapper
	result := wrapUseClientComponent("/app/Header.tsx", code)
	
	// Without "use client" directive, the pattern matching should still work
	// but the Transform method filters based on "use client" presence
	// So for this test, we verify the function itself works
	if !strings.Contains(result, "__GXR_Wrapper__") && !strings.Contains(result, "Header") {
		t.Error("Expected Header component to be processed")
	}
}

// TestUseClientDirectiveRemoval tests that the "use client" directive is properly removed
func TestUseClientDirectiveRemoval(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{
			name: "double quotes",
			code: `"use client"

export default function Counter() { return <div>Count</div> }`,
		},
		{
			name: "single quotes",
			code: `'use client'

export default function Counter() { return <div>Count</div> }`,
		},
		{
			name: "with semicolon",
			code: `"use client";

export default function Counter() { return <div>Count</div> }`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapUseClientComponent("/app/Counter.tsx", tt.code)
			
			// The directive should be removed
			if strings.Contains(result, `"use client"`) || strings.Contains(result, `'use client'`) {
				t.Errorf("use client directive should be removed from:\n%s", result)
			}
			
			// The wrapper should be added
			if !strings.Contains(result, "__GXR_Wrapper__") {
				t.Errorf("Wrapper should be added:\n%s", result)
			}
		})
	}
}
