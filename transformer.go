package gxr

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zbysir/gojsx"
)

// UseClientTransformer wraps the default esbuild transformer
// and adds hydration wrapper for "use client" components
type UseClientTransformer struct {
	inner *gojsx.EsBuildTransform
}

// Transform implements the gojsx.Transformer interface
func (t *UseClientTransformer) Transform(filePath string, src []byte, format gojsx.TransformerFormat) ([]byte, error) {
	code := string(src)
	trimmed := strings.TrimSpace(code)

	// Check if this is a "use client" component
	if strings.HasPrefix(trimmed, `"use client"`) || strings.HasPrefix(trimmed, `'use client'`) {
		code = wrapUseClientComponent(filePath, code)
	}

	// Pass to the inner esbuild transformer
	return t.inner.Transform(filePath, []byte(code), format)
}

// wrapUseClientComponent transforms a "use client" component to include hydration wrapper
func wrapUseClientComponent(filePath string, code string) string {
	// Get component name from file path
	componentName := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))

	// Remove "use client" directive
	useClientRegex := regexp.MustCompile(`^["']use client["'];?\s*`)
	code = useClientRegex.ReplaceAllString(strings.TrimSpace(code), "")

	// Find and transform the default export
	// Pattern: export default function Name(
	exportFuncRegex := regexp.MustCompile(`export\s+default\s+function\s+(\w+)\s*\(`)
	if matches := exportFuncRegex.FindStringSubmatch(code); len(matches) > 1 {
		funcName := matches[1]
		// Replace "export default function Name(" with "function Name("
		code = exportFuncRegex.ReplaceAllString(code, "function "+funcName+"(")

		// Add wrapper at the end with inline hydration data script
		code = code + fmt.Sprintf(`

// GXR: Auto-wrapped for SSR hydration
if (typeof globalThis.__HYDRATION_ID__ === "undefined") {
  globalThis.__HYDRATION_ID__ = 0;
}

function __GXR_Wrapper__(props) {
  if (typeof window === "undefined") {
    const id = globalThis.__HYDRATION_ID__++;
    const hydrationData = JSON.stringify({ id, component: "%s", props });
    return (
      <>
        <div data-hid={id}>
          <%s {...props} />
        </div>
        <script type="application/json" data-hid-data={id} dangerouslySetInnerHTML={{ __html: hydrationData }} />
      </>
    );
  }
  return <%s {...props} />;
}
export default __GXR_Wrapper__;
`, componentName, funcName, funcName)
	}

	return code
}
