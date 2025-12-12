# GXR v0.2 Contribution Plan

## Executive Summary

This document outlines the critical issues identified during the deep runtime audit of the GXR SSR engine, along with prioritized fixes to prepare it for production.

---

## Phase 1: Audit Findings

### 1. Security (CRITICAL) - XSS Vulnerability

**Location:** `gxr.go`, lines 145-146

**Issue:** The `hydrationData` extracted from inline scripts is injected directly into a `<script type="application/json">` tag without proper escaping:

```go
scripts := fmt.Sprintf(`<script id="__HYDRATION_DATA__" type="application/json">%s</script>`, hydrationData)
```

**Risk:** If component props contain the string `</script>`, an attacker could break out of the JSON script tag and inject arbitrary JavaScript.

**Fix:** Escape `</script>` sequences within the JSON payload.

---

### 2. Performance - Regex Compilation on Every Request

**Location:** `gxr.go`, lines 141, 158

**Issue:** Regular expressions are compiled on every call to `injectHydrationScripts()` and `extractHydrationData()`:

```go
cleanupRegex := regexp.MustCompile(`<script[^>]*data-hid-data="[^"]*"[^>]*>.*?</script>`)
dataRegex := regexp.MustCompile(`<script[^>]*data-hid-data="(\d+)"[^>]*>(.*?)</script>`)
```

**Impact:** `regexp.MustCompile()` is expensive. Compiling on every request wastes CPU cycles.

**Fix:** Move regex compilation to package-level variables (compile once at init).

---

### 3. Stability - No Panic Recovery

**Location:** `gxr.go`, `Render()` method

**Issue:** If a component panics during rendering (e.g., invalid JSX, runtime errors), the entire Go HTTP server could crash.

**Current State:** No `defer/recover` blocks protect the render pipeline.

**Fix:** Wrap render logic with `defer/recover` to convert panics into errors.

---

### 4. Performance - File Parsing on Every Request

**Location:** `gxr.go`, line 92

**Issue:** Each call to `Render()` invokes `g.jsx.Render(absPath, props)`, which may read and parse the TSX file from disk.

**Note:** The underlying `gojsx` library has internal caching via `hashicorp/golang-lru`. This may already mitigate the issue. However, we should verify and consider adding an explicit cache layer if needed.

**Status:** Lower priority - needs verification of gojsx caching behavior.

---

## Phase 2: Prioritized Implementation Plan

| Priority | Issue | Severity | Effort | Fix |
|----------|-------|----------|--------|-----|
| 1 | XSS in hydration injection | Critical | Low | Escape `</script>` in JSON |
| 2 | Regex compilation overhead | Medium | Low | Pre-compile at package level |
| 3 | No panic recovery | Medium | Low | Add defer/recover in Render() |
| 4 | Thread-safety verification | Low | Medium | Audit shared state |

---

## Phase 3: Implementation Checklist

### P1: Security - XSS Prevention
- [x] Create `escapeScriptContent()` helper function
- [x] Apply escaping to hydration JSON before injection
- [x] Add XSS escape in transformer JavaScript code
- [x] Add test case with malicious props containing `</script>`

### P2: Performance - Pre-compile Regexes
- [x] Move `cleanupRegex` to package-level var
- [x] Move `dataRegex` to package-level var
- [x] Move `scriptCloseRegex` to package-level var
- [x] Add benchmark test comparing before/after

### P3: Stability - Panic Recovery
- [x] Add `defer/recover` block in `Render()` method
- [x] Convert panics to descriptive errors
- [x] Add test case that verifies graceful error handling

---

## Testing Strategy

### Unit Tests
- Test XSS escaping with malicious payloads
- Test regex matching with edge cases
- Test panic recovery with intentionally broken components

### Benchmark Tests
- Benchmark `extractHydrationData` with pre-compiled regex
- Benchmark `injectHydrationScripts` with pre-compiled regex
- Compare memory allocations

---

## Rollout Checklist

- [x] All tests pass
- [x] No race conditions (`go test -race`)
- [x] Benchmark shows improvement
- [x] CodeQL security scan passes
- [x] Code review approved
