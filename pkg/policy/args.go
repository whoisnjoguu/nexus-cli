package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// argsMatch reports whether every pattern in want matches the request arguments.
//
//   - Keys are dot paths into the arguments object ("path", "options.mode"). A literal key that
//     contains a dot is tried first. Traversing through an array visits every element.
//   - Values are glob patterns. A leading "!" negates the pattern.
//   - Patterns that start with "/", "~" or "./" are path patterns: "~" expands to the home
//     directory, both sides are cleaned (so "/workspace/../etc/passwd" is "/etc/passwd"), "*"
//     matches within one segment and "**" matches any number of segments. Path matching is
//     case-sensitive.
//   - Other patterns use "*" (any run of characters, including "/") and "?" (one character) and
//     are case-insensitive.
//   - When the argument is an array, a positive pattern matches if ANY element matches; a negated
//     pattern matches only if NO element matches.
//   - Non-string scalars are compared via fmt.Sprint (numbers, booleans); objects via their JSON.
//   - A missing key never matches, whether or not the pattern is negated.
func argsMatch(want map[string]string, args map[string]any) bool {
	for key, pattern := range want {
		values, ok := lookupArg(args, key)
		if !ok {
			return false
		}
		negate := strings.HasPrefix(pattern, "!")
		if negate {
			pattern = pattern[1:]
		}
		hit := false
		for _, v := range values {
			if argValueMatch(pattern, v) {
				hit = true
				break
			}
		}
		if negate == hit {
			return false
		}
	}
	return true
}

// lookupArg resolves a dot path to the list of leaf values it addresses (arrays are flattened).
func lookupArg(args map[string]any, key string) ([]any, bool) {
	if args == nil {
		return nil, false
	}
	if v, ok := args[key]; ok {
		return flatten(v), true
	}
	cur := []any{args}
	for _, part := range strings.Split(key, ".") {
		var next []any
		for _, c := range cur {
			for _, el := range flatten(c) {
				m, ok := el.(map[string]any)
				if !ok {
					continue
				}
				if v, ok := m[part]; ok {
					next = append(next, v)
				}
			}
		}
		if len(next) == 0 {
			return nil, false
		}
		cur = next
	}
	var out []any
	for _, c := range cur {
		out = append(out, flatten(c)...)
	}
	return out, true
}

func flatten(v any) []any {
	switch t := v.(type) {
	case []any:
		var out []any
		for _, e := range t {
			out = append(out, flatten(e)...)
		}
		return out
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out
	}
	return []any{v}
}

func argString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case nil:
		return ""
	case map[string]any:
		b, _ := json.Marshal(t)
		return string(b)
	}
	return fmt.Sprint(v)
}

func isPathPattern(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.HasPrefix(p, "./")
}

func argValueMatch(pattern string, v any) bool {
	s := argString(v)
	if isPathPattern(pattern) {
		if _, isStr := v.(string); !isStr {
			return false
		}
		return globPath(cleanArgPath(pattern), cleanArgPath(s))
	}
	return globText(strings.ToLower(pattern), strings.ToLower(s))
}

// cleanArgPath expands a leading "~" and normalizes the path to forward slashes.
func cleanArgPath(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			p = filepath.Join(home, p[1:])
		}
	}
	if p == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(p))
}

// globPath matches slash-separated paths where "**" spans any number of segments.
func globPath(pattern, p string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(p, "/"))
}

func matchSegments(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			rest := pat[1:]
			for i := 0; i <= len(segs); i++ {
				if matchSegments(rest, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		if ok, err := path.Match(pat[0], segs[0]); err != nil || !ok {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}

// globText matches "*" (any run, including "/") and "?" (one rune).
func globText(pattern, s string) bool {
	p, t := []rune(pattern), []rune(s)
	pi, ti := 0, 0
	star, mark := -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// argsFingerprint renders arg patterns deterministically (for one-time rule identity).
func argsFingerprint(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + m[k] + ";")
	}
	return b.String()
}
