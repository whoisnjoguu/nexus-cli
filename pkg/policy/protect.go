package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

// ReasonProtected is the Decision.Reason of a tool call denied by the built-in guard.
const ReasonProtected = "protected nexus file"

// SourceGuard is the Decision.Source of a guard decision.
const SourceGuard = "guard"

// guardTokenMax bounds the strings that are also split into shell-like words: command lines and
// paths, not file content.
const guardTokenMax = 4096

type guardSet struct {
	workspace string
	paths     []string // absolute, cleaned; both the lexical and symlink-resolved form of each
}

// SetProtectedPaths installs the built-in guard: any tool call whose arguments (recursively)
// contain a string that resolves inside one of paths is denied before policy rules run, so no
// rule, grant or reload can allow an agent to edit its own policy, pin, audit log or nexus home.
// Relative strings resolve against workspace (the agent's working directory). HTTP requests
// (Request.Args == nil) are not affected. Calling it with no paths disables the guard.
func (e *Engine) SetProtectedPaths(workspace string, paths []string) {
	if len(paths) == 0 {
		e.guard.Store(nil)
		return
	}
	if ws, err := filepath.Abs(workspace); err == nil {
		workspace = ws
	}
	g := &guardSet{workspace: workspace}
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			g.paths = append(g.paths, p)
		}
	}
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		lex := g.lexical(p)
		add(lex)
		add(resolveExisting(lex, 0))
	}
	e.guard.Store(g)
}

// ProtectedPaths returns the guarded paths (lexical and resolved forms).
func (e *Engine) ProtectedPaths() []string {
	g := e.guard.Load()
	if g == nil {
		return nil
	}
	return append([]string(nil), g.paths...)
}

// checkGuard reports whether req touches a protected path.
func (e *Engine) checkGuard(req Request) (Decision, bool) {
	g := e.guard.Load()
	if g == nil || req.Args == nil {
		return Decision{}, false
	}
	if g.hits(reflect.ValueOf(req.Args), 0) {
		return Decision{Action: ActionDeny, Reason: ReasonProtected, Source: SourceGuard}, true
	}
	return Decision{}, false
}

// guardMaxDepth bounds how deep the guard walks tool arguments. Anything nested deeper is
// treated as a hit: an argument the guard cannot inspect must not slip past it.
const guardMaxDepth = 1000

func (g *guardSet) hits(v reflect.Value, depth int) bool {
	if !v.IsValid() {
		return false
	}
	if depth > guardMaxDepth {
		return true
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return false
		}
		return g.hits(v.Elem(), depth+1)
	case reflect.String:
		return g.stringHits(v.String())
	case reflect.Map:
		it := v.MapRange()
		for it.Next() {
			if g.hits(it.Value(), depth+1) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			return false
		}
		for i := 0; i < v.Len(); i++ {
			if g.hits(v.Index(i), depth+1) {
				return true
			}
		}
	}
	return false
}

func (g *guardSet) stringHits(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if g.pathHits(s) {
		return true
	}
	// Command lines ("cat ~/.nexus/policy.yaml", "sed -i ... ./nexus.yaml"): check each word that
	// looks like a path.
	if len(s) > guardTokenMax || strings.ContainsAny(s, "\r\n") {
		return false
	}
	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || strings.ContainsRune(";|&<>()'\"`=,", r)
	})
	if len(words) < 2 && (len(words) == 0 || words[0] == s) {
		return false
	}
	for _, w := range words {
		if strings.ContainsAny(w, `/\`) || strings.HasPrefix(w, "~") || g.bareNameHits(w) {
			if g.pathHits(w) {
				return true
			}
		}
	}
	return false
}

// bareNameHits reports whether w is exactly the base name of a protected path in the workspace
// (e.g. "nexus.yaml" in "rm nexus.yaml").
func (g *guardSet) bareNameHits(w string) bool {
	for _, p := range g.paths {
		if sameName(filepath.Base(p), w) && sameName(filepath.Dir(p), g.workspace) {
			return true
		}
	}
	return false
}

func (g *guardSet) pathHits(s string) bool {
	lex := g.lexical(s)
	if lex == "" {
		return false
	}
	cands := []string{lex}
	if r := resolveExisting(lex, 0); r != lex {
		cands = append(cands, r)
	}
	for _, c := range cands {
		for _, p := range g.paths {
			if within(c, p) {
				return true
			}
		}
	}
	return false
}

// lexical turns an argument into an absolute cleaned path: file:// URLs are unwrapped, ~ is
// expanded and relative paths are joined to the workspace.
func (g *guardSet) lexical(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "file://") {
		s = s[len("file://"):]
		if runtime.GOOS == "windows" && strings.HasPrefix(s, "/") && len(s) > 2 && s[2] == ':' {
			s = s[1:]
		}
	}
	if s == "" || strings.ContainsRune(s, 0) {
		return ""
	}
	if s == "~" || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		s = filepath.Join(home, s[1:])
	}
	if !filepath.IsAbs(s) {
		s = filepath.Join(g.workspace, s)
	}
	return filepath.Clean(s)
}

// resolveExisting evaluates symlinks in the longest existing prefix of p (so a new file under a
// symlinked directory resolves to its real location), following dangling links too.
func resolveExisting(p string, depth int) string {
	if depth > 16 {
		return p
	}
	dir, rest := p, ""
	for {
		if r, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(r, rest)
		}
		if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			if t, err := os.Readlink(dir); err == nil {
				if !filepath.IsAbs(t) {
					t = filepath.Join(filepath.Dir(dir), t)
				}
				return resolveExisting(filepath.Join(filepath.Clean(t), rest), depth+1)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return p
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

func within(child, parent string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		child, parent = strings.ToLower(child), strings.ToLower(parent)
	}
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func sameName(a, b string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
