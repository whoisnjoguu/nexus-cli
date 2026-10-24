package policy

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"
)

// Severity grades a validation Issue.
type Severity string

const (
	SeverityError   Severity = "error"   // the policy is rejected
	SeverityWarning Severity = "warning" // the policy loads but probably does not do what was meant
)

// Issue is one problem found by Validate. Path addresses the offending field in YAML terms,
// e.g. "tools[3].match.host" or "default_action".
type Issue struct {
	Severity Severity `json:"severity"`
	Path     string   `json:"path"`
	Msg      string   `json:"message"`
}

func (i Issue) String() string {
	if i.Path == "" {
		return fmt.Sprintf("%s: %s", i.Severity, i.Msg)
	}
	return fmt.Sprintf("%s %s: %s", i.Severity, i.Path, i.Msg)
}

// CountIssues returns the number of errors and warnings.
func CountIssues(issues []Issue) (errs, warns int) {
	for _, i := range issues {
		if i.Severity == SeverityError {
			errs++
		} else {
			warns++
		}
	}
	return errs, warns
}

// ValidationError rejects a policy that has error-severity issues.
type ValidationError struct {
	Issues []Issue // errors only
}

func (e *ValidationError) Error() string {
	msgs := make([]string, len(e.Issues))
	for i, is := range e.Issues {
		msgs[i] = strings.TrimPrefix(is.String(), "error ")
	}
	return "invalid policy: " + strings.Join(msgs, "; ") + " (run 'nexus-cli policy lint' for details)"
}

// Check returns a *ValidationError when Validate reports errors (warnings are ignored).
func Check(p Policy) error {
	var errs []Issue
	for _, i := range Validate(p) {
		if i.Severity == SeverityError {
			errs = append(errs, i)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return &ValidationError{Issues: errs}
}

var httpMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
	"OPTIONS": true, "CONNECT": true, "TRACE": true,
}

func validAction(a Action) bool { return a == ActionAllow || a == ActionDeny || a == ActionHITL }

type validator struct{ issues []Issue }

func (v *validator) errf(p, format string, args ...any) {
	v.issues = append(v.issues, Issue{Severity: SeverityError, Path: p, Msg: fmt.Sprintf(format, args...)})
}

func (v *validator) warnf(p, format string, args ...any) {
	v.issues = append(v.issues, Issue{Severity: SeverityWarning, Path: p, Msg: fmt.Sprintf(format, args...)})
}

func (v *validator) action(p string, a Action) {
	if a != "" && !validAction(a) {
		v.errf(p, "unknown action %q (want allow|deny|hitl)", a)
	}
}

// Validate statically checks a policy. Errors make loaders reject the file; warnings flag rules
// that are legal but likely wrong (dead, shadowed or overly broad). NewEngine never validates.
func Validate(p Policy) []Issue {
	v := &validator{}
	v.action("default_action", p.DefaultAction)
	def := p.DefaultAction
	if def == "" {
		def = ActionDeny
	}

	for i, h := range p.Egress.Allow {
		v.hostPattern(fmt.Sprintf("egress.allow[%d]", i), h, true, true)
	}
	for i, h := range p.Egress.Passthrough {
		v.hostPattern(fmt.Sprintf("egress.passthrough[%d]", i), h, true, false)
	}

	names := make([]string, 0, len(p.Providers))
	for n := range p.Providers {
		names = append(names, n)
	}
	sort.Strings(names)
	seen := map[string]string{}
	for _, n := range names {
		pr := p.Providers[n]
		base := "providers." + n
		if strings.TrimSpace(n) == "" {
			v.errf("providers", "empty provider name")
		}
		if prev, dup := seen[strings.ToLower(n)]; dup {
			v.errf(base, "duplicate provider: %q and %q differ only in case", prev, n)
		} else {
			seen[strings.ToLower(n)] = n
		}
		v.action(base+".access", pr.Access)
		v.action(base+".credential", pr.Credential)
		if pr.Credential == ActionAllow {
			v.warnf(base+".credential", "allow hands raw provider tokens to the agent (not secretless); prefer hitl or deny")
		}
		for j, s := range pr.Scopes {
			if strings.TrimSpace(s) == "" {
				v.errf(fmt.Sprintf("%s.scopes[%d]", base, j), "empty scope")
			}
		}
	}

	for i, r := range p.Tools {
		v.rule(fmt.Sprintf("tools[%d]", i), r, def)
	}
	v.shadowed(p.Tools)
	return v.issues
}

func (v *validator) rule(base string, r Rule, def Action) {
	v.action(base+".action", r.Action)
	eff := r.Action
	if eff == "" {
		eff = def
	}
	m := r.Match
	isTool := m.Tool != "" || m.Provider != ""
	isHTTP := m.Method != "" || m.Host != "" || m.Path != ""
	switch {
	case !isTool && !isHTTP && len(m.Args) > 0:
		v.warnf(base+".match.args", "rule never matches: args only apply to rules with a tool or provider")
	case !isTool && !isHTTP:
		v.warnf(base+".match", "rule never matches: empty match (set tool, provider, method, host or path)")
	case isTool && isHTTP:
		v.warnf(base+".match", "method/host/path are ignored on tool rules (tool or provider is set)")
	}

	if m.Tool != "" {
		v.glob(base+".match.tool", strings.ToLower(m.Tool))
		if eff == ActionAllow {
			if m.Tool == "*" {
				v.warnf(base+".match.tool", "\"*\" allows every tool; list the tools you mean")
			} else if midWordGlob(m.Tool) {
				v.warnf(base+".match.tool", "%q starts mid-word and can match unintended tools (e.g. \"*get*\" matches \"forget_password\"); anchor it like \"get_*\" or \"*__get_*\"", m.Tool)
			}
		}
	}
	if m.Provider != "" {
		v.glob(base+".match.provider", strings.ToLower(m.Provider))
	}
	if m.Method != "" && m.Method != "*" && !httpMethods[strings.ToUpper(m.Method)] {
		v.errf(base+".match.method", "unknown HTTP method %q (want GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, CONNECT, TRACE or *)", m.Method)
	}
	if m.Host != "" {
		v.hostPattern(base+".match.host", m.Host, eff == ActionAllow, eff == ActionAllow)
	}
	if m.Path != "" {
		pp := base + ".match.path"
		v.glob(pp, strings.TrimSuffix(m.Path, "/**"))
		if !strings.HasPrefix(m.Path, "/") && !strings.HasPrefix(m.Path, "*") {
			v.warnf(pp, "rule never matches: request paths always start with \"/\" (got %q)", m.Path)
		}
	}
	keys := make([]string, 0, len(m.Args))
	for k := range m.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ap := base + ".match.args." + k
		if strings.TrimSpace(k) == "" {
			v.errf(base+".match.args", "empty argument key")
			continue
		}
		pat := strings.TrimPrefix(m.Args[k], "!")
		if isPathPattern(pat) {
			for _, seg := range strings.Split(cleanArgPath(pat), "/") {
				if seg != "**" && badGlob(seg) {
					v.errf(ap, "invalid glob %q: syntax error in pattern", m.Args[k])
					break
				}
			}
		}
	}

	if r.OneTime && eff != ActionAllow {
		v.errf(base+".one_time", "one_time requires action allow (effective action is %q)", eff)
	}
	if r.Inject && m.Host == "" {
		v.errf(base+".inject", "inject: true requires match.host (credentials are injected only for a specific upstream host)")
	}
	for j, t := range r.Taints {
		if strings.TrimSpace(t) == "" {
			v.errf(fmt.Sprintf("%s.taints[%d]", base, j), "empty taint label")
		}
	}
}

// glob reports an error for a malformed "*"/"?"/"[...]" pattern.
func (v *validator) glob(p, pattern string) {
	if badGlob(pattern) {
		v.errf(p, "invalid glob %q: syntax error in pattern", pattern)
	}
}

// badGlob reports whether path.Match rejects the pattern. Match may stop parsing early on a
// mismatch, so a few different names are tried.
func badGlob(pattern string) bool {
	for _, name := range []string{"", "a", "zzz", pattern} {
		if _, err := path.Match(pattern, name); err != nil {
			return true
		}
	}
	return false
}

// midWordGlob reports a leading "*" directly followed by a letter or digit ("*get*", "*read").
func midWordGlob(p string) bool {
	if len(p) < 2 || p[0] != '*' {
		return false
	}
	r := rune(p[1])
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// hostPattern validates an exact host or a leading "*." wildcard (the only forms hostMatch
// supports). broadWarn flags TLD-wide wildcards like "*.com".
func (v *validator) hostPattern(p, pat string, isEntry, broadWarn bool) {
	h := strings.TrimSpace(pat)
	if h == "" {
		if isEntry {
			v.errf(p, "empty host pattern")
		}
		return
	}
	if strings.Contains(h, "/") {
		v.errf(p, "host pattern %q must not contain a scheme or path", pat)
		return
	}
	if strings.Contains(h, "*") {
		rest := strings.TrimPrefix(h, "*.")
		if !strings.HasPrefix(h, "*.") || rest == "" || strings.ContainsAny(rest, "*") || strings.HasPrefix(rest, ".") {
			v.errf(p, "unsupported host pattern %q (use an exact host or a leading \"*.\" label, e.g. \"*.github.com\")", pat)
			return
		}
		if broadWarn && !strings.Contains(stripPort(rest), ".") {
			v.warnf(p, "%q matches every host under the %q top-level domain", pat, rest)
		}
	}
}

// shadowed warns about rules that can never be reached because an earlier rule matches every
// request they match (the first matching rule always decides).
func (v *validator) shadowed(rules []Rule) {
	for j := range rules {
		b := rules[j].Match
		if !matchCanHit(b) {
			continue
		}
		for i := 0; i < j; i++ {
			a := rules[i].Match
			if matchCanHit(a) && matchCovers(a, b) {
				v.warnf(fmt.Sprintf("tools[%d]", j), "unreachable: shadowed by tools[%d] (the first matching rule wins)", i)
				break
			}
		}
	}
}

func isToolMatch(m Match) bool { return m.Tool != "" || m.Provider != "" }

func matchCanHit(m Match) bool {
	return isToolMatch(m) || m.Method != "" || m.Host != "" || m.Path != ""
}

func hasGlobMeta(s string) bool { return strings.ContainsAny(s, "*?[") }

// coverField reports whether pattern a matches everything pattern b matches (conservatively).
func coverField(a, b string, match func(pat, v string) bool) bool {
	switch {
	case a == "":
		return true
	case b == "":
		return false
	case strings.EqualFold(a, b):
		return true
	case !hasGlobMeta(b):
		return match(a, b)
	}
	return false
}

// matchCovers reports whether every request matched by b is also matched by a.
func matchCovers(a, b Match) bool {
	if isToolMatch(a) != isToolMatch(b) {
		return false
	}
	if isToolMatch(a) {
		return coverField(a.Tool, b.Tool, toolMatch) &&
			coverField(a.Provider, b.Provider, toolMatch) &&
			(len(a.Args) == 0 || argsFingerprint(a.Args) == argsFingerprint(b.Args))
	}
	methodOK := a.Method == "" || a.Method == "*" || strings.EqualFold(a.Method, b.Method)
	hostOK := coverField(a.Host, b.Host, hostMatch)
	// Paths match case-sensitively, so unlike tools and hosts "/API" does not cover "/api".
	pathOK := a.Path == "" || a.Path == b.Path || (b.Path != "" && !hasGlobMeta(b.Path) && pathMatch(a.Path, b.Path)) ||
		(strings.HasSuffix(a.Path, "/**") && strings.HasSuffix(b.Path, "/**") &&
			strings.HasPrefix(b.Path, strings.TrimSuffix(a.Path, "**")))
	return methodOK && hostOK && pathOK
}
