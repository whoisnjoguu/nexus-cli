package mcp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

func policyRequest(tool, provider string, args map[string]any) policy.Request {
	return policy.Request{Tool: tool, Provider: provider, Args: args}
}

// allTools returns the local tools plus every live upstream's namespaced tools.
func (s *Server) allTools() []map[string]any {
	out := toolDefs()
	for _, u := range s.upstreams {
		u.mu.Lock()
		if u.state == stateUp {
			out = append(out, u.tools...)
		}
		u.mu.Unlock()
	}
	return out
}

func (s *Server) rebuildRoutes() {
	route := make(map[string]*upstream)
	for _, u := range s.upstreams {
		u.mu.Lock()
		for _, td := range u.tools {
			if name, ok := td["name"].(string); ok {
				route[name] = u
			}
		}
		u.mu.Unlock()
	}
	s.routeMu.Lock()
	s.toolRoute = route
	s.routeMu.Unlock()
}

// toolsChanged rebuilds routing and tells every client the tool list changed.
func (s *Server) toolsChanged() {
	s.rebuildRoutes()
	s.status.kick()
	if s.baseCtx.Err() == nil {
		s.broadcast("notifications/tools/list_changed", map[string]any{})
	}
}

func (s *Server) routeTool(name string) *upstream {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	return s.toolRoute[name]
}

// upstreamForName finds the upstream owning a namespaced name ("<upstream>__<name>").
func (s *Server) upstreamForName(name string) *upstream {
	for _, u := range s.upstreams {
		if strings.HasPrefix(name, u.prefix) {
			return u
		}
	}
	return nil
}

func (s *Server) upstreamByName(name string) *upstream {
	for _, u := range s.upstreams {
		if u.name == name {
			return u
		}
	}
	return nil
}

// progressRoute maps a progress token seen on one upstream back to the client that asked for
// progress, and to the token that client used.
type progressRoute struct {
	rel  *relation
	orig any
}

func progressKey(u *upstream, tok any) string { return u.name + "\x00" + string(mustJSON(tok)) }

// trackProgress registers params._meta.progressToken so the upstream's notifications/progress
// reach the requesting client. The client's token is passed through unchanged; only if another
// in-flight request already uses the same token on this upstream (e.g. two HTTP sessions) is it
// replaced by a gateway-unique one, mapped back on the way out. It returns a cleanup func.
func (s *Server) trackProgress(u *upstream, params map[string]any, rel *relation) func() {
	meta, _ := params["_meta"].(map[string]any)
	if meta == nil {
		return func() {}
	}
	orig, ok := meta["progressToken"]
	if !ok || orig == nil {
		return func() {}
	}
	s.progMu.Lock()
	key := progressKey(u, orig)
	if _, taken := s.progress[key]; taken {
		s.progSeq++
		tok := "nexus-progress-" + strconv.Itoa(s.progSeq)
		meta["progressToken"] = tok
		key = progressKey(u, tok)
	}
	s.progress[key] = progressRoute{rel: rel, orig: orig}
	s.progMu.Unlock()
	return func() {
		s.progMu.Lock()
		delete(s.progress, key)
		s.progMu.Unlock()
	}
}

func (s *Server) forwardProgress(u *upstream, raw json.RawMessage) {
	params := decodeObject(raw)
	if params == nil {
		return
	}
	s.progMu.Lock()
	route, ok := s.progress[progressKey(u, params["progressToken"])]
	s.progMu.Unlock()
	if !ok {
		return
	}
	params["progressToken"] = route.orig
	_ = route.rel.out.send(notification("notifications/progress", params))
}

// callUpstreamTool forwards an approved tool call, stripping the namespace and passing through
// any other params (such as _meta) verbatim.
func (s *Server) callUpstreamTool(rc *reqCtx, up *upstream, prefixedName string) (any, *rpcError) {
	params := decodeObject(rc.params)
	if params == nil {
		params = map[string]any{}
	}
	params["name"] = strings.TrimPrefix(prefixedName, up.prefix)
	rel := rc.rel()
	defer s.trackProgress(up, params, rel)()
	res, err := up.call(rc.ctx, "tools/call", params, rel)
	if err != nil {
		return textResult(true, "upstream call failed: "+err.Error()), nil
	}
	return res, nil
}

// passthrough forwards a request to an upstream, keeping the client's params and progress token.
func (s *Server) passthrough(rc *reqCtx, u *upstream, method string, params map[string]any) (any, *rpcError) {
	rel := rc.rel()
	defer s.trackProgress(u, params, rel)()
	res, err := u.call(rc.ctx, method, params, rel)
	if err != nil {
		return nil, asRPCError(err)
	}
	return res, nil
}

// advertisedCapabilities is the union of what the upstreams offer, plus our tools.
func (s *Server) advertisedCapabilities() map[string]any {
	caps := map[string]any{"tools": map[string]any{"listChanged": true}}
	var resources, subscribe, prompts, logging, completions bool
	for _, u := range s.upstreams {
		resources = resources || u.hasCap("resources")
		subscribe = subscribe || u.subCap("resources", "subscribe")
		prompts = prompts || u.hasCap("prompts")
		logging = logging || u.hasCap("logging")
		completions = completions || u.hasCap("completions")
	}
	if resources {
		caps["resources"] = map[string]any{"listChanged": true, "subscribe": subscribe}
	}
	if prompts {
		caps["prompts"] = map[string]any{"listChanged": true}
	}
	if logging {
		caps["logging"] = map[string]any{}
	}
	if completions {
		caps["completions"] = map[string]any{}
	}
	return caps
}

// pageCursor is the composite cursor: which upstream, and that upstream's own cursor.
type pageCursor struct {
	U int    `json:"u"`
	C string `json:"c,omitempty"`
}

func encodeCursor(c pageCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (pageCursor, error) {
	var c pageCursor
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.U < 0 {
		return c, errors.New("negative index")
	}
	return c, nil
}

// listPaged serves resources/list, resources/templates/list and prompts/list across upstreams:
// each page is one page of one upstream, and nextCursor encodes where to continue.
func (s *Server) listPaged(rc *reqCtx, method, key, capName string, each func(*upstream, map[string]any)) (any, *rpcError) {
	var p struct {
		Cursor string `json:"cursor"`
	}
	_ = json.Unmarshal(rc.params, &p)
	cur := pageCursor{}
	if p.Cursor != "" {
		c, err := decodeCursor(p.Cursor)
		if err != nil {
			return nil, newErr(codeInvalidParams, "invalid cursor")
		}
		cur = c
	}
	eligible := func(u *upstream) bool { return u.isUp() && u.hasCap(capName) }
	nextFrom := func(i int) int {
		for j := i; j < len(s.upstreams); j++ {
			if eligible(s.upstreams[j]) {
				return j
			}
		}
		return -1
	}
	for i := nextFrom(cur.U); i >= 0; i = nextFrom(i + 1) {
		u := s.upstreams[i]
		params := map[string]any{}
		if i == cur.U && cur.C != "" {
			params["cursor"] = cur.C
		}
		res, err := u.call(rc.ctx, method, params, rc.rel())
		if err != nil {
			if rc.ctx.Err() != nil {
				return nil, asRPCError(err)
			}
			s.logf("%s on upstream %s: %v", method, u.name, err)
			continue
		}
		var page map[string]json.RawMessage
		if err := json.Unmarshal(res, &page); err != nil {
			s.logf("%s on upstream %s: bad result: %v", method, u.name, err)
			continue
		}
		var items []map[string]any
		_ = json.Unmarshal(page[key], &items)
		if items == nil {
			items = []map[string]any{}
		}
		if each != nil {
			for _, it := range items {
				each(u, it)
			}
		}
		var inner string
		_ = json.Unmarshal(page["nextCursor"], &inner)
		out := map[string]any{key: items}
		if inner != "" {
			out["nextCursor"] = encodeCursor(pageCursor{U: i, C: inner})
		} else if j := nextFrom(i + 1); j >= 0 {
			out["nextCursor"] = encodeCursor(pageCursor{U: j})
		}
		return out, nil
	}
	return map[string]any{key: []map[string]any{}}, nil
}

func (s *Server) setURIOwner(uri string, u *upstream) {
	s.uriMu.Lock()
	s.uriOwner[uri] = u
	s.uriMu.Unlock()
}

func (s *Server) uriCandidates(uri, capName string) []*upstream {
	s.uriMu.Lock()
	owner := s.uriOwner[uri]
	s.uriMu.Unlock()
	if owner != nil {
		return []*upstream{owner}
	}
	var out []*upstream
	for _, u := range s.upstreams {
		if u.isUp() && u.hasCap(capName) {
			out = append(out, u)
		}
	}
	return out
}

func (s *Server) handleResourceRead(rc *reqCtx) (any, *rpcError) {
	params := decodeObject(rc.params)
	uri, _ := params["uri"].(string)
	if uri == "" {
		return nil, newErr(codeInvalidParams, "uri is required")
	}
	cands := s.uriCandidates(uri, "resources")
	if len(cands) == 0 {
		return nil, newErr(-32002, "resource not found: "+uri)
	}
	var last *rpcError
	for _, u := range cands {
		preq := policyRequest("resources/read", u.name, map[string]any{"uri": uri})
		az := s.authorize(rc, preq)
		s.recordTool(rc, "resources/read", u.name, mustJSON(map[string]any{"uri": uri}), az)
		if !az.allowed {
			return nil, newErr(codeDenied, "resource read denied by Nexus guardrail: "+az.reason)
		}
		res, rerr := s.passthrough(rc, u, "resources/read", params)
		if rerr == nil {
			s.setURIOwner(uri, u)
			return res, nil
		}
		if rc.ctx.Err() != nil {
			return nil, rerr
		}
		last = rerr
	}
	return nil, last
}

func (s *Server) handleSubscribe(rc *reqCtx) (any, *rpcError) {
	params := decodeObject(rc.params)
	uri, _ := params["uri"].(string)
	if uri == "" {
		return nil, newErr(codeInvalidParams, "uri is required")
	}
	var target *upstream
	for _, u := range s.uriCandidates(uri, "resources") {
		if u.subCap("resources", "subscribe") {
			target = u
			break
		}
	}
	if target == nil {
		return nil, newErr(codeMethodNotFound, "no upstream supports subscribing to "+uri)
	}
	res, rerr := s.passthrough(rc, target, rc.method, params)
	if rerr != nil {
		return nil, rerr
	}
	s.subMu.Lock()
	if rc.method == "resources/subscribe" {
		if s.subs[uri] == nil {
			s.subs[uri] = make(map[*clientSession]bool)
		}
		s.subs[uri][rc.sess] = true
	} else if subs := s.subs[uri]; subs != nil {
		delete(subs, rc.sess)
		if len(subs) == 0 {
			delete(s.subs, uri)
		}
	}
	s.subMu.Unlock()
	return res, nil
}

// notifySubscribers forwards resources/updated to the sessions subscribed to uri (all if none).
func (s *Server) notifySubscribers(uri string, params json.RawMessage) {
	s.subMu.Lock()
	var targets []*clientSession
	for ss := range s.subs[uri] {
		targets = append(targets, ss)
	}
	s.subMu.Unlock()
	if len(targets) == 0 {
		targets = s.liveSessions()
	}
	for _, ss := range targets {
		_ = ss.def.send(notification("notifications/resources/updated", params))
	}
}

func (s *Server) handlePromptGet(rc *reqCtx) (any, *rpcError) {
	params := decodeObject(rc.params)
	name, _ := params["name"].(string)
	u := s.upstreamForName(name)
	if u == nil || name == u.prefix {
		return nil, newErr(codeInvalidParams, "unknown prompt: "+name)
	}
	real := strings.TrimPrefix(name, u.prefix)
	args := map[string]any{"name": real}
	if a, ok := params["arguments"]; ok {
		args["arguments"] = a
	}
	preq := policyRequest("prompts/get", u.name, args)
	az := s.authorize(rc, preq)
	s.recordTool(rc, "prompts/get", u.name, mustJSON(args), az)
	if !az.allowed {
		return nil, newErr(codeDenied, "prompt denied by Nexus guardrail: "+az.reason)
	}
	params["name"] = real
	return s.passthrough(rc, u, "prompts/get", params)
}

func (s *Server) handleComplete(rc *reqCtx) (any, *rpcError) {
	params := decodeObject(rc.params)
	ref, _ := params["ref"].(map[string]any)
	empty := map[string]any{"completion": map[string]any{"values": []string{}, "hasMore": false}}
	if ref == nil {
		return nil, newErr(codeInvalidParams, "ref is required")
	}
	var u *upstream
	switch ref["type"] {
	case "ref/prompt":
		name, _ := ref["name"].(string)
		if u = s.upstreamForName(name); u != nil {
			ref["name"] = strings.TrimPrefix(name, u.prefix)
		}
	case "ref/resource":
		uri, _ := ref["uri"].(string)
		for _, c := range s.uriCandidates(uri, "completions") {
			if c.hasCap("completions") {
				u = c
				break
			}
		}
	}
	if u == nil || !u.hasCap("completions") {
		return empty, nil
	}
	return s.passthrough(rc, u, "completion/complete", params)
}

func (s *Server) handleSetLevel(rc *reqCtx) (any, *rpcError) {
	params := decodeObject(rc.params)
	for _, u := range s.upstreams {
		if !u.isUp() || !u.hasCap("logging") {
			continue
		}
		if _, err := u.call(rc.ctx, "logging/setLevel", params, rc.rel()); err != nil {
			s.logf("logging/setLevel on %s: %v", u.name, err)
		}
	}
	return map[string]any{}, nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
