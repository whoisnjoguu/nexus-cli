package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/whoisnjoguu/nexus-cli/pkg/gate"
)

type recordingChecker struct {
	calls []gate.Call
}

func (c *recordingChecker) Begin(call gate.Call) (gate.Result, *gate.Pending) {
	c.calls = append(c.calls, call)
	return gate.Result{Allowed: call.Tool == "ok", Reason: "fuzz"}, nil
}

// FuzzCheckDecode drives POST /v1/check decoding with arbitrary bodies and content types. It
// must never panic, must answer with a known status, and may only reach the checker with a
// well-formed call.
func FuzzCheckDecode(f *testing.F) {
	for _, s := range []struct{ ct, body string }{
		{"application/json", `{"tool":"ok"}`},
		{"application/json", `{"method":"get","host":"api.good.com","path":"/x"}`},
		{"application/json; charset=utf-8", `{"tool":"fs__write","args":{"path":"/tmp/a","n":{"deep":[1,2,{"x":null}]}}}`},
		{"application/json", `{"tool":"t","args":null}`},
		{"application/json", `{"tool":"t","args":  {"a":1}  }`},
		{"application/json", `{"tool":"t","args":[1,2]}`},
		{"application/json", `{"tool":"t","args":"s"}`},
		{"application/json", `{"tool":"t","wait":"0"}`},
		{"application/json", `{"tool":"t","wait":"-5s"}`},
		{"application/json", `{"tool":"t","wait":"999999h"}`},
		{"application/json", `{"tool":"t"} {"tool":"u"}`},
		{"application/json", `{"tool":"t","unknown":1}`},
		{"application/json", `{}`},
		{"application/json", `null`},
		{"application/json", `[]`},
		{"application/json", ``},
		{"text/plain", `{"tool":"ok"}`},
		{"", `{"tool":"ok"}`},
		{"application/json; =", `{"tool":"ok"}`},
		{"application/json", `{"tool":"ok","scopes":["a",null]}`},
		{"application/json", `{"host":"x","token":"a.b.c","agent_id":"\u0000"}`},
		{"application/json", `{"tool":"t","args":{"a":1}}` + strings.Repeat(" ", maxCheckBodyBytes)},
	} {
		f.Add(s.ct, []byte(s.body))
	}
	f.Fuzz(func(t *testing.T, ct string, body []byte) {
		ck := &recordingChecker{}
		s := &Server{}
		s.SetChecker(ck)
		req := httptest.NewRequest(http.MethodPost, "/v1/check", bytes.NewReader(body))
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		s.handleCheck(rec, req)

		switch rec.Code {
		case http.StatusOK:
			if len(ck.calls) != 1 {
				t.Fatalf("200 with %d checker calls", len(ck.calls))
			}
			var out CheckResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || (out.Decision != "allow" && out.Decision != "deny") {
				t.Fatalf("bad 200 body %q: %v", rec.Body.String(), err)
			}
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
			if len(ck.calls) != 0 {
				t.Fatalf("status %d but the checker was called", rec.Code)
			}
		default:
			t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
		}
		if len(body) > maxCheckBodyBytes && rec.Code == http.StatusOK {
			t.Fatalf("accepted a %d-byte body", len(body))
		}
		for _, c := range ck.calls {
			if c.Tool == "" && c.Method == "" && c.Host == "" {
				t.Fatalf("checker got an empty call: %+v", c)
			}
			if c.Method != strings.ToUpper(c.Method) {
				t.Fatalf("method not upper-cased: %q", c.Method)
			}
			if (c.Args == nil) != (c.RawArgs == nil) {
				t.Fatalf("Args/RawArgs mismatch: %v / %q", c.Args, c.RawArgs)
			}
			if c.RawArgs != nil {
				var m map[string]any
				if err := json.Unmarshal(c.RawArgs, &m); err != nil || m == nil {
					t.Fatalf("RawArgs is not a JSON object: %q", c.RawArgs)
				}
			}
		}
	})
}
