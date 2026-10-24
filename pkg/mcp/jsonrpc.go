package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// rpcMessage is a superset that captures requests, notifications and responses.
type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func hasID(id json.RawMessage) bool {
	return len(id) > 0 && !bytes.Equal(bytes.TrimSpace(id), []byte("null"))
}

func (m rpcMessage) isRequest() bool      { return m.Method != "" && hasID(m.ID) }
func (m rpcMessage) isNotification() bool { return m.Method != "" && !hasID(m.ID) }
func (m rpcMessage) isResponse() bool     { return m.Method == "" && hasID(m.ID) }

// outgoing is a unified frame for replies, notifications and server-initiated requests.
type outgoing struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  any             `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("%s (code %d)", e.Message, e.Code) }

const (
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	codeServerError    = -32000 // gateway-side failure (upstream unavailable, timeout, ...)
	codeDenied         = -32001 // blocked by the Nexus policy
	codeUserRejected   = -1     // MCP convention for a human rejecting a sampling request
)

func newErr(code int, msg string) *rpcError { return &rpcError{Code: code, Message: msg} }

// asRPCError extracts a JSON-RPC error from err, wrapping others as server errors.
func asRPCError(err error) *rpcError {
	var re *rpcError
	if errors.As(err, &re) {
		return re
	}
	return newErr(codeServerError, err.Error())
}

func notification(method string, params any) outgoing {
	return outgoing{JSONRPC: "2.0", Method: method, Params: params}
}

// sink is a destination for outbound JSON-RPC frames (a stdio pipe, an SSE stream, ...).
type sink interface {
	send(v any) error
}

// writerSink writes newline-delimited JSON, serializing concurrent writers.
type writerSink struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *writerSink) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.w.Write(append(b, '\n'))
	return err
}

// decodeObject decodes a JSON object preserving numbers verbatim; invalid or empty input yields nil.
func decodeObject(raw json.RawMessage) map[string]any {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		return nil
	}
	return m
}

// idKey normalizes a JSON-RPC id for use as a map key ("1" and 1 stay distinct).
func idKey(id json.RawMessage) string { return strings.TrimSpace(string(id)) }

func textResult(isErr bool, text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isErr,
	}
}
