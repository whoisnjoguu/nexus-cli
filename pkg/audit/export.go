package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Filter selects entries for tail/export. Zero fields match everything.
type Filter struct {
	Since    time.Time
	Agent    string
	Decision string
}

// Match reports whether e passes the filter.
func (f Filter) Match(e Entry) bool {
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	if f.Agent != "" && e.Agent != f.Agent {
		return false
	}
	if f.Decision != "" && !strings.EqualFold(e.Decision, f.Decision) {
		return false
	}
	return true
}

// Apply returns the entries matching the filter.
func (f Filter) Apply(es []Entry) []Entry {
	out := es[:0:0]
	for _, e := range es {
		if f.Match(e) {
			out = append(out, e)
		}
	}
	return out
}

// ParseSince accepts a Go duration ("24h"), a day count ("7d"), or an RFC 3339 timestamp, and
// returns the absolute cutoff relative to now.
func ParseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if strings.HasSuffix(s, "d") {
		if n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64); err == nil && n >= 0 {
			return now.Add(-time.Duration(n * 24 * float64(time.Hour))), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d < 0 {
			d = -d
		}
		return now.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid --since %q (use e.g. 24h, 7d or an RFC 3339 time)", s)
}

// CSVHeader is the column order written by WriteCSV.
var CSVHeader = []string{"seq", "ts", "agent", "act_as", "tool", "target", "decision", "reason",
	"rule", "source", "session", "jti", "scopes", "args_hash", "key_id", "prev_hash", "hash", "sig"}

// WriteCSV writes entries as RFC 4180 CSV with a header row. Scopes are space-separated.
func WriteCSV(w io.Writer, es []Entry) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return err
	}
	for _, e := range es {
		seq := ""
		if e.Seq != 0 {
			seq = strconv.FormatUint(e.Seq, 10)
		}
		rec := []string{seq, e.Time.Format(time.RFC3339Nano), e.Agent, e.ActAs, e.Tool, e.Target,
			e.Decision, e.Reason, e.Rule, e.Source, e.Session, e.JTI, strings.Join(e.Scopes, " "),
			e.ArgsHash, e.KeyID, e.PrevHash, e.Hash, e.Sig}
		for i, v := range rec {
			rec[i] = csvSafe(v)
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe neutralizes spreadsheet formula injection: audit fields are attacker-influenced
// (targets, reasons), and exports are routinely opened in spreadsheet tools.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// WriteJSONL writes entries verbatim (hashes and signatures included) one per line.
func WriteJSONL(w io.Writer, es []Entry) error {
	enc := json.NewEncoder(w)
	for _, e := range es {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}
