package audit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func sampleEntries() []Entry {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	return []Entry{
		{Seq: 1, Time: now.Add(-48 * time.Hour), Agent: "a", Decision: "allow", Target: "old"},
		{Seq: 2, Time: now.Add(-time.Hour), Agent: "a", Decision: "deny", Target: "x,y", Reason: `said "no"` + "\nline2"},
		{Seq: 3, Time: now.Add(-time.Minute), Agent: "b", Decision: "allow", Target: "=HYPERLINK(\"evil\")", Scopes: []string{"s1", "s2"}},
	}
}

func TestFilter(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	es := sampleEntries()
	since, err := ParseSince("24h", now)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		f    Filter
		want []uint64
	}{
		{Filter{}, []uint64{1, 2, 3}},
		{Filter{Since: since}, []uint64{2, 3}},
		{Filter{Agent: "a"}, []uint64{1, 2}},
		{Filter{Decision: "DENY"}, []uint64{2}},
		{Filter{Since: since, Agent: "b", Decision: "allow"}, []uint64{3}},
	}
	for _, c := range cases {
		got := c.f.Apply(es)
		var seqs []uint64
		for _, e := range got {
			seqs = append(seqs, e.Seq)
		}
		if len(seqs) != len(c.want) {
			t.Fatalf("%+v: got %v want %v", c.f, seqs, c.want)
		}
		for i := range seqs {
			if seqs[i] != c.want[i] {
				t.Fatalf("%+v: got %v want %v", c.f, seqs, c.want)
			}
		}
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"":                     {},
		"90m":                  now.Add(-90 * time.Minute),
		"7d":                   now.Add(-7 * 24 * time.Hour),
		"2026-10-01T00:00:00Z": time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	} {
		got, err := ParseSince(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseSince("yesterday", now); err == nil {
		t.Fatal("expected error")
	}
}

func TestWriteCSVEscaping(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, sampleEntries()); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("output must be valid CSV: %v", err)
	}
	if len(recs) != 4 || strings.Join(recs[0], ",") != strings.Join(CSVHeader, ",") {
		t.Fatal(recs[0])
	}
	col := func(name string) int {
		for i, h := range CSVHeader {
			if h == name {
				return i
			}
		}
		t.Fatal(name)
		return -1
	}
	if recs[2][col("target")] != "x,y" || recs[2][col("reason")] != "said \"no\"\nline2" {
		t.Fatalf("round trip lost data: %q", recs[2])
	}
	if recs[3][col("target")] != `'=HYPERLINK("evil")` {
		t.Fatalf("formula not neutralized: %q", recs[3][col("target")])
	}
	if recs[3][col("scopes")] != "s1 s2" || recs[3][col("seq")] != "3" {
		t.Fatal(recs[3])
	}
}

func TestWriteJSONLKeepsVerifiableEntries(t *testing.T) {
	path, _ := writeSigned(t, 3)
	es, _ := ReadAll(path)
	var buf bytes.Buffer
	if err := WriteJSONL(&buf, es); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "copy.jsonl")
	os.WriteFile(out, buf.Bytes(), 0o600)
	if n, err := Verify(out); err != nil || n != 3 {
		t.Fatalf("exported jsonl should verify: %d %v", n, err)
	}
	var e Entry
	if err := json.Unmarshal(bytes.Split(buf.Bytes(), []byte("\n"))[0], &e); err != nil || e.Sig == "" {
		t.Fatal(err)
	}
}

func TestConfigOptions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NEXUS_HOME", home)
	t.Setenv("SIEM_TOKEN", "s3cret")
	var c Config
	src := `
max_bytes: 2048
fsync: false
sign: true
sinks:
  - {type: webhook, url: "http://127.0.0.1:1/ingest", headers: {Authorization: "Bearer ${SIEM_TOKEN}"}}
`
	if err := yaml.Unmarshal([]byte(src), &c); err != nil {
		t.Fatal(err)
	}
	o, err := c.Options()
	if err != nil {
		t.Fatal(err)
	}
	if o.Fsync || o.MaxBytes != 2048 || o.SigningKey == nil || len(o.Sinks) != 1 {
		t.Fatalf("%+v", o)
	}
	ws := o.Sinks[0].(*WebhookSink)
	if ws.o.Headers["Authorization"] != "Bearer s3cret" {
		t.Fatal(ws.o.Headers)
	}
	ws.o.CloseTimeout = 10 * time.Millisecond
	_ = ws.Close()
	if _, err := os.Stat(filepath.Join(home, "audit.key")); err != nil {
		t.Fatal("key should be created under NEXUS_HOME")
	}
	if _, err := os.Stat(filepath.Join(home, "audit.pub")); err != nil {
		t.Fatal("pub should be written")
	}

	if o, _ := (Config{}).Options(); !o.Fsync || o.SigningKey != nil {
		t.Fatal("defaults: fsync on, unsigned")
	}
	if _, err := (Config{Sinks: []SinkConfig{{Type: "carrier-pigeon"}}}).Options(); err == nil {
		t.Fatal("unknown sink should error")
	}

	l, err := Config{Sign: true}.Open()
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Log(Entry{Decision: "allow"})
	l.Close()
	if l.Path() != filepath.Join(home, "audit.jsonl") || l.KeyID() == "" {
		t.Fatal(l.Path(), l.KeyID())
	}
}
