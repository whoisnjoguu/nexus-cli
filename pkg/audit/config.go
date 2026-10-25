package audit

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Config is the YAML shape for the `audit:` block of nexus.yaml, e.g.
//
//	audit:
//	  max_bytes: 10485760
//	  sign: true
//	  sinks:
//	    - {type: webhook, url: https://siem.example/ingest, headers: {Authorization: "Bearer ${SIEM_TOKEN}"}}
//	    - {type: syslog, network: udp, addr: logs.example:514}
type Config struct {
	Path     string       `yaml:"path,omitempty" json:"path,omitempty"`
	MaxBytes int64        `yaml:"max_bytes,omitempty" json:"max_bytes,omitempty"`
	Fsync    *bool        `yaml:"fsync,omitempty" json:"fsync,omitempty"` // default true
	Sign     bool         `yaml:"sign,omitempty" json:"sign,omitempty"`
	KeyPath  string       `yaml:"key_path,omitempty" json:"key_path,omitempty"` // default <nexus home>/audit.key
	Sinks    []SinkConfig `yaml:"sinks,omitempty" json:"sinks,omitempty"`
}

// SinkConfig configures one off-box sink. Header values and URLs undergo ${ENV} expansion so
// secrets need not live in the YAML file.
type SinkConfig struct {
	Type    string            `yaml:"type" json:"type"` // webhook | syslog
	URL     string            `yaml:"url,omitempty" json:"url,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Network string            `yaml:"network,omitempty" json:"network,omitempty"` // syslog: "", udp, tcp, unix…
	Addr    string            `yaml:"addr,omitempty" json:"addr,omitempty"`
	Tag     string            `yaml:"tag,omitempty" json:"tag,omitempty"`
}

// ResolvedPath returns Path or DefaultPath().
func (c Config) ResolvedPath() (string, error) {
	if c.Path != "" {
		return c.Path, nil
	}
	return DefaultPath()
}

// Options builds Logger options: loads/creates the signing key when Sign is set and
// constructs the sinks. On error, any sinks already created are closed.
func (c Config) Options() (Options, error) {
	o := DefaultOptions()
	if c.Fsync != nil {
		o.Fsync = *c.Fsync
	}
	o.MaxBytes = c.MaxBytes
	if c.Sign {
		kp := c.KeyPath
		if kp == "" {
			var err error
			if kp, err = DefaultKeyPath(); err != nil {
				return Options{}, err
			}
		}
		key, err := LoadOrCreateKey(kp)
		if err != nil {
			return Options{}, err
		}
		o.SigningKey = key
	}
	for i, sc := range c.Sinks {
		s, err := sc.Build()
		if err != nil {
			var errs []error
			for _, made := range o.Sinks {
				errs = append(errs, made.Close())
			}
			return Options{}, errors.Join(append([]error{fmt.Errorf("audit sink %d: %w", i, err)}, errs...)...)
		}
		o.Sinks = append(o.Sinks, s)
	}
	return o, nil
}

// Open opens the configured logger.
func (c Config) Open() (*Logger, error) {
	path, err := c.ResolvedPath()
	if err != nil {
		return nil, err
	}
	o, err := c.Options()
	if err != nil {
		return nil, err
	}
	l, err := OpenWithOptions(path, o)
	if err != nil {
		for _, s := range o.Sinks {
			_ = s.Close()
		}
		return nil, err
	}
	return l, nil
}

// Build constructs the sink.
func (sc SinkConfig) Build() (Sink, error) {
	switch strings.ToLower(sc.Type) {
	case "webhook", "http", "https":
		h := make(map[string]string, len(sc.Headers))
		for k, v := range sc.Headers {
			h[k] = os.ExpandEnv(v)
		}
		return NewWebhookSink(os.ExpandEnv(sc.URL), h)
	case "syslog":
		return NewSyslogSink(sc.Network, sc.Addr, sc.Tag)
	default:
		return nil, fmt.Errorf("unknown sink type %q (want webhook or syslog)", sc.Type)
	}
}
