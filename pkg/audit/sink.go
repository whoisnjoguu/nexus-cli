package audit

// Sink ships durably-written entries off-box. Write must not block for long; errors are
// ignored by the Logger (a sink outage never fails an authorization decision).
type Sink interface {
	Write(Entry) error
	Close() error
}
