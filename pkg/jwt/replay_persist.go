package jwt

import (
	"fmt"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/state"
)

// NewPersistentReplayGuard builds a replay guard whose consumed jtis live in the state file at
// path, so a single-use token stays spent across restarts and across nexus-cli processes sharing
// the file: the check and insert happen under a cross-process lock. Entries are kept until the
// token expires and pruned on every write. A storage failure rejects the token (fail closed).
func NewPersistentReplayGuard(path string) (*ReplayGuard, error) {
	st, err := state.Open(path)
	if err != nil {
		return nil, err
	}
	return &ReplayGuard{seen: make(map[string]time.Time), store: st}, nil
}

// DefaultReplayStatePath returns $NEXUS_HOME/state/jti.json.
func DefaultReplayStatePath() (string, error) { return state.DefaultPath("jti.json") }

func (g *ReplayGuard) usePersistent(jti string, expiry time.Time) error {
	// Keep every jti at least a minute so verifier clock-skew leeway can't outlive the entry.
	if floor := time.Now().Add(time.Minute); expiry.Before(floor) {
		expiry = floor
	}
	key := "jti:" + jti
	var replayed bool
	err := g.store.Update(func(m map[string]state.Entry) (bool, error) {
		if _, ok := m[key]; ok {
			replayed = true
			return false, nil
		}
		m[key] = state.Entry{Expires: expiry}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("replay store: %w", err)
	}
	if replayed {
		return fmt.Errorf("token replay detected for jti %s", jti)
	}
	return nil
}
