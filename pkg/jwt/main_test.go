package jwt

import (
	"os"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestMain points go-keyring at its in-memory mock so tests never touch the real OS keychain.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}
