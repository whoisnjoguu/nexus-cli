package policy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/whoisnjoguu/nexus-cli/internal/atomicfile"
	"github.com/whoisnjoguu/nexus-cli/internal/fslock"
	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
)

// PinPath is the default pin file: $NEXUS_HOME/policy.pin (or ~/.nexus/policy.pin).
func PinPath() (string, error) {
	h, err := audit.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "policy.pin"), nil
}

// PinMismatchError reports a policy file whose content differs from its pinned hash.
type PinMismatchError struct {
	Path   string
	Pinned string
	Actual string
}

func (e *PinMismatchError) Error() string {
	return fmt.Sprintf("policy %s does not match its pin (sha256:%s, pinned sha256:%s); review the change, then run 'nexus-cli policy pin' or restart with --accept-policy-change",
		e.Path, ShortSum(e.Actual), ShortSum(e.Pinned))
}

var pinLine = regexp.MustCompile(`^([0-9a-f]{64})\s+\*?(.+)$`)

// pinKey is the absolute, cleaned form a policy path is pinned under.
func pinKey(policyPath string) string {
	if abs, err := filepath.Abs(policyPath); err == nil {
		policyPath = abs
	}
	return filepath.Clean(policyPath)
}

// readPins parses a pin file (sha256sum format: "<hex>  <absolute path>" per line).
func readPins(pinFile string) (map[string]string, error) {
	data, err := os.ReadFile(pinFile)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	pins := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := pinLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("%s:%d: malformed pin line", pinFile, n)
		}
		pins[m[2]] = m[1]
	}
	return pins, sc.Err()
}

// ReadPin returns the pinned sha256 of policyPath, if any.
func ReadPin(pinFile, policyPath string) (sum string, ok bool, err error) {
	pins, err := readPins(pinFile)
	if err != nil {
		return "", false, err
	}
	sum, ok = pins[pinKey(policyPath)]
	return sum, ok, nil
}

// WritePin records sum as the approved hash of policyPath. An empty sum removes the entry.
func WritePin(pinFile, policyPath, sum string) error {
	if err := os.MkdirAll(filepath.Dir(pinFile), 0o700); err != nil {
		return err
	}
	release, err := fslock.Acquire(pinFile + ".lock")
	if err != nil {
		return err
	}
	defer release()
	pins, err := readPins(pinFile)
	if err != nil {
		return err
	}
	key := pinKey(policyPath)
	if sum == "" {
		delete(pins, key)
	} else {
		pins[key] = strings.ToLower(sum)
	}
	keys := make([]string, 0, len(pins))
	for k := range pins {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# nexus-cli policy pins: sha256 of approved policy files (nexus-cli policy pin)\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s  %s\n", pins[k], k)
	}
	return atomicfile.Write(pinFile, []byte(b.String()), 0o600)
}

// CheckPin verifies data against the pin of policyPath. It returns (pinned=false, nil) when the
// path has no pin and a *PinMismatchError when it is pinned to a different hash.
func CheckPin(pinFile, policyPath string, data []byte) (pinned bool, err error) {
	want, ok, err := ReadPin(pinFile, policyPath)
	if err != nil || !ok {
		return false, err
	}
	if got := Sum(data); got != want {
		return true, &PinMismatchError{Path: policyPath, Pinned: want, Actual: got}
	}
	return true, nil
}
