package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

// VerifyOptions tightens verification beyond the hash chain.
type VerifyOptions struct {
	// PublicKeys verify Entry.Sig. Without keys, signatures are not checked (but signature
	// stripping after a signed entry is still detected).
	PublicKeys []ed25519.PublicKey
	// RequireSigned fails on any unsigned entry.
	RequireSigned bool
	// Anchor, when set, must be the hash of some entry in the chain (an externally stored head).
	Anchor string
}

// VerifyResult summarizes a successful (or partial, on error) verification.
type VerifyResult struct {
	Entries     int
	Signed      int
	Unsigned    int
	Files       int
	Head        string // hash of the last entry
	HeadSeq     uint64
	HeadTime    time.Time
	SigsChecked bool   // signatures were verified against PublicKeys
	AnchorSeq   uint64 // seq of the entry matching Anchor
}

// Verify re-walks the chain, confirming each entry's hash and its link to the previous entry.
func Verify(path string) (int, error) {
	res, err := VerifyWithOptions(path, VerifyOptions{})
	return res.Entries, err
}

// VerifyWithOptions walks the rotated set and the active file as a single chain, checking
// hashes, links, sequence numbers, signatures, signature downgrade and the optional anchor.
func VerifyWithOptions(path string, opts VerifyOptions) (VerifyResult, error) {
	var res VerifyResult
	files, err := Files(path)
	if err != nil {
		return res, err
	}
	res.Files = len(files)
	keys := make(map[string]ed25519.PublicKey, len(opts.PublicKeys))
	for _, k := range opts.PublicKeys {
		if len(k) == ed25519.PublicKeySize {
			keys[KeyID(k)] = k
		}
	}
	res.SigsChecked = len(keys) > 0

	prev := ""
	var seq uint64
	seenSigned := false
	anchorFound := false
	for _, name := range files {
		base := filepath.Base(name)
		err := scanFile(name, func(line []byte, lineNo int) error {
			n := res.Entries + 1
			where := fmt.Sprintf("entry %d (%s:%d)", n, base, lineNo)
			var e Entry
			if err := json.Unmarshal(line, &e); err != nil {
				return fmt.Errorf("%s: invalid json: %w", where, err)
			}
			if e.PrevHash != prev {
				return fmt.Errorf("%s: broken chain (prev_hash mismatch)", where)
			}
			if got := hashEntry(e); got != e.Hash {
				return fmt.Errorf("%s: hash mismatch (tampered)", where)
			}
			if e.Seq != 0 && e.Seq != seq+1 {
				return fmt.Errorf("%s: seq %d out of order (want %d)", where, e.Seq, seq+1)
			}
			seq = nextSeq(seq, e.Seq)
			if e.Sig == "" {
				if seenSigned {
					return fmt.Errorf("%s: unsigned entry after signed entries (signature stripped / downgrade)", where)
				}
				if opts.RequireSigned {
					return fmt.Errorf("%s: unsigned entry (signatures required)", where)
				}
				res.Unsigned++
			} else {
				seenSigned = true
				if res.SigsChecked {
					if err := checkSig(e, keys); err != nil {
						return fmt.Errorf("%s: %w", where, err)
					}
				}
				res.Signed++
			}
			if opts.Anchor != "" && e.Hash == opts.Anchor {
				anchorFound = true
				res.AnchorSeq = seq
			}
			prev = e.Hash
			res.Entries = n
			res.Head, res.HeadSeq, res.HeadTime = e.Hash, seq, e.Time
			return nil
		})
		if err != nil {
			return res, err
		}
	}
	if opts.Anchor != "" && !anchorFound {
		return res, fmt.Errorf("anchor %s not found in chain (history rewritten or truncated)", opts.Anchor)
	}
	return res, nil
}

func checkSig(e Entry, keys map[string]ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(e.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("malformed signature")
	}
	if e.KeyID != "" {
		k, ok := keys[e.KeyID]
		if !ok {
			return fmt.Errorf("signed by unknown key %s", e.KeyID)
		}
		if !ed25519.Verify(k, []byte(e.Hash), sig) {
			return fmt.Errorf("signature mismatch (key %s)", e.KeyID)
		}
		return nil
	}
	for _, k := range keys {
		if ed25519.Verify(k, []byte(e.Hash), sig) {
			return nil
		}
	}
	return fmt.Errorf("signature mismatch")
}
