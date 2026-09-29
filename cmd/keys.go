package cmd

import "github.com/whoisnjoguu/nexus-cli/pkg/jwt"

// resolveKeyPath returns the explicit flag value or falls back to the default persistent key path.
func resolveKeyPath(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	return jwt.DefaultKeyPath()
}
