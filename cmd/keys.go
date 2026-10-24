package cmd

import "github.com/whoisnjoguu/nexus-cli/pkg/jwt"

// resolveKeyPath returns the explicit flag value or falls back to the default persistent key path.
func resolveKeyPath(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	return jwt.DefaultKeyPath()
}

// resolveKeyTarget returns the key path for --key and the backend selected by NEXUS_KEY_BACKEND.
func resolveKeyTarget(flag string) (string, jwt.Backend, error) {
	path, err := resolveKeyPath(flag)
	if err != nil {
		return "", "", err
	}
	b, err := jwt.BackendFromEnv()
	if err != nil {
		return "", "", err
	}
	return path, b, nil
}
