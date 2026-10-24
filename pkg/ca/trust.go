package ca

import (
	"os"
	"path"
	"path/filepath"
)

const (
	debianAnchorDir = "/usr/local/share/ca-certificates"
	rhelAnchorDir   = "/etc/pki/ca-trust/source/anchors"
	anchorName      = "nexus-cli-ca.crt"
)

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func darwinKeychain() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "~"
	}
	return path.Join(filepath.ToSlash(home), "Library", "Keychains", "login.keychain-db")
}

// InstallCommands returns the commands that add certPath to the OS trust store for goos.
// It returns nil for unsupported platforms.
func InstallCommands(goos, certPath string) [][]string {
	return installCommands(goos, certPath, pathExists)
}

// UninstallCommands returns the commands that remove the nexus-cli CA from the OS trust store.
func UninstallCommands(goos, certPath string) [][]string {
	return uninstallCommands(goos, certPath, pathExists)
}

func installCommands(goos, certPath string, exists func(string) bool) [][]string {
	switch goos {
	case "linux":
		if exists(debianAnchorDir) {
			return [][]string{
				{"sudo", "cp", certPath, debianAnchorDir + "/" + anchorName},
				{"sudo", "update-ca-certificates"},
			}
		}
		return [][]string{
			{"sudo", "cp", certPath, rhelAnchorDir + "/" + anchorName},
			{"sudo", "update-ca-trust"},
		}
	case "darwin":
		return [][]string{
			{"security", "add-trusted-cert", "-r", "trustRoot", "-k", darwinKeychain(), certPath},
		}
	case "windows":
		return [][]string{
			{"certutil", "-user", "-addstore", "Root", certPath},
		}
	}
	return nil
}

func uninstallCommands(goos, certPath string, exists func(string) bool) [][]string {
	_ = certPath
	switch goos {
	case "linux":
		if exists(debianAnchorDir) {
			return [][]string{
				{"sudo", "rm", "-f", debianAnchorDir + "/" + anchorName},
				{"sudo", "update-ca-certificates", "--fresh"},
			}
		}
		return [][]string{
			{"sudo", "rm", "-f", rhelAnchorDir + "/" + anchorName},
			{"sudo", "update-ca-trust"},
		}
	case "darwin":
		return [][]string{
			{"security", "delete-certificate", "-c", CommonName, darwinKeychain()},
		}
	case "windows":
		return [][]string{
			{"certutil", "-user", "-delstore", "Root", CommonName},
		}
	}
	return nil
}
