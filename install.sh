#!/bin/sh

set -eu

REPO="whoisnjoguu/nexus-cli"
BINARY="nexus-cli"
VERSION="${NEXUS_VERSION:-${1:-latest}}"

err() { printf 'error: %s\n' "$1" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- detect platform ---------------------------------------------------------
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
	linux) os="linux" ;;
	darwin) os="darwin" ;;
	*) err "unsupported OS: $os (use the Windows archive from the Releases page)" ;;
esac

arch="$(uname -m)"
case "$arch" in
	x86_64 | amd64) arch="amd64" ;;
	arm64 | aarch64) arch="arm64" ;;
	*) err "unsupported architecture: $arch" ;;
esac

have curl || have wget || err "need curl or wget"
have tar || err "need tar"

fetch() { # fetch URL -> stdout
	if have curl; then curl -fsSL "$1"; else wget -qO- "$1"; fi
}
download() { # download URL FILE
	if have curl; then curl -fsSL "$1" -o "$2"; else wget -qO "$2" "$1"; fi
}

# --- resolve version ---------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
	VERSION="$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
		| grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
	[ -n "$VERSION" ] || err "could not determine the latest release; set NEXUS_VERSION"
fi
# goreleaser archive uses the version without a leading "v".
ver_no_v="${VERSION#v}"

archive="${BINARY}_${ver_no_v}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$VERSION"

printf 'Installing %s %s (%s/%s)\n' "$BINARY" "$VERSION" "$os" "$arch"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
download "$base/$archive" "$tmp/$archive" || err "download failed: $base/$archive"

# --- optional checksum verification -----------------------------------------
if download "$base/checksums.txt" "$tmp/checksums.txt" 2>/dev/null; then
	if have sha256sum; then
		( cd "$tmp" && grep " $archive\$" checksums.txt | sha256sum -c - >/dev/null 2>&1 ) \
			&& printf 'checksum: ok\n' || printf 'checksum: WARNING could not verify\n' >&2
	elif have shasum; then
		( cd "$tmp" && grep " $archive\$" checksums.txt | shasum -a 256 -c - >/dev/null 2>&1 ) \
			&& printf 'checksum: ok\n' || printf 'checksum: WARNING could not verify\n' >&2
	fi
fi

tar -xzf "$tmp/$archive" -C "$tmp" || err "extract failed"
[ -f "$tmp/$BINARY" ] || err "binary not found in archive"
chmod +x "$tmp/$BINARY"

# --- install -----------------------------------------------------------------
dir="${INSTALL_DIR:-/usr/local/bin}"
if [ ! -d "$dir" ] || [ ! -w "$dir" ]; then
	dir="$HOME/.local/bin"
	mkdir -p "$dir"
fi
mv "$tmp/$BINARY" "$dir/$BINARY"

printf '\n✔ Installed %s to %s\n' "$BINARY" "$dir/$BINARY"
case ":$PATH:" in
	*":$dir:"*) : ;;
	*) printf 'note: add %s to your PATH:\n  export PATH="%s:$PATH"\n' "$dir" "$dir" ;;
esac
"$dir/$BINARY" version || true
