#!/usr/bin/env bash
# Checks a built APT repo with real apt before it is published:
# signature, hashes, package version, and no private key material.
set -euo pipefail

REPO_DIR=$(realpath "${1:?usage: verify.sh <repo-dir> <version>}")
VERSION=${2:?usage: verify.sh <repo-dir> <version>}
ARCHITECTURES=${ARCHITECTURES:-"amd64 arm64"}
PORT=${APT_VERIFY_PORT:-18765}
WORK=$(mktemp -d)
SERVER_PID=""

cleanup() {
	if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
	rm -rf "$WORK"
}
trap cleanup EXIT

if grep -rlqa -e 'PRIVATE KEY' "$REPO_DIR"; then
	echo "private key material found in $REPO_DIR" >&2
	exit 1
fi

python3 -I -m http.server "$PORT" --bind 127.0.0.1 --directory "$REPO_DIR" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1

for arch in $ARCHITECTURES; do
	root="$WORK/$arch"
	mkdir -p "$root/state/lists/partial" "$root/cache/archives/partial" "$root/download"
	touch "$root/status"
	echo "deb [signed-by=$REPO_DIR/signing-key.gpg] http://127.0.0.1:$PORT stable main" >"$root/sources.list"
	options=(
		-o "Dir::State=$root/state"
		-o "Dir::State::status=$root/status"
		-o "Dir::Cache=$root/cache"
		-o "Dir::Etc::sourcelist=$root/sources.list"
		-o "Dir::Etc::sourceparts=/dev/null"
		-o "APT::Architecture=$arch"
		-o "APT::Architectures::=$arch"
		-o "Acquire::AllowInsecureRepositories=false"
		-o "Debug::NoDropPrivs=1"
	)
	apt-get "${options[@]}" --error-on=any update
	(cd "$root/download" && apt-get "${options[@]}" download flotte)

	deb="$root/download/flotte_${VERSION}_${arch}.deb"
	[[ "$(dpkg-deb -f "$deb" Version)" == "$VERSION" ]]
	[[ "$(dpkg-deb -f "$deb" Architecture)" == "$arch" ]]
	dpkg-deb -c "$deb" | grep -Eq '^-rwxr-xr-x root/root .* \./usr/bin/flotte$'
done

echo "APT repo verified: flotte $VERSION ($ARCHITECTURES)"
