#!/usr/bin/env bash
set -euo pipefail

OUT_DIR=${1:-public}
VERSION=${2:-0.0.0}
ARCHITECTURES=${ARCHITECTURES:-"amd64 arm64"}
BINARY=flotte
PKGNAME=flotte
DIST_DIR=dist
PACKAGE_DIR=.apt-package
RELEASE_DIR="$OUT_DIR/dists/stable"
POOL_DIR="$OUT_DIR/pool/main/$PKGNAME"

if ! command -v dpkg-scanpackages >/dev/null 2>&1; then
	echo "dpkg-scanpackages not found. Install dpkg-dev." >&2
	exit 2
fi

if [[ ! "$VERSION" =~ ^[0-9] ]]; then
	echo "invalid Debian package version: '$VERSION' (must start with a digit)" >&2
	exit 5
fi

entry() {
	local sum_cmd=$1
	local file=$2
	local rel_path=$3
	printf " %s %s %s\n" "$($sum_cmd "$file" | awk '{print $1}')" "$(stat -c%s "$file")" "$rel_path"
}

rm -rf "$OUT_DIR" "$PACKAGE_DIR"-*
mkdir -p "$POOL_DIR"

for arch in $ARCHITECTURES; do
	package_root="$PACKAGE_DIR-$arch"
	binary_path="$DIST_DIR/${BINARY}_linux_${arch}/$BINARY"
	deb_file="$DIST_DIR/${PKGNAME}_${VERSION}_${arch}.deb"

	if [[ ! -f "$binary_path" ]]; then
		echo "missing binary: $binary_path. Run 'just build-all' first." >&2
		exit 4
	fi

	mkdir -p "$package_root/DEBIAN" "$package_root/usr/local/bin"
	sed "s/{{VERSION}}/$VERSION/g; s/{{ARCH}}/$arch/g" .github/apt-config/package.template > "$package_root/DEBIAN/control"
	install -m 0755 "$binary_path" "$package_root/usr/local/bin/$BINARY"
	dpkg-deb --build "$package_root" "$deb_file"
	cp "$deb_file" "$POOL_DIR/"
	rm -rf "$package_root"
done

MD5_ENTRIES=""
SHA256_ENTRIES=""

for arch in $ARCHITECTURES; do
	binary_dir="$RELEASE_DIR/main/binary-$arch"
	mkdir -p "$binary_dir"

	(cd "$OUT_DIR" && dpkg-scanpackages --arch "$arch" pool /dev/null > "dists/stable/main/binary-$arch/Packages")
	gzip -9c "$binary_dir/Packages" > "$binary_dir/Packages.gz"

	MD5_ENTRIES+="$(entry md5sum "$binary_dir/Packages" "main/binary-$arch/Packages")"
	MD5_ENTRIES+="$(entry md5sum "$binary_dir/Packages.gz" "main/binary-$arch/Packages.gz")"
	SHA256_ENTRIES+="$(entry sha256sum "$binary_dir/Packages" "main/binary-$arch/Packages")"
	SHA256_ENTRIES+="$(entry sha256sum "$binary_dir/Packages.gz" "main/binary-$arch/Packages.gz")"
done

{
	echo "Origin: GitHub Pages"
	echo "Label: GitHub Pages APT Repo"
	echo "Suite: stable"
	echo "Codename: stable"
	echo "Architectures: $ARCHITECTURES"
	echo "Components: main"
	echo "Description: Flotte CLI APT repository"
	echo "Date: $(date -Ru)"
	echo "MD5Sum:"
	printf "%s" "$MD5_ENTRIES"
	echo "SHA256:"
	printf "%s" "$SHA256_ENTRIES"
} > "$RELEASE_DIR/Release"

if [[ "${GPG_SIGN:-false}" == "true" ]]; then
	if ! command -v gpg >/dev/null 2>&1; then
		echo "gpg not found. Install gnupg." >&2
		exit 3
	fi

	gpg --batch --yes --armor --clearsign --output "$RELEASE_DIR/InRelease" "$RELEASE_DIR/Release"
	gpg --batch --yes --armor --detach-sign --output "$RELEASE_DIR/Release.gpg" "$RELEASE_DIR/Release"
	gpg --batch --yes --armor --export > "$OUT_DIR/signing-key.asc"
	gpg --batch --yes --export > "$OUT_DIR/signing-key.gpg"
fi
