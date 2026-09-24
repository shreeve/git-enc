#!/bin/sh
# Build the release archives and checksums for one tag.
#
#   scripts/package-release.sh v0.1.0 [OUT]
#
# Writes to OUT (default dist/):
#   git-enc-vX.Y.Z-<plat>.tar.gz   (plat: osx-arm64 osx-amd64 linux-amd64 linux-arm64)
#   git-enc-vX.Y.Z-windows-amd64.zip
#   git-enc-vX.Y.Z-checksums.txt   (sha256 of every archive)
# Each archive unpacks to git-enc-vX.Y.Z-<plat>/ holding the binary,
# README.md and LICENSE.
set -eu

TAG=${1:?usage: package-release.sh vX.Y.Z [OUT]}
OUT=${2:-dist}
case "$TAG" in v[0-9]*) ;; *) echo "tag must look like v1.2.3" >&2; exit 2 ;; esac
VERSION=${TAG#v}
NAME=git-enc

rm -rf "$OUT"
mkdir -p "$OUT"
for target in darwin/arm64:osx-arm64 darwin/amd64:osx-amd64 linux/amd64:linux-amd64 linux/arm64:linux-arm64 windows/amd64:windows-amd64; do
	goos=${target%%/*}
	rest=${target#*/}
	goarch=${rest%%:*}
	plat=${rest#*:}
	dir="$NAME-$TAG-$plat"
	exe=$NAME
	[ "$goos" = windows ] && exe=$NAME.exe
	mkdir -p "$OUT/$dir"
	CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath \
		-ldflags "-s -w -X main.version=$VERSION" \
		-o "$OUT/$dir/$exe" ./cmd/git-enc
	cp README.md LICENSE "$OUT/$dir/"
	if [ "$goos" = windows ]; then
		(cd "$OUT" && zip -qr "$dir.zip" "$dir")
	else
		(cd "$OUT" && tar -czf "$dir.tar.gz" "$dir")
	fi
	rm -rf "${OUT:?}/$dir"
done
(cd "$OUT" && { command -v sha256sum >/dev/null && sha256sum ./*.tar.gz ./*.zip || shasum -a 256 ./*.tar.gz ./*.zip; } |
	sed 's# \./# #' >"$NAME-$TAG-checksums.txt")
ls -l "$OUT"
