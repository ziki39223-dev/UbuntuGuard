#!/usr/bin/env bash
# Build a GPG-signed source package for a Launchpad PPA.
#
# Usage:
#   GPG_KEY_ID=<fingerprint> scripts/build-ppa-source.sh [--distro noble] [--out DIR]
#
# The script works on an exported copy of the current git HEAD, rewrites the
# top changelog distribution to the target series and signs .dsc/.changes.
set -euo pipefail

distro="noble"
out="dist/ppa"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --distro) distro="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "${GPG_KEY_ID:-}" ]]; then
    echo "GPG_KEY_ID is required" >&2
    exit 2
fi
for tool in dpkg-buildpackage dpkg-source gpg; do
    command -v "$tool" >/dev/null || { echo "$tool not found" >&2; exit 8; }
done

root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Export committed sources only, so local build artifacts never leak in.
tar -C "$root" --exclude=.git --exclude=dist --exclude=.venv \
    --exclude=.pytest_cache --exclude=.mypy_cache --exclude=.ruff_cache \
    --exclude='__pycache__' -cf - . | tar -C "$work" -xf -

chmod +x "$work"/debian/rules "$work"/debian/postinst "$work"/debian/prerm "$work"/debian/postrm
chmod -x "$work"/debian/install "$work"/systemd/*

# Launchpad rejects uploads whose distribution does not match the series.
sed -i "1s/\(.*) \)[^;]*;/\1$distro;/" "$work/debian/changelog"

version=$(dpkg-parsechangelog -l "$work/debian/changelog" -S Version)
upstream=${version%-*}
tar -C "$work" --exclude=debian -czf "$work/../ubuntuguard_${upstream}.orig.tar.gz" .

mkdir -p "$out"
(
    cd "$work"
    dpkg-buildpackage -S -sa -k"$GPG_KEY_ID"
)

find "$work/.." -maxdepth 1 \( -name '*.dsc' -o -name '*.changes' -o -name '*.debian.tar.*' -o -name '*.orig.tar.*' \) \
    -exec cp -f {} "$out"/ \;

echo "signed source package ready in $out:"
ls -1 "$out"
echo
echo "next: dput ppa:<launchpad-id>/<ppa-name> $out/ubuntuguard_*_source.changes"
