#!/usr/bin/env bash
# Build a signed APT repository from .deb files.
#
# Usage:
#   GPG_KEY_ID=<fingerprint> scripts/build-apt-repo.sh [--pool DIR] [--out DIR] [--codename NAME ...]
#
# Options:
#   --pool DIR        directory containing *.deb (default: dist)
#   --out DIR         repository root to create (default: dist/apt-repo)
#   --codename NAME   distribution codename, repeatable (default: jammy noble)
#
# Environment:
#   GPG_KEY_ID   signing key fingerprint or key ID (required)
#   APT_ORIGIN   Origin/Label value (default: UbuntuGuard)
set -euo pipefail

pool="dist"
out="dist/apt-repo"
origin="${APT_ORIGIN:-UbuntuGuard}"
codenames=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pool) pool="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --codename) codenames+=("$2"); shift 2 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "${GPG_KEY_ID:-}" ]]; then
    echo "GPG_KEY_ID is required" >&2
    exit 2
fi
if [[ ${#codenames[@]} -eq 0 ]]; then
    codenames=(jammy noble)
fi

command -v dpkg-scanpackages >/dev/null || { echo "dpkg-scanpackages not found (dpkg-dev)" >&2; exit 8; }
command -v apt-ftparchive >/dev/null || { echo "apt-ftparchive not found (apt-utils)" >&2; exit 8; }
command -v gpg >/dev/null || { echo "gpg not found" >&2; exit 8; }

mapfile -t debs < <(find "$pool" -maxdepth 1 -name '*.deb' -type f | sort)
if [[ ${#debs[@]} -eq 0 ]]; then
    echo "no .deb files found in $pool" >&2
    exit 1
fi

mkdir -p "$out/pool/main/u/ubuntuguard"
for deb in "${debs[@]}"; do
    cp -f "$deb" "$out/pool/main/u/ubuntuguard/"
done

for code in "${codenames[@]}"; do
    index_dir="$out/dists/$code/main/binary-amd64"
    mkdir -p "$index_dir"

    (cd "$out" && dpkg-scanpackages -m pool > "dists/$code/main/binary-amd64/Packages")
    gzip -9 -c "$index_dir/Packages" > "$index_dir/Packages.gz"

    apt-ftparchive \
        -o "APT::FTPArchive::Release::Origin=$origin" \
        -o "APT::FTPArchive::Release::Label=$origin" \
        -o "APT::FTPArchive::Release::Suite=$code" \
        -o "APT::FTPArchive::Release::Codename=$code" \
        -o "APT::FTPArchive::Release::Architectures=amd64" \
        -o "APT::FTPArchive::Release::Components=main" \
        -o "APT::FTPArchive::Release::Description=$origin APT repository" \
        release "$out/dists/$code" > "$out/dists/$code/Release"

    gpg --batch --yes --local-user "$GPG_KEY_ID" \
        --clearsign -o "$out/dists/$code/InRelease" "$out/dists/$code/Release"
    gpg --batch --yes --local-user "$GPG_KEY_ID" \
        --armor --detach-sign -o "$out/dists/$code/Release.gpg" "$out/dists/$code/Release"

    echo "signed $code: $index_dir/Packages, dists/$code/InRelease"
done

gpg --batch --yes --export "$GPG_KEY_ID" > "$out/ubuntuguard-archive-keyring.gpg"
gpg --batch --yes --armor --export "$GPG_KEY_ID" > "$out/ubuntuguard-archive-keyring.asc"

echo "repository ready: $out"
echo "users install the keyring from $out/ubuntuguard-archive-keyring.gpg"
