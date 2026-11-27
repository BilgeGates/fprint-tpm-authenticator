#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Generates PKGBUILD, .SRCINFO and fpta.install for a tagged release.
#   tools/make-aur.sh --url https://github.com/OWNER/REPO --license SPDX-ID \
#                     --tarball v0.2.0.tar.gz --out DIR
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
die() { echo "❌ $*" >&2; exit 1; }
url="" license="" tarball="" out=""
while (($#)); do
    (($# >= 2)) || die "missing value for $1"
    case $1 in
        --url) url=$2 ;;
        --license) license=$2 ;;
        --tarball) tarball=$2 ;;
        --out) out=$2 ;;
        *) die "unknown option $1" ;;
    esac
    shift 2
done
[[ $url =~ ^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die "--url must be a GitHub repository URL"
[[ $license =~ ^[A-Za-z0-9.+-]+$ ]] || die "--license must be an SPDX identifier"
[[ -f $tarball ]] || die "--tarball: download the release tag archive first"
[[ -n $out ]] || die "--out is required"

[[ -s $root/LICENSE ]] || die "RELEASE BLOCKED: no LICENSE file"
if grep -q 'BUS_USB' "$root/src/broker.c"; then
    die "RELEASE BLOCKED: the virtual device must not claim a USB vendor/product ID"
fi

version=$(sed -n 's/^project(.* VERSION \([0-9.]*\) .*/\1/p' "$root/CMakeLists.txt")
[[ -n $version ]] || die "cannot read the version from CMakeLists.txt"
listing=$(tar -tzf "$tarball")
grep -q '/LICENSE$' <<<"$listing" || die "the tarball has no LICENSE file"
sum=$(sha256sum "$tarball" | cut -d' ' -f1)

mkdir -p "$out"
sed -e "s|@VERSION@|$version|" -e "s|@URL@|$url|" -e "s|@LICENSE@|$license|" \
    -e "s|@SHA256@|$sum|" "$root/packaging/aur/PKGBUILD.in" >"$out/PKGBUILD"
cp "$root/packaging/arch/fpta.install" "$out/"
(cd "$out" && makepkg --printsrcinfo >.SRCINFO)
echo "✅ AUR files written to $out. Build them with makepkg before publishing."
