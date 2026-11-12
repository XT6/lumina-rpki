#!/usr/bin/env bash
#
# Builds Barry (https://github.com/LACNIC/barry) and its build dependencies
# (asn1c, libasn1fort) into a project-local prefix, without sudo.
#
# Usage: scripts/install-barry.sh [--force]
#
#   LUMINA_TOOLS  install prefix (default: <repo>/_tools)
#
# Each project is pinned to a commit: Barry is WIP and its Repository
# Descriptor format may change incompatibly before 1.0.0. See doc/barry.md
# for how to upgrade the pins.

set -euo pipefail

ASN1C_REPO=https://github.com/vlm/asn1c.git
ASN1C_REV=8a274c3f99761f249b6c205e1c89be1b1cb7c669
LIBASN1FORT_REPO=https://github.com/NICMx/libasn1fort.git
LIBASN1FORT_REV=925b8419d2810a6ad59f3ef821efbf4155055822
BARRY_REPO=https://github.com/LACNIC/barry.git
BARRY_REV=478ee89a78bbbabfd8acc542faf02b322cecf85d

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${LUMINA_TOOLS:-$ROOT/_tools}"
SRC="$PREFIX/src"
STAMP="$PREFIX/.pins"
PINS="asn1c=$ASN1C_REV libasn1fort=$LIBASN1FORT_REV barry=$BARRY_REV"

if [[ "${1:-}" != "--force" && -x "$PREFIX/bin/barry" && -f "$STAMP" && "$(cat "$STAMP")" == "$PINS" ]]; then
  echo "Barry is already installed at $PREFIX/bin/barry (pins unchanged)."
  exit 0
fi

JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

export PATH="$PREFIX/bin:$PATH"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CPPFLAGS="-I$PREFIX/include ${CPPFLAGS:-}"
export LDFLAGS="-L$PREFIX/lib -Wl,-rpath,$PREFIX/lib ${LDFLAGS:-}"

if [[ "$(uname -s)" == "Darwin" ]]; then
  if ! command -v brew >/dev/null; then
    echo "Homebrew is required on macOS. See doc/barry.md." >&2
    exit 1
  fi
  # libasn1fort's compile-asn1.sh uses GNU sed syntax (sed -i'').
  gnubin="$(brew --prefix gnu-sed)/libexec/gnubin"
  if [[ ! -x "$gnubin/sed" ]]; then
    echo "GNU sed is required: brew install gnu-sed" >&2
    exit 1
  fi
  export PATH="$gnubin:$PATH"
  # Homebrew's OpenSSL and libxml2 are keg-only, so point the build at them.
  for formula in openssl@3 libxml2; do
    dir="$(brew --prefix "$formula")"
    export PKG_CONFIG_PATH="$dir/lib/pkgconfig:$PKG_CONFIG_PATH"
    export CPPFLAGS="-I$dir/include $CPPFLAGS"
    export LDFLAGS="-L$dir/lib $LDFLAGS"
  done
fi

# fetch NAME REPO REV: shallow checkout of exactly REV into $SRC/NAME.
fetch() {
  local dir="$SRC/$1"
  rm -rf "$dir"
  mkdir -p "$dir"
  git -C "$dir" init -q
  git -C "$dir" fetch -q --depth 1 "$2" "$3"
  git -C "$dir" checkout -q FETCH_HEAD
}

build() {
  local dir="$SRC/$1"
  echo "==> Building $1"
  (
    cd "$dir"
    if [[ -x ./autogen.sh ]]; then ./autogen.sh; else autoreconf -fi; fi
    ./configure --prefix="$PREFIX"
    make -j"$JOBS"
    make install
  )
}

mkdir -p "$SRC"
fetch asn1c "$ASN1C_REPO" "$ASN1C_REV"
build asn1c
fetch libasn1fort "$LIBASN1FORT_REPO" "$LIBASN1FORT_REV"
build libasn1fort
fetch barry "$BARRY_REPO" "$BARRY_REV"
build barry

echo "$PINS" > "$STAMP"
echo "Barry installed at $PREFIX/bin/barry"
