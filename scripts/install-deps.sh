#!/usr/bin/env bash
#
# Installs, or checks, what Lumina needs to build and run (#90):
#
#   * Erlang/OTP and Elixir, at the versions pinned in .tool-versions;
#   * rsync 3.1.0 or later, first on PATH (on macOS, /usr/bin/rsync is
#     openrsync, which is too old);
#   * the development dependencies (mix deps.get), and the ./lumina escript.
#
# Usage: scripts/install-deps.sh [--check]
#
#   --check  only report; install nothing. Exits 1 if something is missing.
#
# Erlang and Elixir are installed with mise or asdf when either is present
# (both read .tool-versions), otherwise with Homebrew on macOS. On Linux
# without mise or asdf, the script says what to install. rsync comes from
# Homebrew on macOS and from apt-get or dnf (with sudo) on Linux.
# Running it again changes nothing that is already in place.
#
# Barry, needed only to regenerate test fixtures, has its own script:
# scripts/install-barry.sh.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CHECK=0
case "${1:-}" in
  --check) CHECK=1 ;;
  "") ;;
  *)
    echo "usage: scripts/install-deps.sh [--check]" >&2
    exit 2
    ;;
esac

OS="$(uname -s)"
WANT_OTP="$(awk '$1 == "erlang" {print $2}' .tool-versions)"
WANT_ELIXIR="$(awk '$1 == "elixir" {print $2}' .tool-versions | sed 's/-otp-.*//')"
MIN_RSYNC="3.1.0"
problems=0

ok() { printf 'ok       %s\n' "$*"; }
warn() { printf 'warning  %s\n' "$*"; }
missing() {
  printf 'missing  %s\n' "$*"
  problems=$((problems + 1))
}
step() { printf '==> %s\n' "$*"; }

# version_ge A B: true if version A >= version B (dotted numbers).
version_ge() {
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" == "$2" ]]
}

otp_version() {
  local root release
  command -v erl >/dev/null || return 1
  root="$(erl -noshell -eval 'io:format("~s", [code:root_dir()]), halt().' 2>/dev/null)" || return 1
  release="$(erl -noshell -eval 'io:format("~s", [erlang:system_info(otp_release)]), halt().' 2>/dev/null)" || return 1
  cat "$root/releases/$release/OTP_VERSION" 2>/dev/null || echo "$release"
}

elixir_version() {
  command -v elixir >/dev/null || return 1
  elixir --short-version 2>/dev/null
}

rsync_version() {
  "$1" --version 2>/dev/null | sed -n 's/.*version \([0-9]*\.[0-9]*\.[0-9]*\).*/\1/p' | head -1
}

# --- Erlang/OTP and Elixir ---------------------------------------------------

install_beam() {
  if command -v mise >/dev/null; then
    step "Installing Erlang $WANT_OTP and Elixir $WANT_ELIXIR with mise"
    mise install
  elif command -v asdf >/dev/null; then
    step "Installing Erlang $WANT_OTP and Elixir $WANT_ELIXIR with asdf"
    asdf plugin add erlang 2>/dev/null || true
    asdf plugin add elixir 2>/dev/null || true
    asdf install
  elif [[ "$OS" == "Darwin" ]] && command -v brew >/dev/null; then
    step "Installing Erlang and Elixir with Homebrew (its current versions)"
    brew install erlang elixir
  else
    echo "Install Erlang/OTP $WANT_OTP and Elixir $WANT_ELIXIR, for example with" >&2
    echo "mise (https://mise.jdx.dev): mise install, in this directory." >&2
    return 1
  fi
}

check_beam() {
  local otp elixir
  otp="$(otp_version)" || otp=""
  elixir="$(elixir_version)" || elixir=""

  if [[ -z "$otp" ]]; then
    missing "Erlang/OTP (wanted $WANT_OTP)"
  elif [[ "$otp" == "$WANT_OTP" ]]; then
    ok "Erlang/OTP $otp"
  elif [[ "${otp%%.*}" == "${WANT_OTP%%.*}" ]]; then
    warn "Erlang/OTP $otp (pinned $WANT_OTP; the same major release should work)"
  else
    missing "Erlang/OTP $WANT_OTP (found $otp)"
  fi

  if [[ -z "$elixir" ]]; then
    missing "Elixir (wanted $WANT_ELIXIR)"
  elif [[ "$elixir" == "$WANT_ELIXIR" ]]; then
    ok "Elixir $elixir"
  elif [[ "$(cut -d. -f1,2 <<<"$elixir")" == "$(cut -d. -f1,2 <<<"$WANT_ELIXIR")" ]]; then
    warn "Elixir $elixir (pinned $WANT_ELIXIR; the same minor release should work)"
  else
    missing "Elixir $WANT_ELIXIR (found $elixir)"
  fi
}

# --- rsync ---------------------------------------------------------------------

install_rsync() {
  if [[ "$OS" == "Darwin" ]]; then
    if ! command -v brew >/dev/null; then
      echo "Homebrew is needed to install rsync on macOS: https://brew.sh" >&2
      return 1
    fi
    step "Installing rsync with Homebrew"
    brew install rsync
  elif command -v apt-get >/dev/null; then
    step "Installing rsync with apt-get (sudo)"
    sudo apt-get update && sudo apt-get install -y rsync
  elif command -v dnf >/dev/null; then
    step "Installing rsync with dnf (sudo)"
    sudo dnf install -y rsync
  else
    echo "Install rsync $MIN_RSYNC or later with your package manager." >&2
    return 1
  fi
}

# True if an rsync >= MIN_RSYNC is first on PATH or, on macOS, in
# Homebrew's prefix.
good_rsync_installed() {
  local candidate version
  for candidate in "$(command -v rsync || true)" \
    "$( [[ "$OS" == "Darwin" ]] && command -v brew >/dev/null && echo "$(brew --prefix)/bin/rsync")"; do
    [[ -n "$candidate" && -x "$candidate" ]] || continue
    version="$(rsync_version "$candidate")"
    if [[ -n "$version" ]] && version_ge "$version" "$MIN_RSYNC"; then
      return 0
    fi
  done
  return 1
}

check_rsync() {
  local path version brew_rsync
  path="$(command -v rsync || true)"

  if [[ -z "$path" ]]; then
    missing "rsync $MIN_RSYNC or later (none on PATH)"
    return
  fi

  version="$(rsync_version "$path")"

  if [[ -n "$version" ]] && version_ge "$version" "$MIN_RSYNC"; then
    ok "rsync $version ($path)"
    return
  fi

  # An old rsync comes first on PATH. On macOS a Homebrew one may be
  # installed but further down.
  if [[ "$OS" == "Darwin" ]] && command -v brew >/dev/null; then
    brew_rsync="$(brew --prefix)/bin/rsync"
    if [[ -x "$brew_rsync" ]] && version_ge "$(rsync_version "$brew_rsync")" "$MIN_RSYNC"; then
      missing "rsync first on PATH: $path is ${version:-of unknown version}, too old." \
        "Put $(brew --prefix)/bin before /usr/bin in PATH, or run lumina sync --rsync $brew_rsync"
      return
    fi
  fi

  missing "rsync $MIN_RSYNC or later ($path is ${version:-of unknown version})"
}

# --- Mix dependencies and the escript --------------------------------------------

check_mix() {
  if [[ -d deps ]] && [[ -n "$(ls -A deps 2>/dev/null)" ]]; then
    ok "development dependencies fetched (deps/)"
  else
    missing "development dependencies (mix deps.get)"
  fi

  if [[ -x lumina ]]; then
    ok "./lumina built"
  else
    missing "./lumina (mix escript.build)"
  fi
}

# --- Main ------------------------------------------------------------------------

if [[ "$CHECK" == 0 ]]; then
  check_beam >/dev/null
  if [[ "$problems" -gt 0 ]]; then
    install_beam
  fi
  problems=0
  # Only install rsync if no good one exists at all; a good one further
  # down PATH is reported by the check below.
  if ! good_rsync_installed; then
    install_rsync
  fi
  if command -v mix >/dev/null; then
    step "Fetching development dependencies and building ./lumina"
    mix local.hex --force --if-missing >/dev/null
    mix deps.get
    mix escript.build
  fi
  echo
fi

step "Checking"
check_beam
check_rsync
check_mix
echo "Barry (only for regenerating test fixtures): scripts/install-barry.sh"

if [[ "$problems" -gt 0 ]]; then
  echo "$problems problem(s) found." >&2
  exit 1
fi
