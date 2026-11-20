#!/usr/bin/env bash
# POJUN install / deploy script (single entry point)
#
# Run it, pick a deployment mode, and the matching flow runs; --mode selects
# one directly.
#
#   sudo ./install.sh                     interactive choice (binary / Docker)
#   sudo ./install.sh --mode=binary       binary: single file + systemd + system PostgreSQL
#                                         (on macOS it uses launchd + Homebrew PostgreSQL
#                                          automatically, no sudo needed: brew and user-level
#                                          launchd both run as the current user)
#   sudo ./install.sh --mode=docker       Docker Compose: container + in-container PostgreSQL
#   sudo ./install.sh --mode=binary --with-tools
#
#   curl -fsSL .../install.sh | sudo bash    # one-liner, interactive (mode/proxy can be chosen via /dev/tty)
#
# Idempotent: re-running = upgrading the program while preserving data
# (config.json / jwt.key / data / database / .env).
#
# Uninstall: binary  systemctl disable --now pojun && rm -rf /opt/pojun
#            Docker  cd /opt/pojun && docker compose down -v && rm -rf /opt/pojun
set -euo pipefail

REPO="chu0119/Pojun"
INSTALL_DIR="/opt/pojun"
SERVICE="pojun"
RUN_USER="pojun"
VERSION="latest"
MODE="${MODE:-}"
WITH_TOOLS=0
LISTEN_ADDR="${LISTEN_ADDR:-:8787}"
PROXY_ADDR="${PROXY_ADDR:-127.0.0.1:8788}"
PG_SUPER="${PG_SUPER:-postgres}"
# Outbound proxy used during install (apt / curl / go downloads go through it).
# Empty = direct connection. It only applies to "installing things" and is
# unrelated to the agent's target proxy or the LLM proxy at runtime.
INSTALL_PROXY="${INSTALL_PROXY:-${HTTPS_PROXY:-}}"
# macOS ships bash 3.2 (no ${var,,} lowercase expansion); use tr for compatibility
IMAGE="ghcr.io/$(printf '%s' "$REPO" | tr '[:upper:]' '[:lower:]')"
ASSUME_YES=0
# Whether to install the privileged helper pojun-hostd (powers one-click
# install on the "System -> Host Environment" page). On by default; pass
# --no-installer to keep the Web UI from gaining package-install ability.
WITH_INSTALLER=1

# When piped (curl ... | sudo bash), stdin is the script itself and cannot be
# used for input. As long as /dev/tty is readable we can still ask questions
# interactively (the key to BT-panel-style one-command installs).
CAN_PROMPT=0
if [ -r /dev/tty ]; then CAN_PROMPT=1; fi

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage(){
  cat <<EOF
POJUN install script

Usage: $0 [options]

Recommended system: Debian 12 / Ubuntu 22.04+ LTS (stable); Kali gives you the
                    full toolset out of the box (rolling release has risks)
                    Minimum 2C4G/20G, recommended 4C8G/60G (incl. tools,
                    wordlists and browser)

Deployment mode:
  --mode=binary|docker   binary (default, recommended) or Docker. Interactive
                         choice when omitted (a piped curl ... | bash still
                         prompts via /dev/tty)
  --with-tools           also install common pentest tools (under Docker the
                         tools are fixed in the image, see docs)

General:
  --version=VER          version, default latest (e.g. v0.3.20)
  --dir=PATH             install directory (default /opt/pojun)
  --listen=ADDR          listen address (default :8787)
  --proxy=ADDR           traffic-recording proxy address (default 127.0.0.1:8788)
  --install-proxy=URL    outbound proxy during install, e.g. http://10.0.0.14:7897 (defaults to \$HTTPS_PROXY)
  -y, --yes              non-interactive, accept all defaults
  -h, --help             show this help

Binary mode only:
  --user=NAME            runtime user (default pojun)
  --pg-super=NAME        PostgreSQL superuser (default postgres)
  --no-installer         do not install the privileged helper pojun-hostd (disables one-click install in the Web UI)

Docker mode only:
  --image=REF            image name (default $IMAGE)

Examples:
  sudo ./install.sh --mode=binary --with-tools
  sudo ./install.sh --mode=docker --version=v0.3.20
  sudo ./install.sh --mode=binary --install-proxy=http://10.0.0.14:7897 --with-tools
EOF
}

# ── arguments ────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --mode=*)          MODE="${arg#--mode=}" ;;
    --with-tools)      WITH_TOOLS=1 ;;
    --version=*)       VERSION="${arg#--version=}" ;;
    --dir=*)           INSTALL_DIR="${arg#--dir=}"; DIR_EXPLICIT=1 ;;
    --listen=*)        LISTEN_ADDR="${arg#--listen=}" ;;
    --proxy=*)         PROXY_ADDR="${arg#--proxy=}" ;;
    --install-proxy=*) INSTALL_PROXY="${arg#--install-proxy=}" ;;
    --user=*)          RUN_USER="${arg#--user=}" ;;
    --pg-super=*)      PG_SUPER="${arg#--pg-super=}" ;;
    --image=*)         IMAGE="${arg#--image=}" ;;
    --no-installer)    WITH_INSTALLER=0 ;;
    -y|--yes)          ASSUME_YES=1 ;;
    -h|--help)         usage; exit 0 ;;
    *) die "unknown argument: $arg (see --help)" ;;
  esac
done

# ── preflight checks ─────────────────────────────
DIR_EXPLICIT="${DIR_EXPLICIT:-0}"
IS_MAC=0
case "$(uname -s)" in
  Linux)  : ;;
  Darwin) IS_MAC=1 ;;
  *) die "only Linux / macOS are supported" ;;
esac

ARCH="$(uname -m)"
if [ "$IS_MAC" = "1" ]; then
  # macOS: brew and user-level launchd both belong to the current user, so
  # sudo is never needed. Explicitly using sudo actually breaks things: root's
  # brew/HOME differ from the user's, and the service would land in root's
  # LaunchAgents and never start. The install dir also defaults to
  # $HOME/pojun (/opt needs privileges).
  [ "$(id -u)" = "0" ] && die "on macOS run this script directly (do NOT add sudo)"
  case "$ARCH" in
    arm64)  PKG_ARCH="darwin-arm64" ;;
    x86_64) PKG_ARCH="darwin-amd64" ;;
    *) die "unsupported Mac arch: $ARCH (supported: arm64/x86_64)" ;;
  esac
  # /opt needs privileges on macOS; install to the home dir by default, an
  # explicit --dir wins
  if [ "$DIR_EXPLICIT" != "1" ]; then
    INSTALL_DIR="$HOME/pojun"
  fi
else
  [ "$(id -u)" = "0" ] || die "please run as root/sudo"
  case "$ARCH" in
    x86_64)  PKG_ARCH="linux-amd64" ;;
    aarch64) PKG_ARCH="linux-arm64" ;;
    *) die "unsupported arch: $ARCH (supported: x86_64/aarch64)" ;;
  esac
fi

# curl is a shared dependency of both modes
if ! command -v curl >/dev/null 2>&1; then
  command -v apt-get >/dev/null 2>&1 && { apt-get update -qq || true; apt-get install -y curl >/dev/null || true; }
  command -v dnf >/dev/null 2>&1 && dnf install -y curl >/dev/null || true
fi
command -v curl >/dev/null 2>&1 || die "failed to install curl; please install it manually"

# CA certificates are the prerequisite for every HTTPS request below. On
# minimal systems (e.g. curl installed with --no-install-recommends does not
# pull in the ca-certificates Recommends) you get curl: (77)
# "error setting certificate file" — every HTTPS request fails and the error
# does not point at the real cause. Check the CA bundle locations of both big
# distro families and fill in whichever is missing; failure here is not fatal
# (real fresh machines almost always ship them; this only rescues extremely
# stripped-down systems).
# macOS keeps its system certs at /etc/ssl/cert.pem (bundled with the OS);
# only Linux needs the fallback install below
if [ "$IS_MAC" != "1" ] && \
   [ ! -e /etc/ssl/certs/ca-certificates.crt ] && [ ! -e /etc/pki/tls/certs/ca-bundle.crt ]; then
  info "no CA certificate bundle found, trying to install ca-certificates..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1 || true
    apt-get install -y ca-certificates >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates >/dev/null 2>&1 || true
  fi
  [ -e /etc/ssl/certs/ca-certificates.crt ] || [ -e /etc/pki/tls/certs/ca-bundle.crt ] \
    || die "CA certificate bundle missing and auto-install failed; please install ca-certificates manually and retry"
  ok "CA certificate bundle ready"
fi

# ── resource preflight (warn only, never blocks) ─────
mem_kb="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
if [ "${mem_kb:-0}" -gt 0 ] && [ "$mem_kb" -lt 3800000 ]; then
  warn "memory < 4G: multiple workers + the compactor will be tight (4C8G+ recommended)"
fi
disk_avail="$(df -Pk / 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "${disk_avail:-}" ] && [ "$disk_avail" -lt 10485760 ]; then
  warn "root partition free < 10G: tools/SecLists(~2.5G)/nuclei templates/chromium may not fit (>=40G recommended)"
fi
if command -v python3 >/dev/null 2>&1; then
  pyver="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "0.0")"
  case "$pyver" in
    3.10|3.11|3.12|3.13|3.14) ;;
    *) warn "python3 version ${pyver}: the builtin FOFA MCP needs >=3.10 (does not affect the main service)" ;;
  esac
else
  warn "python3 not found: the builtin FOFA MCP needs Python >=3.10 (does not affect the main service)"
fi

# ── outbound proxy: interactive config + auto-verify ───
#
# Why interactive: the single most common install blocker is "this machine
# cannot reach GitHub / the apt mirror". Let the user type a standard proxy
# (http / https / socks5 / socks5h) on the spot, the script verifies it works,
# and only then continues — much faster than leaving them to dig through logs
# for "curl: (7) Failed to connect" afterwards.
#
# Once a proxy is set, every outbound path goes through it: apt / curl / npm /
# git / pip / go install. If verification fails you may re-enter or skip
# (skip = direct; whatever would fail later will fail).
normalize_proxy(){
  local p="$1"
  p="$(printf '%s' "$p" | tr -d ' \t"'"'"'' | sed 's|/*$||')"
  [ -z "$p" ] && return 0
  # bare host:port -> treat as http (most local proxies are http mixed ports)
  case "$p" in
    *://*) : ;;
    *) p="http://$p" ;;
  esac
  printf '%s' "$p"
}

# proxy_scheme_ok validates the scheme: only http/https/socks5/socks5h are valid.
proxy_scheme_ok(){
  case "$1" in
    http://*|https://*|socks5://*|socks5h://*) return 0 ;;
    *) return 1 ;;
  esac
}

# proxy_has_hostport validates that host:port is complete.
proxy_has_hostport(){
  local rest="${1#*://}"
  rest="${rest%%/*}"
  case "$rest" in
    *@*) rest="${rest#*@}" ;;
  esac
  case "$rest" in
    *:*) [ -n "${rest%%:*}" ] && [ -n "${rest##*:}" ] ;;
    *) return 1 ;;
  esac
}

# proxy_curl_args builds curl's proxy arguments per scheme.
# curl's -x does not accept the socks5:// URL form (it errors with
# "unsupported protocol scheme") — it wants --socks5-hostname host:port.
# Feeding it the URL anyway presents as "a socks proxy was set but every
# download fails", and the error points nowhere near the real cause.
#
# --socks5-hostname vs --socks5: the former lets the proxy resolve names too
# (= socks5h); the latter resolves DNS locally. In mainland-China networks
# local DNS often cannot resolve overseas names, so we use the former.
proxy_curl_args(){
  local p="$1"
  case "$p" in
    socks5://*|socks5h://*)
      local _p="${p#*://}" _auth=""
      case "$_p" in
        *@*) _auth="${_p%%@*}"; _p="${_p#*@}" ;;
      esac
      _p="${_p%%/*}"
      printf '%s\n' --socks5-hostname "$_p"
      [ -n "$_auth" ] && printf '%s\n' --socks5-basic -U "$_auth"
      ;;
    *)
      printf '%s\n' -x "$p"
      ;;
  esac
}

# verify_proxy sends a real request through the proxy to prove it works.
# The GitHub API is the target: the install flow needs it anyway, so the check
# matches the actual use.
verify_proxy(){
  local p="$1"
  local -a pargs=()
  while IFS= read -r line; do pargs+=("$line"); done < <(proxy_curl_args "$p")
  local code
  code="$(curl -fsSL "${pargs[@]}" -o /dev/null -w '%{http_code}' \
        --connect-timeout 8 --max-time 20 \
        https://api.github.com/repos/projectdiscovery/nuclei/releases/latest 2>/dev/null)" || code="000"
  case "$code" in
    200|301|302|403) return 0 ;;   # 403 = GitHub rate limit; the link itself works
    *) return 1 ;;
  esac
}

# configure_proxy asks interactively + normalizes.
# It only "asks" and "format-checks"; verification happens after CURL is
# constructed (verify_proxy needs the scheme-specific curl args, which depend
# on INSTALL_PROXY being final).
#
# An explicit --install-proxy goes through the same checks: a wrong
# scheme/port is the most common failure.
configure_proxy(){
  if [ -n "$INSTALL_PROXY" ]; then
    INSTALL_PROXY="$(normalize_proxy "$INSTALL_PROXY")"
    if ! proxy_scheme_ok "$INSTALL_PROXY"; then
      die "unsupported proxy scheme: $INSTALL_PROXY (supported: http/https/socks5/socks5h)"
    fi
    if ! proxy_has_hostport "$INSTALL_PROXY"; then
      die "proxy missing host:port: $INSTALL_PROXY"
    fi
    return 0
  fi

  # Non-interactive: don't bother the user, go direct.
  [ "$ASSUME_YES" = "1" ] && return 0
  [ "$CAN_PROMPT" = "0" ] && return 0

  printf '\n'
  printf 'Configure an outbound proxy?\n'
  printf '  The install reaches apt mirrors / GitHub / npm / pypi; if direct access fails, a proxy here is the easiest fix.\n'
  printf '  Supported: http://host:port , https://host:port , socks5://host:port , socks5h://host:port\n'
  printf '  With auth: http://user:pass@host:port ; empty = direct\n'
  printf 'Proxy address (empty = direct): '
  local ans=""
  read -r ans </dev/tty || ans=""
  ans="$(printf '%s' "$ans" | tr -d ' \t"'"'"'')"
  [ -z "$ans" ] && { info "using direct connection"; return 0; }

  ans="$(normalize_proxy "$ans")"
  if ! proxy_scheme_ok "$ans"; then
    warn "unsupported scheme: $ans"
    warn "supported: http/https/socks5/socks5h"
    return 0
  fi
  if ! proxy_has_hostport "$ans"; then
    warn "missing host:port: $ans"
    return 0
  fi
  INSTALL_PROXY="$ans"
  return 0
}

configure_proxy

# ── curl proxy args: dispatched by scheme ─────────
#
# curl's -x does not accept the socks5:// URL form (it errors with
# "unsupported protocol scheme") — it wants --socks5-hostname host:port.
# Feeding it the URL anyway presents as "a socks proxy was set but every
# download fails", and the error points nowhere near the real cause.
#
# --socks5-hostname vs --socks5: the former lets the proxy resolve names too
# (= socks5h); the latter resolves DNS locally. In mainland-China networks
# local DNS often cannot resolve overseas names, so we use the former.
# --retry-all-errors: without it, curl's --retry **only retries transient
# errors** (timeouts/429/5xx); transport failures like an SSL cut
# (SSL_read: unexpected eof) fail immediately — measured on 2026-10-22 on a
# real server: while pulling a 17MB release package through a proxy, the
# connection was cut and curl gave up instantly; the retry flags did nothing.
#
# --retry-delay: back off between retries to avoid hammering the same flaky
# egress.
CURL=(curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 --retry-max-time 1800)
if [ -n "$INSTALL_PROXY" ]; then
  while IFS= read -r _parg; do
    [ -n "$_parg" ] && CURL+=("$_parg")
  done < <(proxy_curl_args "$INSTALL_PROXY")
  info "using proxy during install: $INSTALL_PROXY"

  # The proxy must verify before we continue: the rest of the install pulls
  # GitHub assets through it, and a dead proxy makes every download fail with
  # a pile of unreadable errors.
  printf 'verifying proxy ... '
  if verify_proxy "$INSTALL_PROXY"; then
    ok "proxy works"
  else
    printf '\n'
    warn "proxy verification failed (GitHub API unreachable)"
    if [ "$ASSUME_YES" = "1" ] || [ "$CAN_PROMPT" = "0" ]; then
      die "proxy unusable, aborting install (fix with --install-proxy=, or omit it for direct)"
    fi
    printf 'Continue with this proxy anyway? (y/N) '
    local _ans=""; read -r _ans </dev/tty || _ans=""
    case "$_ans" in
      y|Y|yes|YES) : ;;
      *) die "aborted" ;;
    esac
  fi
fi

# Unified proxy environment: tools like git / npm / go / pip only honor
# HTTP_PROXY/HTTPS_PROXY/ALL_PROXY, not curl's -x. Once exported they all use
# the same proxy automatically.
# socks5 goes via ALL_PROXY (curl's path is already handled separately;
# ALL_PROXY is for git/npm).
if [ -n "$INSTALL_PROXY" ]; then
  case "$INSTALL_PROXY" in
    socks5://*|socks5h://*)
      export ALL_PROXY="$INSTALL_PROXY"
      export all_proxy="$INSTALL_PROXY"
      ;;
    *)
      export HTTP_PROXY="$INSTALL_PROXY"  HTTPS_PROXY="$INSTALL_PROXY"
      export http_proxy="$INSTALL_PROXY"  https_proxy="$INSTALL_PROXY"
      ;;
  esac
  export NO_PROXY="localhost,127.0.0.1,::1"
  export no_proxy="$NO_PROXY"
fi

# The proxy env line inside systemd units. hostd is a separate process that
# does not share the main service's environment, so both the main-service and
# hostd units must carry this line.
INSTALL_PROXY_ENV=""
if [ -n "$INSTALL_PROXY" ]; then
  case "$INSTALL_PROXY" in
    socks5://*|socks5h://*)
      INSTALL_PROXY_ENV="Environment=ALL_PROXY=${INSTALL_PROXY}"
      ;;
    *)
      INSTALL_PROXY_ENV="Environment=HTTP_PROXY=${INSTALL_PROXY}
Environment=HTTPS_PROXY=${INSTALL_PROXY}"
      ;;
  esac
fi

# ── pick a deployment mode ───────────────────────
choose_mode(){
  if [ -n "$MODE" ]; then
    case "$MODE" in binary|docker) return ;; *) die "--mode must be binary or docker"; esac
  fi
  if [ "$ASSUME_YES" = "1" ] || [ "$CAN_PROMPT" = "0" ]; then
    MODE="binary"
    info "non-interactive mode, defaulting to binary deployment (--mode to specify)"
    return
  fi
  printf '\nChoose a deployment mode:\n'
  printf '  1) binary (recommended)  single file + systemd + system PostgreSQL, zero runtime deps\n'
  printf '  2) Docker                container orchestration, tools fixed in the image\n'
  printf 'Choice [1]: '
  local pick=""
  read -r -t 60 pick </dev/tty || true
  case "${pick:-1}" in
    2|docker|D) MODE="docker" ;;
    *)          MODE="binary" ;;
  esac
  printf '\n'
}

choose_mode
ok "deployment mode: $MODE  target dir: $INSTALL_DIR"

# ── resolve the version ──────────────────────────
resolve_version(){
  # Note: this cannot be written as `[ "$VERSION" = latest ] || return` — when
  # the test is false, `return` propagates the test's exit code 1 and set -e
  # kills the script on the spot. Every caller passing --version hits it.
  if [ "$VERSION" != "latest" ]; then
    return 0
  fi
  VERSION="$("${CURL[@]}" "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -oE '"tag_name": *"[^"]+"' | head -1 | cut -d'"' -f4)" || VERSION=""
  [ -n "$VERSION" ] || die "cannot fetch the latest version (check the network or use --install-proxy)"
}

# ── download and verify the release package (both modes need it: binary for
# the program, Docker for skills) ──
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch_release(){
  resolve_version
  ok "target version: $VERSION"
  local zip="pojun-${VERSION#v}-${PKG_ARCH}.zip"
  info "downloading $zip"
  # Save under the original name: SHA256SUMS lists that name, and a renamed
  # file makes sha256sum -c unable to find it.
  #
  # -C - is resume: with a 17MB package crossing a flaky egress, drops are the
  # norm and resuming beats re-downloading (one measured install wasted 40
  # minutes on an SSL interruption).
  #
  # A failed download must die here: it used to fall through and end with
  # "unzip failed (need unzip)" — misreporting a network problem as package
  # corruption and sending users down the wrong debugging path.
  "${CURL[@]}" "https://github.com/$REPO/releases/download/$VERSION/$zip" -C - -o "$TMP/$zip" \
    || die "failed to download $zip (network down? proxy flaky? try --install-proxy)"

  # SHA256SUMS is the supply-chain check: if we cannot fetch it there is **no
  # verification**, and continuing would mean installing an unverified binary.
  # The old behavior just warned and skipped the check — a real defect.
  "${CURL[@]}" "https://github.com/$REPO/releases/download/$VERSION/SHA256SUMS" -o "$TMP/SHA256SUMS" \
    || die "cannot fetch SHA256SUMS, cannot verify $zip (refusing to install an unverified binary; retry or switch egress with --install-proxy)"
  ( cd "$TMP" && grep " $zip\$" SHA256SUMS | sha256sum -c - ) || die "SHA256 verification failed"
  ok "SHA256 verified"

  unzip -oq "$TMP/$zip" -d "$TMP/unpack" || die "unzip failed (need unzip)"
}

# ══════════════════════════════════════════════════
# Binary deployment
# ══════════════════════════════════════════════════
deploy_binary(){
  if [ "$IS_MAC" = "1" ]; then deploy_binary_darwin; return; fi
  command -v systemctl >/dev/null 2>&1 || die "systemd not found"
  command -v unzip   >/dev/null 2>&1 || { apt-get install -y unzip >/dev/null 2>&1 || dnf install -y unzip >/dev/null 2>&1 || die "need unzip"; }

  fetch_release
  local src="$TMP/unpack/pojun-${VERSION#v}-${PKG_ARCH}"
  [ -d "$src" ] || die "release package layout abnormal: $src not found"

  mkdir -p "$INSTALL_DIR"
  # Program/skills are overwritten; config.json / jwt.key / data are not in the
  # zip, so they are naturally untouched.
  # A binary cannot be cp'ed over a running process (Linux reports ETXTBSY
  # "Text file busy"); drop it under a temp name in the same dir first, then
  # rename — rename over a running executable is legal.
  # This step was once missing, so "rerun install.sh to upgrade" always failed
  # while the service was running.
  for b in pojun pojun-hostd pojun-maint; do
    [ -f "$src/$b" ] || continue
    cp "$src/$b" "$INSTALL_DIR/.$b.new"
    chmod +x "$INSTALL_DIR/.$b.new"
    mv -f "$INSTALL_DIR/.$b.new" "$INSTALL_DIR/$b"
  done
  # Everything else (skills / README / start.sh / config.example.json) is
  # copied over directly
  for f in "$src"/*; do
    base="$(basename "$f")"
    case "$base" in pojun|pojun-hostd|pojun-maint) continue ;; esac
    cp -r "$f" "$INSTALL_DIR/"
  done
  chmod +x "$INSTALL_DIR/start.sh"
  ok "program ready: $INSTALL_DIR/pojun"

  # runtime user
  if ! id "$RUN_USER" >/dev/null 2>&1; then
    useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin "$RUN_USER"
    ok "created system user $RUN_USER"
  fi
  chown -R "$RUN_USER:$RUN_USER" "$INSTALL_DIR"

  # PostgreSQL + config.json (first install only)
  if [ ! -f "$INSTALL_DIR/config.json" ]; then
    info "configuring PostgreSQL..."
    if ! command -v psql >/dev/null 2>&1; then
      # This apt call must honor the proxy: apt mirrors on machines in China
      # often need a proxy at all, and postgres is a hard dependency — if it
      # cannot be installed the whole flow stops.
      if command -v apt-get >/dev/null 2>&1; then
        local PP=()
        [ -n "$INSTALL_PROXY" ] && PP=(-o "Acquire::http::Proxy=$INSTALL_PROXY" -o "Acquire::https::Proxy=$INSTALL_PROXY")
        apt-get "${PP[@]}" update -qq && apt-get "${PP[@]}" install -y postgresql
      elif command -v dnf >/dev/null 2>&1; then
        # dnf --setopt=proxy="" reads as "proxy pointing at an empty address",
        # not "no proxy" — so only add the flag when a proxy is actually set.
        local DP=()
        [ -n "$INSTALL_PROXY" ] && DP=(--setopt=proxy="$INSTALL_PROXY")
        dnf "${DP[@]}" install -y postgresql-server && postgresql-setup --initdb
      else
        die "unrecognized package manager; please install PostgreSQL manually"
      fi
      systemctl enable --now postgresql
    fi
    systemctl is-active --quiet postgresql || systemctl start postgresql
    local DB_PASS
    DB_PASS="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
    # When the role already exists you **must sync the password**, not just skip.
    #
    # Lesson learned (a real install on 2026-10-22): the machine had a leftover
    # pojun role (reinstall / changed port / forgot to drop the role), the
    # script took the "role exists -> skip creation" branch, so config.json was
    # written with a **newly generated** password while the role in the DB kept
    # the **old** one -> the service booted into repeated SASL auth failures,
    # and the error pointed nowhere near the real cause.
    #
    # Syncing the password is safe: config.json is written exclusively by this
    # script (never over an existing install), so the password there is
    # authoritative. When the role exists AND config.json also exists,
    # install.sh never reaches this point (see the "first install only" check
    # above), so an existing install's password is never clobbered.
    if sudo -u "$PG_SUPER" psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='pojun'" | grep -q 1; then
      info "database role pojun already exists, syncing password"
      sudo -u "$PG_SUPER" psql -c "ALTER ROLE pojun LOGIN PASSWORD '$DB_PASS'" >/dev/null
    else
      sudo -u "$PG_SUPER" psql -c "CREATE ROLE pojun LOGIN PASSWORD '$DB_PASS'"
    fi
    sudo -u "$PG_SUPER" psql -tAc "SELECT 1 FROM pg_database WHERE datname='pojun'" | grep -q 1 \
      || sudo -u "$PG_SUPER" createdb -O pojun pojun
    cat > "$INSTALL_DIR/config.json" <<JSON
{
  "database": {
    "host": "127.0.0.1",
    "port": 5432,
    "user": "pojun",
    "password": "$DB_PASS",
    "dbname": "pojun",
    "sslmode": "disable"
  }
}
JSON
    chown "$RUN_USER:$RUN_USER" "$INSTALL_DIR/config.json"
    chmod 600 "$INSTALL_DIR/config.json"
    ok "database pojun ready (password written to config.json, mode 600)"
  else
    ok "reusing existing config.json (upgrade does not overwrite)"
  fi

  # systemd unit (hardened: safe enough without breaking pentest tools)
  #
  # ProtectSystem=strict requires ReadWritePaths, otherwise the whole
  # filesystem is read-only and the service cannot write its own data dir:
  # the traffic index (SQLite), task artifacts, evidence and transcripts all
  # fail silently (log floods with "attempt to write a readonly database"),
  # and one-click update in the UI cannot swap the binary either.
  #
  # Every directive below was verified line by line — read the comments before
  # changing; every pitfall here took the form "the hardening applied but the
  # tools stopped working":
  #   - MemoryDenyWriteExecute=true makes nuclei panic at startup (Go's sonic
  #     loader needs mprotect(PROT_EXEC)). The hardening gain is far smaller
  #     than "the scanner can't run", so it is not set.
  #   - Without CAP_NET_RAW, masscan reports "PF_PACKET sockets not
  #     supported" and nmap -sS reports "requires root privileges"; the agent
  #     falls back to -sT connect scans. AF_PACKET must also be allowed in
  #     RestrictAddressFamilies, otherwise a raw socket cannot even be
  #     created.
  #   - The directive name is SystemCallErrorNumber. Writing the nonexistent
  #     SystemCallErrorAction only makes systemd ignore it silently (one log
  #     line "Unknown key ... ignoring"), and out-of-scope syscalls take the
  #     default action SIGSYS, which kills the process — not the "clean
  #     refusal" wanted here.
  #   - Environment=HOME points at the install dir: ProtectHome + an
  #     unwritable home dir means nuclei's template/cache dirs
  #     (~/nuclei-templates etc.) cannot be written.
  # Note: if --dir points under /home or /root, ProtectHome=true hides the
  # whole thing — remove that option yourself in that case.
  cat > "/etc/systemd/system/${SERVICE}.service" <<UNIT
[Unit]
Description=POJUN - AI Autonomous Penetration Testing System
Documentation=https://github.com/${REPO}
After=network-online.target postgresql.service
Wants=network-online.target postgresql.service
# Repeated failures must let systemd mark the unit failed instead of
# restarting forever.
#
# start.sh has its own crash cap (after 5 consecutive abnormal exits it gives
# up relaunching and exits non-zero), but that is only the first line of
# defense: systemd's Restart=always immediately relaunches start.sh, which
# recreates the "status shows active (running) while everything is actually
# down" state (start.sh alive, the pojun binary crashing). The StartLimit
# here is the second line: once the burst is hit the unit truly enters
# failed, so ops can see the service is broken instead of being fooled by
# "running".
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
Environment=HOME=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/start.sh -addr ${LISTEN_ADDR} -proxy ${PROXY_ADDR}
# Install-time proxy: used by the "one-click install" on the Host Environment
# page and background intel syncs. hostd is a separate process that does not
# share the main service's environment, so its own unit also carries it (see
# the hostd unit below).
${INSTALL_PROXY_ENV}
Restart=always
RestartSec=5
# hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}
ProtectHome=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
# AF_PACKET/AF_NETLINK: masscan's and nmap's raw sockets need them
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_PACKET AF_NETLINK
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
# Not root, but enough raw-socket capability: masscan / ping / AF_PACKET work
# directly; nmap checks euid, so privileged scans need --privileged (the
# prompts already say so). CAP_NET_BIND_SERVICE lets --listen use low ports.
# Note: with capabilities granted, no extra privilege surface beyond
# NoNewPrivileges should be added; these three are the minimal set for
# scanning.
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "$SERVICE" 2>/dev/null || true
  # On upgrade the service may already be running: enable --now does not
  # restart it; an explicit restart is required to pick up the swapped binary.
  systemctl restart "$SERVICE"
  ok "systemd service started (${SERVICE})"

  # The bundled MCP server ships in the package (FOFA asset mapping); also
  # make sure uv is present so the preset works out of the box.
  if [ -d "$INSTALL_DIR/mcp-servers/fofa" ]; then
    ok "bundled MCP server installed ($INSTALL_DIR/mcp-servers/fofa)"
  fi
  ensure_uv

  if [ "$WITH_INSTALLER" = "1" ]; then install_hostd; fi
}

# ── write the proxy into runtime settings ────────
# During install the proxy only applies to the script itself; the Web
# "System -> Host Environment" page's "one-click install" and the background
# intel syncs go through the install_proxy setting in the database. If the
# two were not linked, the user would have to type the proxy again after
# installing — exactly the "everything that should use the proxy uses the
# proxy" the user asked for.
#
# Go through the database, not the HTTP API: the settings endpoint needs a
# JWT, and the admin password is set by the user on first visit — install.sh
# cannot have it. The settings table is simple (key/value), a direct UPSERT
# is the easiest path.
# ══════════════════════════════════════════════════
# Binary deployment · macOS (launchd + Homebrew PostgreSQL)
# ══════════════════════════════════════════════════
# Differences from the Linux version (everything else — download/verify/
# unzip/config.json/one-click update — is fully reused):
#   - package manager apt/dnf -> Homebrew; PostgreSQL via the postgresql@16
#     formula, whose superuser is the current user (brew creates no postgres
#     system user); psql connects directly;
#   - service manager systemd -> launchd: a LaunchAgents plist launches
#     start.sh (KeepAlive). start.sh is itself the watchdog (crash backoff
#     relaunch + one-click update swap live in it); launchd only handles
#     "start at boot + relaunch on unexpected exit", no duplicated watchdog;
#   - no pojun-hostd (the apt-based tool install is unavailable) and no
#     system user;
#   - everything runs as the current user, no sudo needed (sudo would in fact
#     break brew/launchd consistency).
deploy_binary_darwin(){
  # Homebrew: install it if missing (the official installer needs one
  # interactive password/enter confirmation on Intel machines writing to
  # /usr/local; Apple Silicon installs to /opt/homebrew without a password)
  if ! command -v brew >/dev/null 2>&1; then
    warn "Homebrew not found, installing it first (may ask for a password/enter)..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"       || die "Homebrew install failed; you can also install it manually and rerun this script"
    eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || true)"
    eval "$(/usr/local/bin/brew shellenv 2>/dev/null || true)"
  fi
  command -v brew >/dev/null 2>&1 || die "brew unusable (not in PATH?)"
  local BREW_PREFIX
  BREW_PREFIX="$(brew --prefix)"
  export PATH="$BREW_PREFIX/bin:$BREW_PREFIX/opt/postgresql@16/bin:$PATH"

  command -v unzip >/dev/null 2>&1 || brew install unzip >/dev/null 2>&1 || die "need unzip"

  # PostgreSQL 16 (hard dependency). Check whether the formula is installed,
  # not `command -v psql`: the machine may have another psql (an older formula
  # / the system CLI) that would fool us into thinking @16 is ready.
  if ! brew list --formula 2>/dev/null | grep -q "^postgresql@16$"; then
    info "installing PostgreSQL 16 (brew, first run takes a few minutes)..."
    brew install postgresql@16 || die "postgresql@16 install failed"
  fi
  export PATH="$BREW_PREFIX/opt/postgresql@16/bin:$PATH"
  command -v psql >/dev/null 2>&1 || die "psql not in PATH (postgresql@16 is keg-only; the script already prepends PATH explicitly, so this should be unreachable)"
  if ! brew services list 2>/dev/null | grep -q "postgresql@16.*started"; then
    info "starting PostgreSQL service (brew services = launchd)..."
    brew services start postgresql@16 || die "failed to start PostgreSQL"
  fi
  local i
  for i in $(seq 1 30); do pg_isready -q >/dev/null 2>&1 && break; sleep 2; done
  pg_isready -q >/dev/null 2>&1 || die "PostgreSQL not ready within 60s (check brew services list)"
  ok "PostgreSQL ready"
  # psql without -d defaults to a database named after the current user
  # (usually nonexistent) — pin it to postgres explicitly
  export PGDATABASE=postgres

  fetch_release
  local src="$TMP/unpack/pojun-${VERSION#v}-${PKG_ARCH}"
  [ -d "$src" ] || die "release package layout abnormal: $src not found"

  mkdir -p "$INSTALL_DIR"
  for b in pojun pojun-hostd pojun-maint; do
    [ -f "$src/$b" ] || continue
    cp "$src/$b" "$INSTALL_DIR/.$b.new"
    chmod +x "$INSTALL_DIR/.$b.new"
    mv -f "$INSTALL_DIR/.$b.new" "$INSTALL_DIR/$b"
  done
  local f base
  for f in "$src"/*; do
    base="$(basename "$f")"
    case "$base" in pojun|pojun-hostd|pojun-maint) continue ;; esac
    cp -r "$f" "$INSTALL_DIR/"
  done
  chmod +x "$INSTALL_DIR/start.sh"
  ok "program ready: $INSTALL_DIR/pojun"

  # config.json (first install only; upgrades do not overwrite)
  if [ ! -f "$INSTALL_DIR/config.json" ]; then
    local DB_PASS
    DB_PASS="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
    # brew's PostgreSQL superuser is the current user — no `sudo -u postgres`
    if psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='pojun'" 2>/dev/null | grep -q 1; then
      info "database role pojun already exists, syncing password"
      psql -c "ALTER ROLE pojun LOGIN PASSWORD '$DB_PASS'" >/dev/null
    else
      psql -c "CREATE ROLE pojun LOGIN PASSWORD '$DB_PASS'" >/dev/null
    fi
    psql -tAc "SELECT 1 FROM pg_database WHERE datname='pojun'" 2>/dev/null | grep -q 1       || createdb -O pojun pojun
    cat > "$INSTALL_DIR/config.json" <<JSON
{
  "database": {
    "host": "127.0.0.1",
    "port": 5432,
    "user": "pojun",
    "password": "$DB_PASS",
    "dbname": "pojun",
    "sslmode": "disable"
  }
}
JSON
    chmod 600 "$INSTALL_DIR/config.json"
    ok "database pojun ready (password written to config.json, mode 600)"
  else
    ok "reusing existing config.json (upgrade does not overwrite)"
  fi

  # launchd user-level service (start at boot + KeepAlive crash relaunch)
  # Declared on separate lines: `local` is a command, and in
  # `local A=1 B=$A` the $A expands before A is assigned — under set -u that
  # errors with unbound variable
  local PLIST_LABEL="com.pojun"
  local PLIST_DIR="$HOME/Library/LaunchAgents"
  local PLIST="$PLIST_DIR/$PLIST_LABEL.plist"
  mkdir -p "$PLIST_DIR"
  cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$PLIST_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>$INSTALL_DIR/start.sh</string>
  </array>
  <key>WorkingDirectory</key><string>$INSTALL_DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$INSTALL_DIR/pojun.launchd.log</string>
  <key>StandardErrorPath</key><string>$INSTALL_DIR/pojun.launchd.log</string>
</dict>
</plist>
PLIST
  launchctl bootout "gui/$(id -u)/$PLIST_LABEL" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST" || die "launchd registration failed ($PLIST)"
  ok "launchd service registered (starts at boot, relaunches on crash)"

  info "optional dependencies (install on demand, core features unaffected):"
  info "  brew install libreoffice --cask   # Word/evidence rendering (then ln -sf "/Applications/LibreOffice.app/Contents/MacOS/soffice" "$BREW_PREFIX/bin/soffice")"
  info "  brew install poppler imagemagick  # PDF/image preview"
  info "  brew install nmap sqlmap nuclei ffuf ...  # install pentest tools as needed; missing ones show honestly on the Host Environment page"
}

persist_install_proxy(){
  [ -n "$INSTALL_PROXY" ] || return 0
  [ -f "$INSTALL_DIR/config.json" ] || { warn "config.json not found, skipping runtime proxy write"; return 0; }
  command -v psql >/dev/null 2>&1 || { warn "no psql, skipping runtime proxy write"; return 0; }

  # The whole write is handed to Python — no bash variables ferrying
  # connection params in between.
  #
  # The previous two-step design (bash eval reads config.json -> passes to
  # psql) hit two pitfalls:
  #   1. The `eval "$(python3 ... <<'HEREDOC' ... HEREDOC
  #      )"` form — a heredoc nested inside $() — has boundaries that are
  #      painful to get right in bash: eval failed silently in practice,
  #      db_pass became an empty string, psql could not connect, and the outer
  #      layer only saw "write failed".
  #   2. psql's `:'proxy'` variable substitution does **not** work inside a
  #      `-c` argument (that path only exists for -f file reads or an
  #      interactive session) — it reports "syntax error at or near :".
  # Now: Python reads config.json for the connection params, builds and
  # escapes the SQL, and invokes psql.
  if python3 - "$INSTALL_DIR/config.json" "$INSTALL_PROXY" <<'PYEOF'
import json, os, subprocess, sys

cfg_path, proxy = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(cfg_path)).get("database", {}) or {}
except Exception:
    d = {}
host = str(d.get("host") or "127.0.0.1")
port = str(d.get("port") or 5432)
user = str(d.get("user") or "pojun")
dbname = str(d.get("dbname") or "pojun")
password = str(d.get("password") or "")

# SQL string-literal escaping: single quotes doubled. The proxy address has
# already passed URL validation (http/https/socks5 only, and must carry
# host:port) and contains no control characters.
lit = "'" + proxy.replace("'", "''") + "'"
sql = ("INSERT INTO settings(key, value) VALUES ('install_proxy', %s) "
       "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()" % lit)

env = dict(os.environ)
if password:
    env["PGPASSWORD"] = password
p = subprocess.run(
    ["psql", "-h", host, "-p", port, "-U", user, "-d", dbname,
     "-v", "ON_ERROR_STOP=1", "-c", sql],
    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
sys.exit(p.returncode)
PYEOF
  then
    ok "runtime install proxy written (one-click install on the Host Environment page will reuse it)"
  else
    warn "failed to write the runtime install proxy; you can set it manually once on the Web 'System -> Host Environment' page"
  fi
}

# ── privileged install helper pojun-hostd ─────────
# The main service unit carries NoNewPrivileges + ProtectSystem=strict: the
# process cannot escalate and /usr is read-only, so "one-click install" cannot
# be done from inside — it needs an external root helper. The helper only
# listens on a single Unix socket and only accepts whitelisted tool ids from
# hosttools — no free-form commands.
install_hostd(){
  if [ ! -f "$INSTALL_DIR/pojun-hostd" ]; then
    warn "pojun-hostd is not in the release package (old package), skipping; health check still works, one-click install does not"
    return 0
  fi
  # Same as above: the target may be a running helper — drop under a temp name
  # first, then rename to avoid ETXTBSY.
  install -m 0755 "$INSTALL_DIR/pojun-hostd" /usr/local/bin/.pojun-hostd.new
  mv -f /usr/local/bin/.pojun-hostd.new /usr/local/bin/pojun-hostd
  cat > "/etc/systemd/system/${SERVICE}-hostd.service" <<UNIT
[Unit]
Description=POJUN host tool installer (privileged helper)
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/pojun-hostd -socket /run/pojun/hostd.sock -socket-group ${RUN_USER}
${INSTALL_PROXY_ENV}
Restart=always
RestartSec=5
# /run/pojun is created by systemd and cleaned on stop; the helper itself
# downgrades the socket to 0660 root:${RUN_USER}
RuntimeDirectory=pojun
RuntimeDirectoryMode=0755
# The helper must call apt/dnf and write /usr/local/bin, so it cannot mount
# the root filesystem read-only like the main service.
#
# NoNewPrivileges is **deliberately not set** here: measured side effect — it
# strips CAP_SETUID/CAP_SETGID from the process's effective set (CapEff's
# trailing bits go ff -> 7f), and apt drops privileges to the _apt user when
# downloading, so it inevitably reports "seteuid 42 failed - Operation not
# permitted" and every apt-based tool install fails. The helper's real
# security boundary is "socket permissions + the tool whitelist in code",
# not this switch.
#
# CapabilityBoundingSet explicitly lists what apt/dpkg/maintainer scripts need
# (and incidentally blocks CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_NET_ADMIN and
# other caps installs do not need). If a future package's postinst needs
# more, add them per the error message.
PrivateTmp=true
ProtectHome=true
ProtectClock=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
# Deliberately no SystemCallFilter: the helper calls apt/dpkg as root, and
# dpkg runs arbitrary maintainer scripts shipped by packages — a whitelist can
# never cover what they actually need, and going out of scope means a SIGSYS
# hard kill. A mid-install kill is far harder to debug than an install error.
# The helper's real security boundary is socket permissions + the tool
# whitelist in code.
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID CAP_KILL CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_CHROOT CAP_MKNOD CAP_AUDIT_WRITE CAP_SETFCAP
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "${SERVICE}-hostd" 2>/dev/null || true
  # Same as the main service: if it is already running, an explicit restart is
  # required to pick up the newly installed binary.
  systemctl restart "${SERVICE}-hostd"
  ok "install helper started (${SERVICE}-hostd) -> socket /run/pojun/hostd.sock"
}

# ══════════════════════════════════════════════════
# Docker deployment
# ══════════════════════════════════════════════════
deploy_docker(){
  command -v docker >/dev/null 2>&1 || die "docker not found (see https://docs.docker.com/engine/install/)"
  docker compose version >/dev/null 2>&1 || die "docker compose plugin not found (install docker-compose-plugin)"
  docker info >/dev/null 2>&1 || die "Docker daemon not running (systemctl start docker)"
  command -v unzip >/dev/null 2>&1 || { apt-get install -y unzip >/dev/null 2>&1 || dnf install -y unzip >/dev/null 2>&1 || die "need unzip"; }

  # skills must be mounted into the container: mounting an empty dir would
  # shadow the image's builtin /app/skills, so seed it from the release
  # package first
  fetch_release
  local src="$TMP/unpack/pojun-${VERSION#v}-${PKG_ARCH}"
  mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/skills"
  if [ ! -f "$INSTALL_DIR/skills/.keep" ] && [ -z "$(ls -A "$INSTALL_DIR/skills" 2>/dev/null)" ]; then
    [ -d "$src/skills" ] && cp -r "$src/skills/." "$INSTALL_DIR/skills/"
  fi
  touch "$INSTALL_DIR/skills/.keep"

  # .env (first install generates a random PG password; upgrades do not overwrite)
  if [ ! -f "$INSTALL_DIR/.env" ]; then
    local PG_PASS
    PG_PASS="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
    cat > "$INSTALL_DIR/.env" <<ENV
POSTGRES_USER=pojun
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=pojun
POJUN_IMAGE=$IMAGE
POJUN_TAG=$VERSION
POJUN_INSTALL_PROXY=$INSTALL_PROXY
ENV
    chmod 600 "$INSTALL_DIR/.env"
    ok "generated $INSTALL_DIR/.env (with random database password, mode 600)"
  else
    ok "reusing existing .env (upgrade does not overwrite)"
    # But the proxy must follow this install: it is not a "generated once"
    # secret — it should sync on upgrade too, otherwise rerunning the install
    # after changing the proxy leaves the stale proxy in the old .env active.
    if [ -n "$INSTALL_PROXY" ]; then
      if grep -q '^POJUN_INSTALL_PROXY=' "$INSTALL_DIR/.env"; then
        sed -i "s|^POJUN_INSTALL_PROXY=.*|POJUN_INSTALL_PROXY=$INSTALL_PROXY|" "$INSTALL_DIR/.env"
      else
        printf 'POJUN_INSTALL_PROXY=%s\n' "$INSTALL_PROXY" >> "$INSTALL_DIR/.env"
      fi
      ok "synced the install proxy in .env"
    fi
  fi

  local PORT="${LISTEN_ADDR##*:}" PROXY_PORT="${PROXY_ADDR##*:}"
  cat > "$INSTALL_DIR/docker-compose.yml" <<COMPOSE
# Generated by install.sh. Data lives in ./data, skills in ./skills, the
# database in the pgdata volume.
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: \${POSTGRES_USER:-pojun}
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}
      POSTGRES_DB: \${POSTGRES_DB:-pojun}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U \${POSTGRES_USER:-pojun} -d \${POSTGRES_DB:-pojun}"]
      interval: 5s
      timeout: 3s
      retries: 10
    restart: unless-stopped

  pojun:
    image: \${POJUN_IMAGE}:\${POJUN_TAG}
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      POJUN_PG_DSN: postgres://\${POSTGRES_USER:-pojun}:\${POSTGRES_PASSWORD}@postgres:5432/\${POSTGRES_DB:-pojun}?sslmode=disable
      ANTHROPIC_API_KEY: \${ANTHROPIC_API_KEY:-}
      OPENAI_API_KEY: \${OPENAI_API_KEY:-}
      POJUN_LLM_PROVIDER: \${POJUN_LLM_PROVIDER:-}
      POJUN_LLM_MODEL: \${POJUN_LLM_MODEL:-}
      POJUN_LLM_BASE_URL: \${POJUN_LLM_BASE_URL:-}
      POJUN_LLM_PROXY: \${POJUN_LLM_PROXY:-}
      # Install-time proxy: used by the "one-click install" on the Host
      # Environment page and background intel syncs. Docker mode has no
      # config.json, so it can only go through an env var; the server reads it
      # as the fallback for the database setting.
      POJUN_INSTALL_PROXY: \${POJUN_INSTALL_PROXY:-}
    ports:
      - "${PORT}:8787"
      - "127.0.0.1:${PROXY_PORT}:8788"
      # Reverse-connection port mapping (open as needed): ports that
      # MSF/listener inside the container listens on must be mapped to the
      # host for the agent to receive a reverse shell. Example:
      # - "4444-4450:4444-4450"
    volumes:
      - ./data:/app/data
      - ./skills:/app/skills
    restart: unless-stopped

volumes:
  pgdata:
COMPOSE

  ok "generated $INSTALL_DIR/docker-compose.yml"
  info "pulling image $IMAGE:$VERSION ..."
  ( cd "$INSTALL_DIR" && docker compose pull )
  ( cd "$INSTALL_DIR" && docker compose up -d )
  ok "containers started"
}

# ── --with-tools: host pentest tools ─────────────
install_tools(){
  if [ "$MODE" = "docker" ]; then
    warn "Under Docker the tools are baked into the image and not installed at runtime."
    warn "For more tools: build on top of the official image (see the README 'Docker deployment' section), or use --mode=binary."
    return 0
  fi
  info "installing common pentest tools (from system repos)..."
  local APT_PROXY=() DNF_PROXY=()
  if [ -n "$INSTALL_PROXY" ]; then
    APT_PROXY=(-o "Acquire::http::Proxy=$INSTALL_PROXY" -o "Acquire::https::Proxy=$INSTALL_PROXY")
    DNF_PROXY=(--setopt=proxy="$INSTALL_PROXY")
  fi
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get "${APT_PROXY[@]}" update -qq || warn "apt update failed, continuing anyway"
    # seclists has no stable package name in apt repos — cloned separately
    # (see install_wordlists); everything else is installed in one pass, and
    # missing packages don't block the whole set (package names differ across
    # distro repos).
    # imagemagick: report evidence collages / filename watermarking
    # (dep since v0.4.10);
    # libreoffice-writer/calc/impress + poppler-utils: document evidence to
    # image preview (since v0.4.21, Word/Excel/PPT -> PDF -> JPEG).
    # Install strategy: install as a group first (fast); if the group fails,
    # retry **package by package**.
    # Why the per-package fallback is required: apt-get install is an atomic
    # transaction — on a weak network, any one of ~200 packages failing to
    # download rolls back the whole group; in practice small but critical
    # packages like git were lost (every script-type tool then 127s).
    apt_install() {
      apt-get "${APT_PROXY[@]}" install -y "$@" >/dev/null 2>&1 && return 0
      local p
      for p in "$@"; do
        apt-get "${APT_PROXY[@]}" install -y "$p" >/dev/null 2>&1 \
          || warn "  apt missing package: $p"
      done
    }
    # Critical base packages first (missing git/ca certs would make every
    # later script install fail wholesale)
    apt_install git jq perl ruby ca-certificates curl wget unzip openssl openssh-client netcat-openbsd
    # pentest tool group
    apt_install nmap masscan sqlmap hydra whatweb nikto gobuster ffuf john \
      dnsutils whois nodejs npm python3-impacket gitleaks imagemagick \
      hashcat testssl.sh default-jre-headless apktool adb aapt awscli tcpdump sshuttle
    # document rendering group (big, most likely to drag the group down on a
    # weak network — kept separate)
    apt_install libreoffice-writer libreoffice-calc libreoffice-impress poppler-utils
  elif command -v dnf >/dev/null 2>&1; then
    dnf "${DNF_PROXY[@]}" install -y nmap masscan sqlmap hydra whatweb nikto john nmap-ncat bind-utils unzip \
      nodejs python3-impacket ImageMagick hashcat openssl tcpdump \
      libreoffice-writer libreoffice-calc libreoffice-impress poppler-utils \
      || warn "some dnf packages missing; installed what was available"
  else
    warn "unrecognized package manager, skipping system-repo tool install"
  fi
  ok "system-repo tools installed"

  # Non-system-repo tools (Go ecosystem / GitHub Releases); whatever can't be
  # installed can be installed later on demand on the Web "System -> Host
  # Environment" page
  install_github_tools
  install_wordlists
  install_pip_tools
  install_browser_mcp
  install_fonts
  # catalog preinstall (v0.4.68): the host helper tops up the ~90-item tool
  # catalog not covered above (mobile reversing / intranet tunneling / binary
  # exploitation, etc.) — the same list as Web one-click install.
  install_catalog_tools
}

# ── catalog preinstall: reuse hostd's whitelisted recipes and serial queue ───
# Why it runs last: the apt base packages and the GitHub table-driven installs
# are the best-vetted paths; the catalog only fills in tools they don't cover
# (idempotent: already-working tools are skipped).
install_catalog_tools(){
  local bin="/usr/local/bin/pojun-hostd"
  if [ ! -x "$bin" ]; then
    warn "  pojun-hostd not installed, skipping catalog preinstall (Web one-click install still works)"
    return 0
  fi
  info "preinstalling missing catalog tools (first run is slow: apt/pip/GitHub full pass)..."
  local was_active=0
  if systemctl is-active --quiet pojun-hostd 2>/dev/null; then
    was_active=1
    systemctl stop pojun-hostd 2>/dev/null || true
  fi
  # GitHub/pip flakiness is the norm on weak networks: failed items auto-retry
  # three rounds (each round only reinstalls the missing ones; installed ones
  # are skipped), greatly improving unattended-install success.
  local attempt ok_any=0
  for attempt in 1 2 3; do
    if "$bin" -install-all; then
      ok "catalog tools preinstall done"
      ok_any=1
      break
    fi
    if [ "$attempt" -lt 3 ]; then
      warn "catalog preinstall round $attempt had failures, retrying in 30s..."
      sleep 30
    fi
  done
  if [ "$ok_any" != "1" ]; then
    warn "catalog tools preinstall still has failures; retry them one by one on the Web 'System -> Host Environment' page"
  fi
  [ "$was_active" = "1" ] && systemctl start pojun-hostd 2>/dev/null || true
}

# ── official-document fonts: report PDF rendering ───
# The fonts are already embedded in docx (odttf), so Word/WPS needs no system
# fonts; but LibreOffice reads system fonts when converting to PDF and falls
# back without them. Pull the trio from the repo raw (ASCII filenames; the
# TTFs' internal family names remain FangSong_GB2312 etc., and docx references
# match by internal name). A failed download only warns — Word export is
# unaffected.
install_fonts(){
  local dir="/usr/share/fonts/gongwen"
  mkdir -p "$dir" || { warn "cannot create $dir, skipping official-document fonts"; return 0; }
  local base="https://raw.githubusercontent.com/${REPO}/main/report/fonts"
  local f
  for f in fangsong_gb2312.ttf kaiti_gb2312.ttf fzxiaobiaosong_gbk.ttf; do
    if [ ! -s "$dir/$f" ]; then
      "${CURL[@]}" -fsSL "$base/$f" -o "$dir/$f" >/dev/null 2>&1         || { rm -f "$dir/$f"; warn "  official-document font $f download failed (only affects local docx->PDF)"; }
    fi
  done
  command -v fc-cache >/dev/null 2>&1 && fc-cache -f "$dir" >/dev/null 2>&1 || true
  ok "official-document fonts ready ($dir)"
}

# ── GitHub Release single-file tools ─────────────
# Table-driven: repo|asset-name template|binary name. Template placeholders:
# {ver} (no v), {verv} (with v), {arch} (amd64/arm64), {arch2}
# (x86_64/aarch64), {arch3} (x86/arm), {arch4} (x64/arm64).
#
# Asset naming varies wildly per project (arch first/last, version with/without
# v, extension .zip/.tar.gz/.gz), so every template must be written against
# the actual asset names — there is no universal pattern.
#
# Not `go install`: the host may have no Go toolchain, and go install downloads
# the modules every time anyway.
# Not apt: these tools' apt packages either don't exist or are ancient.
install_github_tools(){
  local GOBIN_DIR="/usr/local/bin"
  local arch="amd64" arch2="x86_64" arch3="x86" arch4="x64" lin="x86_64"
  if [ "$ARCH" = "aarch64" ]; then
    arch="arm64"; arch2="aarch64"; arch3="arm"; arch4="arm64"; lin="arm64"
  fi

  # repo|asset template|binary name
  local specs="
projectdiscovery/nuclei|nuclei_{ver}_linux_{arch}.zip|nuclei
projectdiscovery/httpx|httpx_{ver}_linux_{arch}.zip|httpx
projectdiscovery/subfinder|subfinder_{ver}_linux_{arch}.zip|subfinder
projectdiscovery/naabu|naabu_{ver}_linux_{arch}.zip|naabu
projectdiscovery/dnsx|dnsx_{ver}_linux_{arch}.zip|dnsx
projectdiscovery/katana|katana_{ver}_linux_{arch}.zip|katana
projectdiscovery/tlsx|tlsx_{ver}_linux_{arch}.zip|tlsx
projectdiscovery/notify|notify_{ver}_linux_{arch}.zip|notify
projectdiscovery/interactsh|interactsh-client_{ver}_linux_{arch}.zip|interactsh-client
gitleaks/gitleaks|gitleaks_{ver}_linux_{arch4}.tar.gz|gitleaks
jpillora/chisel|chisel_{ver}_linux_{arch}.gz|chisel
OWASP/Amass|amass_linux_{arch}.tar.gz|amass
hahwul/dalfox|dalfox-{verv}-linux-{arch2}.tar.gz|dalfox
epi052/feroxbuster|{arch2}-linux-feroxbuster.tar.gz|feroxbuster
OJ/gobuster|gobuster_Linux_{lin}.tar.gz|gobuster
"
  local spec repo tmpl bin tag ver url asset file tmpd
  for spec in $specs; do
    repo="$(printf '%s' "$spec" | cut -d'|' -f1)"
    tmpl="$(printf '%s' "$spec" | cut -d'|' -f2)"
    bin="$(printf '%s' "$spec" | cut -d'|' -f3)"
    if command -v "$bin" >/dev/null 2>&1; then
      ok "  $bin already present"
      continue
    fi
    tag="$("${CURL[@]}" "https://api.github.com/repos/$repo/releases/latest" \
      | grep -oE '"tag_name": *"[^"]+"' | head -1 | cut -d'"' -f4)" || tag=""
    if [ -z "$tag" ]; then
      warn "  $bin cannot resolve latest version (GitHub API limited; try --install-proxy)"
      continue
    fi
    ver="${tag#v}"
    asset="$tmpl"
    asset="${asset//\{ver\}/$ver}"
    asset="${asset//\{verv\}/$tag}"
    asset="${asset//\{arch\}/$arch}"
    asset="${asset//\{arch2\}/$arch2}"
    asset="${asset//\{arch3\}/$arch3}"
    asset="${asset//\{arch4\}/$arch4}"
    asset="${asset//\{lin\}/$lin}"
    url="https://github.com/$repo/releases/download/${tag}/${asset}"
    file="$TMP/$(basename "$asset")"
    tmpd="$TMP/ghtool"
    rm -rf "$tmpd"; mkdir -p "$tmpd"
    if ! "${CURL[@]}" "$url" -o "$file"; then
      warn "  $bin download failed ($url; try --install-proxy)"
      rm -rf "$file" "$tmpd"
      continue
    fi
    # Three archive forms: .zip / .tar.gz / single-file .gz
    local extracted=""
    case "$asset" in
      *.zip)  unzip -oq "$file" -d "$tmpd" 2>/dev/null || true ;;
      *.tar.gz|*.tgz) tar -xzf "$file" -C "$tmpd" 2>/dev/null || true ;;
      *.gz)   gzip -dc "$file" > "$tmpd/$bin" 2>/dev/null || true ;;
    esac
    if [ -f "$tmpd/$bin" ]; then
      extracted="$tmpd/$bin"
    else
      # The archive may wrap files in a directory level — fall back to find
      local found
      found="$(find "$tmpd" -type f -name "$bin" 2>/dev/null | head -1)"
      [ -n "$found" ] && extracted="$found"
    fi
    if [ -n "$extracted" ] && [ -s "$extracted" ]; then
      mv "$extracted" "$GOBIN_DIR/$bin" && chmod +x "$GOBIN_DIR/$bin"
      ok "  $bin $tag -> $GOBIN_DIR/$bin"
    else
      warn "  $bin binary not found after extraction (asset naming may have changed: $url)"
    fi
    rm -rf "$file" "$tmpd"
  done
}

# SecLists: general wordlist collection (directory/parameter/username brute-
# force corpus). No stable package name in apt repos — it must be cloned. It is
# 2.5G, so use a --depth 1 shallow clone.
install_wordlists(){
  local dir="/opt/SecLists"
  if [ -d "$dir" ] && [ -d "$dir/Discovery" ]; then
    ok "  SecLists already present -> $dir"
    return 0
  fi
  info "cloning the SecLists wordlist collection (shallow clone, ~2.5G)..."
  if command -v git >/dev/null 2>&1; then
    if git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$dir" >/dev/null 2>&1; then
      ok "  SecLists -> $dir"
    else
      warn "  SecLists clone failed (try --install-proxy)"
    fi
  else
    warn "  git not installed, skipping SecLists"
  fi
}

# uv: the bundled MCP "FOFA asset mapping" uses it to launch the stdio server
# (relative path mcp-servers/fofa).
#
# Key point (a real pitfall): the pojun service runs as a systemd user whose
# PATH only guarantees
# /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; installing uv
# as root via pipx drops it in /root/.local/bin (the service user can neither
# traverse /root nor find it on PATH) — the binary must land in
# /usr/local/bin or you get "the preset can be added but the MCP won't start".
# Best-effort: failure only warns, the main service is unaffected.
ensure_uv(){
  local cand=""
  for c in /usr/local/bin/uv /usr/bin/uv /root/.local/bin/uv "$HOME/.local/bin/uv"; do
    if [ -x "$c" ]; then cand="$c"; break; fi
  done
  if [ -z "$cand" ]; then
    if command -v pipx >/dev/null 2>&1; then
      pipx install --global uv >/dev/null 2>&1 || pipx install uv >/dev/null 2>&1 || true
    fi
    if [ -z "$cand" ] && command -v python3 >/dev/null 2>&1; then
      python3 -m pip install --break-system-packages -q uv >/dev/null 2>&1 || true
    fi
    for c in /usr/local/bin/uv /root/.local/bin/uv "$HOME/.local/bin/uv"; do
      if [ -x "$c" ]; then cand="$c"; break; fi
    done
  fi
  if [ -n "$cand" ] && [ "$cand" != "/usr/local/bin/uv" ]; then
    cp -f "$cand" /usr/local/bin/uv 2>/dev/null || true
    chmod 755 /usr/local/bin/uv 2>/dev/null || true
  fi
  if [ -x /usr/local/bin/uv ] && /usr/local/bin/uv --version >/dev/null 2>&1; then
    ok "uv ready (/usr/local/bin/uv, FOFA MCP usable)"
  else
    warn "uv not ready: the FOFA MCP preset needs it (pip install uv then copy to /usr/local/bin)"
  fi
  return 0
}

# pip tools: wafw00f (WAF detection), some impacket scripts.
# Prefer pipx (isolated env, doesn't pollute system Python, avoids PEP668
# externally-managed); fall back to python3 -m pip --break-system-packages
# when pipx is absent.
install_pip_tools(){
  command -v python3 >/dev/null 2>&1 || { warn "  no python3, skipping pip tools"; return 0; }
  local PIPX=()
  if command -v pipx >/dev/null 2>&1; then
    PIPX=(pipx install)
  else
    PIPX=(python3 -m pip install --break-system-packages)
  fi
  local proxy_args=()
  [ -n "$INSTALL_PROXY" ] && proxy_args=(--proxy "$INSTALL_PROXY")
  # package|executable name (empty = the package ships no CLI). Skip if it
  # already exists — pipx errors out on already-installed packages, which must
  # not count as an "install failure".
  local specs="wafw00f|wafw00f
semgrep|semgrep
pwntools|pwntools
uv|uv"
  # netexec is not installed: NetExec went commercial in 2026 and its PyPI
  # release files were pulled (installing always fails); install from GitHub
  # source when needed (the hosttools netexec entry explains).
  local spec pkg bin
  for spec in $specs; do
    pkg="$(printf '%s' "$spec" | cut -d'|' -f1)"
    bin="$(printf '%s' "$spec" | cut -d'|' -f2)"
    if [ -n "$bin" ] && command -v "$bin" >/dev/null 2>&1; then
      ok "  $bin already present"
      continue
    fi
    if "${PIPX[@]}" "${proxy_args[@]}" "$pkg" >/dev/null 2>&1; then
      ok "  $pkg ✓"
    else
      warn "  $pkg install failed"
    fi
  done
}

# Playwright MCP: the browser MCP starts via `npx @playwright/mcp`, needing
# node+npx; also pre-stage the chromium browser, otherwise first launch has to
# download it.
#
# The browser goes to /opt/ms-playwright, not ~/.cache/ms-playwright: the
# service runs as the pojun user and cannot see caches under root's home.
install_browser_mcp(){
  command -v node >/dev/null 2>&1 || { warn "  no node, skipping browser MCP"; return 0; }
  command -v npm >/dev/null 2>&1 || { warn "  no npm, skipping browser MCP"; return 0; }

  # NPMENV must be defined outside both branches: under set -u an undefined
  # variable aborts the script outright.
  local NPMENV=()
  [ -n "$INSTALL_PROXY" ] && NPMENV=(HTTP_PROXY="$INSTALL_PROXY" HTTPS_PROXY="$INSTALL_PROXY")

  if ! npm ls -g @playwright/mcp >/dev/null 2>&1; then
    info "  installing Playwright MCP (global npm)..."
    if env "${NPMENV[@]}" npm install -g @playwright/mcp@latest >/dev/null 2>&1; then
      ok "  @playwright/mcp ✓"
    else
      warn "  @playwright/mcp install failed"
    fi
  fi

  local BROWSER_DIR="/opt/ms-playwright"
  if [ -d "$BROWSER_DIR" ]; then
    ok "  chromium already staged -> $BROWSER_DIR"
    return 0
  fi
  info "  pre-staging chromium browser (~150MB first time)..."
  if env "${NPMENV[@]}" PLAYWRIGHT_BROWSERS_PATH="$BROWSER_DIR" \
       npx --yes playwright@latest install --with-deps chromium >/dev/null 2>&1; then
    ok "  chromium -> $BROWSER_DIR"
  else
    warn "  chromium pre-stage failed (first MCP launch can still auto-download)"
  fi
}

# ── run the deployment ───────────────────────────
case "$MODE" in
  binary) deploy_binary ;;
  docker) deploy_docker ;;
  *) die "unknown deployment mode: $MODE" ;;
esac

if [ "$WITH_TOOLS" = "1" ]; then
  if [ "$IS_MAC" = "1" ]; then
    # macOS: the apt/dnf stack is unavailable, so install the core pieces per-package,
    # best-effort, via Homebrew (the pentest/GitHub tool groups are brew install on demand;
    # packages that fail simply show as missing on the health page).
    if ! command -v brew >/dev/null 2>&1; then
      warn "Homebrew not detected — installing it first (may prompt for a password/Enter)..."
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
        || die "Homebrew install failed"
      eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || true)"
      eval "$(/usr/local/bin/brew shellenv 2>/dev/null || true)"
    fi
    BREW_PREFIX="$(brew --prefix)"
    export PATH="$BREW_PREFIX/bin:$BREW_PREFIX/opt/postgresql@16/bin:$PATH"
    info "Installing core dependencies via Homebrew (PostgreSQL/document rendering/pentest tool group, tolerant per package)..."
    for pkg in postgresql@16 poppler imagemagick nmap masscan sqlmap hydra whatweb nikto \
               gobuster ffuf john gitleaks dnsutils; do
      brew list --formula 2>/dev/null | grep -q "^${pkg}@\|^${pkg}$" \
        || brew install "$pkg" >/dev/null 2>&1 \
        || warn "  brew missing package: $pkg"
    done
    # LibreOffice is a cask: after installing, symlink soffice into PATH so the report docx→PDF step finds it.
    if [ ! -x "$BREW_PREFIX/bin/soffice" ] && [ -x "/Applications/LibreOffice.app/Contents/MacOS/soffice" ]; then
      ln -sf "/Applications/LibreOffice.app/Contents/MacOS/soffice" "$BREW_PREFIX/bin/soffice"
      ok "soffice symlinked → $BREW_PREFIX/bin/soffice"
    fi
    ok "macOS core install complete (brew install fills in other tools on demand)"
  else
    install_tools
  fi
fi

# The proxy must land in runtime settings so one-click install on the Host
# Environment page uses the same proxy. Done last: the service is up and the
# schema exists by now.
persist_install_proxy

# ── health check ─────────────────────────────────
PORT="${LISTEN_ADDR##*:}"
for _n in $(seq 1 30); do
  # Print progress each round: at an install site "which step it is stuck on"
  # must be visible, and it helps troubleshooting.
  # Capture curl's exit code explicitly: under set -e an if-condition is
  # exempted anyway, but an explicit rc makes "why did it exit" directly
  # visible (a bizarre silent exit once happened here; this line found it)
  health_rc=0
  curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/api/health" 2>/dev/null || health_rc=$?
  echo "[*] health check #${_n}: rc=${health_rc}"
  if [ "$health_rc" = "0" ]; then
    # macOS hostname has no -I (exit code 1); set -o pipefail would propagate
    # it into the whole pipeline and set -e would kill the script on the spot —
    # it once made a macOS install exit silently right after a 200 health
    HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    ok "service ready -> http://${HOST_IP:-127.0.0.1}:${PORT} (set the admin password on first visit)"
    info "next steps: 1) set the admin password 2) configure a channel under 'LLM Config' 3) use presets under 'System -> MCP' to attach FOFA/Playwright 4) create a task, optionally applying a builtin Playbook"
    if [ "$MODE" = "binary" ]; then
      if [ "$IS_MAC" = "1" ]; then
        tail -5 "$INSTALL_DIR/pojun.launchd.log" 2>/dev/null || true
        info "service management: launchctl kickstart -k gui/$(id -u)/com.pojun to restart | launchctl bootout gui/$(id -u)/com.pojun to stop | tail -f $INSTALL_DIR/pojun.launchd.log for logs"
      else
        systemctl --no-pager status "$SERVICE" | head -5
      fi
    else
      ( cd "$INSTALL_DIR" && docker compose ps )
    fi
    exit 0
  fi
  info "waiting for service (${_n}/30)..."
  sleep 2
done
if [ "$MODE" = "binary" ]; then
  if [ "$IS_MAC" = "1" ]; then
    warn "not ready within 60s, check logs: tail -n 50 $INSTALL_DIR/pojun.launchd.log"
  else
    warn "not ready within 60s, check logs: journalctl -u $SERVICE -n 50"
  fi
else
  warn "not ready within 60s, check logs: cd $INSTALL_DIR && docker compose logs --tail 50"
fi
exit 1
