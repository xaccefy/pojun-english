#!/usr/bin/env bash
# POJUN cross-platform release builder.
#
# The default mode builds one target and embeds the already-exported frontend.
# `./build.sh --release` builds and packages all supported desktop/server targets.
#
# Environment variables:
#   POJUN_TARGET_OS=linux             One target OS in single-target mode.
#   POJUN_TARGET_ARCH=amd64           One target arch in single-target mode.
#   POJUN_TARGETS=linux/amd64,...     Comma-separated targets for multi-target mode.
#   POJUN_BUILD_VERSION=v0.3.3        Version embedded in the binary and archive name.
#   POJUN_OUTPUT=/path/to/pojun       Explicit binary path in single-target mode.
#   POJUN_OUTPUT_DIR=dist             Directory for default binary paths.
#   POJUN_PACKAGE=1                   Create a zip archive for each target.
#   POJUN_PACKAGE_DIR=dist            Directory for release archives.
#   POJUN_COMPRESS=off                UPX mode: off, auto, or required.
#   POJUN_UPX_ARGS="--best --lzma"    Arguments passed to UPX.
#   POJUN_SKIP_FRONTEND=1             Reuse server/webui/dist (for CI artifact builds).
#   POJUN_SKIP_NPM_CI=1               Skip npm ci while rebuilding the frontend.
#   POJUN_GOSUMDB=sum.golang.org      Go checksum database.
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  ./build.sh                         build for the current OS/arch
  ./build.sh --target linux/amd64    build one specific target
  ./build.sh --release               build and package all supported targets

Options:
  --release              build Linux and macOS amd64/arm64 release archives (zip)
  --target OS/ARCH       set a single target, e.g. linux/arm64 (other platforms for local debugging only)
  --upx                  force UPX binary compression (may affect compatibility on some Linux environments)
  --no-compress          no UPX; rely on Go linker trimming plus zip compression only
  --help                 show this help

The multi-target list can be overridden via POJUN_TARGETS, e.g.:
  POJUN_TARGETS=linux/amd64 ./build.sh --release
EOF
}

RELEASE_TARGETS_DEFAULT="linux/amd64,linux/arm64,darwin/amd64,darwin/arm64"
POJUN_RELEASE="${POJUN_RELEASE:-0}"
POJUN_COMPRESS="${POJUN_COMPRESS:-off}"
POJUN_PACKAGE="${POJUN_PACKAGE:-0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      POJUN_RELEASE=1
      POJUN_PACKAGE=1
      shift
      ;;
    --target)
      [ "$#" -ge 2 ] || die "--target requires an OS/ARCH argument"
      target_arg="$2"
      case "$target_arg" in
        */*)
          POJUN_TARGET_OS="${target_arg%%/*}"
          POJUN_TARGET_ARCH="${target_arg##*/}"
          POJUN_TARGETS="$target_arg"
          ;;
        *) die "target must be OS/ARCH, e.g. linux/amd64" ;;
      esac
      shift 2
      ;;
    --no-compress)
      POJUN_COMPRESS=0
      shift
      ;;
    --upx)
      POJUN_COMPRESS=required
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) die "unknown argument: $1 (see --help for usage)" ;;
  esac
done

command -v go >/dev/null 2>&1 || die "Go not found (the project requires Go 1.26 or newer)"

POJUN_GOSUMDB="${POJUN_GOSUMDB:-sum.golang.org}"
if [ -z "${POJUN_BUILD_VERSION:-}" ]; then
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    POJUN_BUILD_VERSION="$(git describe --tags --always --dirty)"
  else
    POJUN_BUILD_VERSION="dev"
  fi
fi
# Release tags are commonly passed as v0.3.3; keep the binary version consistent.
POJUN_BUILD_VERSION="${POJUN_BUILD_VERSION#v}"
POJUN_OUTPUT_DIR="${POJUN_OUTPUT_DIR:-dist}"
POJUN_PACKAGE_DIR="${POJUN_PACKAGE_DIR:-$POJUN_OUTPUT_DIR}"
POJUN_UPX_ARGS="${POJUN_UPX_ARGS:---best --lzma}"

if [ "${POJUN_RELEASE}" = "1" ]; then
  POJUN_TARGETS="${POJUN_TARGETS:-$RELEASE_TARGETS_DEFAULT}"
else
  POJUN_TARGET_OS="${POJUN_TARGET_OS:-$(GOSUMDB="$POJUN_GOSUMDB" go env GOOS)}"
  POJUN_TARGET_ARCH="${POJUN_TARGET_ARCH:-$(GOSUMDB="$POJUN_GOSUMDB" go env GOARCH)}"
  POJUN_TARGETS="${POJUN_TARGETS:-${POJUN_TARGET_OS}/${POJUN_TARGET_ARCH}}"
fi

if [ "${POJUN_SKIP_FRONTEND:-0}" = "1" ]; then
  [ -d server/webui/dist ] || die "POJUN_SKIP_FRONTEND=1 but server/webui/dist does not exist"
else
  command -v npm >/dev/null 2>&1 || die "npm not found (frontend static build requires Node.js/npm)"
  command -v rsync >/dev/null 2>&1 || die "rsync not found"
  info "Building frontend static assets"
  if [ "${POJUN_SKIP_NPM_CI:-0}" != "1" ]; then
    (cd web && npm ci)
  fi
  (cd web && npm run build:static)
  info "Normalising frontend assets to English-only (third-party bundles ship CJK lookup tables)"
  python3 scripts/strip_cjk.py web/out
  info "Syncing frontend assets to server/webui/dist"
  mkdir -p server/webui/dist
  rsync -a --delete web/out/ server/webui/dist/
fi

compress_binary() {
  binary="$1"
  goos="$2"
  case "$POJUN_COMPRESS" in
    0|off|false|none)
      info "Skipping UPX: $binary"
      return 0
      ;;
    auto|required|true|1) ;;
    *) die "POJUN_COMPRESS must be off, auto or required" ;;
  esac

  if ! command -v upx >/dev/null 2>&1; then
    if [ "$POJUN_COMPRESS" = "required" ]; then
      die "POJUN_COMPRESS=required but upx not found"
    fi
    warn "upx not found, keeping linker-compressed result: $binary"
    return 0
  fi

  before=$(wc -c < "$binary" | tr -d ' ')
  upx_args="$POJUN_UPX_ARGS"
  [ "$goos" = "darwin" ] && upx_args="$upx_args --force-macos"
  # shellcheck disable=SC2086
  if ! upx $upx_args -- "$binary"; then
    if [ "$POJUN_COMPRESS" = "required" ]; then
      die "UPX compression failed: $binary"
    fi
    warn "UPX does not support this target format, keeping uncompressed binary: $binary"
    return 0
  fi
  after=$(wc -c < "$binary" | tr -d ' ')
  ok "UPX compression done: $binary (${before} -> ${after} bytes)"
}

package_binary() {
  binary="$1"
  goos="$2"
  goarch="$3"
  package_name="pojun-${POJUN_BUILD_VERSION}-${goos}-${goarch}"
  package_root="${POJUN_PACKAGE_DIR}/${package_name}"
  archive="${POJUN_PACKAGE_DIR}/${package_name}.zip"

  command -v zip >/dev/null 2>&1 || die "packaging requires zip"
  rm -rf "$package_root" "$archive"
  mkdir -p "$package_root"
  cp "$binary" "$package_root/"
  # The install helper ships with Linux packages (it is the executor behind
  # "one-click install", installed by install.sh as a root-resident service)
  if [ -f "$(dirname "$binary")/pojun-hostd" ]; then
    cp "$(dirname "$binary")/pojun-hostd" "$package_root/"
  fi
  if [ -f "$(dirname "$binary")/pojun-maint" ]; then
    cp "$(dirname "$binary")/pojun-maint" "$package_root/"
  fi
  # The watchdog start script is the real entry point: one-click update in the
  # UI relies on it to relaunch the process after exit — running the pojun
  # binary directly means it never comes back after an update. Ship only the
  # variant matching the target OS.
  if [ "$goos" = "windows" ]; then
    cp start.bat "$package_root/"
  else
    cp start.sh "$package_root/"
    chmod +x "$package_root/start.sh"
  fi
  cp -R skills "$package_root/"
  # Platform-bundled MCP servers (FOFA asset mapping): relative paths resolve
  # against start.sh's cwd
  [ -d mcp-servers ] && cp -R mcp-servers "$package_root/"
  cp config.example.json "$package_root/"
  if [ -f README.md ]; then cp README.md "$package_root/"; fi
  (cd "$POJUN_PACKAGE_DIR" && zip -q -r -9 "$(basename "$archive")" "$(basename "$package_root")")
  rm -rf "$package_root"
  ok "Release archive: $archive"
}

build_target() {
  target="$1"
  case "$target" in
    */*) ;;
    *) die "invalid target: $target (must be OS/ARCH)" ;;
  esac
  goos="${target%%/*}"
  goarch="${target##*/}"
  case "$goos" in
    linux|darwin|windows) ;;
    *) die "unsupported OS: $goos (supported: linux, darwin, windows)" ;;
  esac

  binary_name="pojun"
  [ "$goos" = "windows" ] && binary_name="pojun.exe"
  if [ -n "${POJUN_OUTPUT:-}" ] && [ "$POJUN_RELEASE" != "1" ]; then
    output="$POJUN_OUTPUT"
  else
    output="${POJUN_OUTPUT_DIR}/pojun-${goos}-${goarch}/${binary_name}"
  fi
  mkdir -p "$(dirname "$output")"

  info "Compiling ${goos}/${goarch}, version ${POJUN_BUILD_VERSION}"
  GOSUMDB="$POJUN_GOSUMDB" \
  CGO_ENABLED=0 \
  GOOS="$goos" \
  GOARCH="$goarch" \
  go build \
    -tags embedui \
    -trimpath \
    -ldflags "-s -w -buildid= -X main.version=${POJUN_BUILD_VERSION}" \
    -o "$output" \
    ./cmd/pojun

  compress_binary "$output" "$goos"
  if command -v file >/dev/null 2>&1; then file "$output"; fi
  # Privileged install helper (Linux only: relies on a Unix socket + apt/dnf,
  # meaningless on other platforms). The main service is locked down by
  # NoNewPrivileges/ProtectSystem=strict and cannot escalate, so "one-click
  # install" is executed by this root-resident helper — it must ship with the
  # release package.
  if [ "$goos" = "linux" ]; then
    hostd_output="$(dirname "$output")/pojun-hostd"
    info "Compiling ${goos}/${goarch} install helper"
    GOSUMDB="$POJUN_GOSUMDB" \
    CGO_ENABLED=0 \
    GOOS="$goos" \
    GOARCH="$goarch" \
    go build \
      -trimpath \
      -ldflags "-s -w -buildid= -X main.version=${POJUN_BUILD_VERSION}" \
      -o "$hostd_output" \
      ./cmd/pojun-hostd
    compress_binary "$hostd_output" "$goos"
    # Offline maintenance tool (historical data repair: attachment
    # re-registration / builtin prompt updates). Distributed only inside Linux
    # packages; install.sh places it at /opt/pojun/pojun-maint.
    maint_output="$(dirname "$output")/pojun-maint"
    info "Compiling ${goos}/${goarch} maintenance tool"
    GOSUMDB="$POJUN_GOSUMDB" \
    CGO_ENABLED=0 \
    GOOS="$goos" \
    GOARCH="$goarch" \
    go build \
      -trimpath \
      -ldflags "-s -w -buildid= -X main.version=${POJUN_BUILD_VERSION}" \
      -o "$maint_output" \
      ./cmd/pojun-maint
    compress_binary "$maint_output" "$goos"
  fi
  if [ "$POJUN_PACKAGE" = "1" ]; then package_binary "$output" "$goos" "$goarch"; fi
  ok "Build done: $output"
}

write_checksums() {
  [ "$POJUN_PACKAGE" = "1" ] || return 0
  checksum_file="$POJUN_PACKAGE_DIR/SHA256SUMS"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$POJUN_PACKAGE_DIR" && for archive in *.zip; do sha256sum "$archive"; done > "$(basename "$checksum_file")")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$POJUN_PACKAGE_DIR" && for archive in *.zip; do shasum -a 256 "$archive"; done > "$(basename "$checksum_file")")
  else
    warn "sha256sum/shasum not found, skipping SHA256SUMS"
    return 0
  fi
  ok "Checksum file: $checksum_file"
}

mkdir -p "$POJUN_OUTPUT_DIR"
if [ "$POJUN_PACKAGE" = "1" ]; then mkdir -p "$POJUN_PACKAGE_DIR"; fi

old_ifs="$IFS"
IFS=','
read -r -a targets <<< "$POJUN_TARGETS"
IFS="$old_ifs"
[ "${#targets[@]}" -gt 0 ] || die "POJUN_TARGETS must not be empty"
for target in "${targets[@]}"; do
  target="${target//[[:space:]]/}"
  [ -n "$target" ] || continue
  build_target "$target"
done

if [ "$POJUN_PACKAGE" = "1" ]; then
  write_checksums
  info "Release packages written to: $POJUN_PACKAGE_DIR"
fi
