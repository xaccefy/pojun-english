#!/usr/bin/env bash
# Built-in tool installation for the Docker image (runs at build time, docker/install-tools.sh).
#
# Aligned with the tool set of the binary form's install.sh --with-tools — the Docker form has no
# pojun-hostd one-click install (the privileged helper only serves systemd deployments), so every tool
# visible on the host environment "health check" page must ship inside the image, otherwise it always
# shows as missing.
#
# Differences (relative to --with-tools):
#   - nuclei is not installed here: the Dockerfile installs it separately (with version verification)
#   - SecLists installs to /opt/SecLists (matching the directory reference in hosttools.go)
#   - Official document fonts are COPYed straight from report/fonts in the repo by the Dockerfile (not downloaded at build time)
set -euo pipefail

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }

# fetch: download with retries — GitHub release blob flakiness on the same day is normal (measured
# 2026-11-05: the same URL passed a whole round on CI, then failed every time the next round);
# three rounds 8s apart ride out most flaky windows.
fetch(){
  local url="$1" out="$2" i
  for i in 1 2 3; do
    curl -fsSL --retry 2 --connect-timeout 15 --max-time 300 "$url" -o "$out" && return 0
    sleep 8
  done
  return 1
}

arch="$(dpkg --print-architecture)"
case "$arch" in
  amd64) pa="amd64"  p2="x86_64"  p3="x86" p4="x64" lin="x86_64" ;;
  arm64) pa="arm64"  p2="aarch64" p3="arm" p4="arm64" lin="arm64" ;;
  *) echo "unsupported arch: $arch"; exit 1 ;;
esac

# -- The apt pentest group is already installed package-by-package with error tolerance in the Dockerfile base layer --
# (masscan/sqlmap/hydra/whatweb/nikto/ffuf/john/impacket/socat/proxychains4;
#   packages missing from the bookworm repos (e.g. nikto) leave a [warn] in the build log and the health page reports them as missing)

# -- GitHub Release single files ----------------------------
# Table: repo|asset template|binary name. Placeholders {ver}(no v) {verv}(with v)
# {arch}(amd64/arm64) {arch2}(x86_64/aarch64) {arch3}(x86/arm) {arch4}(x64/arm64).
# Same table as install.sh (except nuclei/gitleaks which the Dockerfile/apt already covers).
specs="
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

tmpd="$(mktemp -d)"
trap 'rm -rf "$tmpd"' EXIT
for spec in $specs; do
  repo="$(printf '%s' "$spec" | cut -d'|' -f1)"
  tmpl="$(printf '%s' "$spec" | cut -d'|' -f2)"
  bin="$(printf '%s' "$spec" | cut -d'|' -f3)"
  if command -v "$bin" >/dev/null 2>&1; then ok "  $bin already present"; continue; fi
  # Version resolution has two channels: when the API is rate-limited, follow the releases/latest 302 redirect (no API quota used)
  tag="$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 "https://api.github.com/repos/$repo/releases/latest" \
    | grep -oE '"tag_name": *"[^"]+"' | head -1 | cut -d'"' -f4)" || tag=""
  if [ -z "$tag" ]; then
    tag="$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 -o /dev/null -w '%{url_effective}' \
      "https://github.com/$repo/releases/latest" | sed 's|.*/tag/||')" || tag=""
  fi
  if [ -z "$tag" ]; then warn "  $bin version unresolvable, skipping"; continue; fi
  ver="${tag#v}"
  asset="$tmpl"
  asset="${asset//\{ver\}/$ver}"; asset="${asset//\{verv\}/$tag}"
  asset="${asset//\{arch\}/$pa}";  asset="${asset//\{arch2\}/$p2}"
  asset="${asset//\{arch3\}/$p3}"; asset="${asset//\{arch4\}/$p4}"; asset="${asset//\{lin\}/$lin}"
  url="https://github.com/$repo/releases/download/${tag}/${asset}"
  file="$tmpd/$(basename "$asset")"
  if ! fetch "$url" "$file"; then warn "  $bin download failed, skipping"; continue; fi
  xdir="$tmpd/x"; rm -rf "$xdir"; mkdir -p "$xdir"
  case "$asset" in
    *.zip) unzip -oq "$file" -d "$xdir" 2>/dev/null || true ;;
    *.tar.gz|*.tgz) tar -xzf "$file" -C "$xdir" 2>/dev/null || true ;;
    *.gz)  gzip -dc "$file" > "$xdir/$bin" 2>/dev/null || true ;;
  esac
  found="$(find "$xdir" -type f -name "$bin" 2>/dev/null | head -1)"
  if [ -n "$found" ] && [ -s "$found" ]; then
    install -m 0755 "$found" "/usr/local/bin/$bin"
    ok "  $bin $tag"
  else
    warn "  $bin binary not found after extraction ($url)"
  fi
done

# -- pip group (the python base image ships pip, no PEP668 restriction) --
# Package name|executable name. Individually || true: one package failing doesn't block the whole build,
# but the build log shows a warn and the host environment health page honestly reports it as missing.
info "pip installing wafw00f / semgrep / pwntools..."
# impacket must go through pip: Debian's python3-impacket deb only ships the library, not the
# impacket-smbexec and other command scripts; the pip version installs the full /usr/local/bin/impacket-* set.
# netexec (nxc) is not installed: NetExec went commercial from 2026 and all distribution files on PyPI
# were pulled (/simple/netexec 404), so pip can't fetch it. Install from GitHub source when needed
# (the netexec entry in the hosttools catalog carries a note), and the runtime health check reports it as missing.
for pkg in wafw00f semgrep pwntools; do
  if python3 -m pip install --no-cache-dir --root-user-action=ignore "$pkg" >/dev/null 2>&1; then
    ok "  $pkg"
  else
    warn "  $pkg pip install failed"
  fi
done

# -- impacket dedicated install -----------------------------
# No PyPI channel registers commands (both the 0.11 and 0.12+ wheel/sdist were measured to lack impacket-*
# scripts), while pentest jobs invoke them by name: impacket-smbexec/wmiexec/getST.
# Strategy: (1) install from the codeload master source (full examples); (2) regardless of (1)'s outcome,
# generate dual-name wrappers from the examples directory (impacket-<name> and <name>) so the commands always exist.
imp_ok=0
rm -rf /tmp/impacket-src; mkdir -p /tmp/impacket-src
for i in 1 2 3; do
  # Avoid pip git+: that needs git on the build machine; the codeload tarball goes over a CDN and fetch has its own retries
  if fetch "https://github.com/fortra/impacket/archive/refs/heads/master.tar.gz" /tmp/impacket-src/imp.tar.gz; then
    tar -xzf /tmp/impacket-src/imp.tar.gz -C /tmp/impacket-src 2>/dev/null || true
    d="$(find /tmp/impacket-src -maxdepth 1 -type d -name 'impacket-*' | head -1)"
    [ -n "$d" ] || break
    python3 -m pip install --no-cache-dir --root-user-action=ignore "$d" >/dev/null 2>&1 \
      && command -v impacket-smbexec >/dev/null 2>&1 && { imp_ok=1; break; }
  fi
  sleep 8
done
[ "$imp_ok" = "1" ] && ok "  impacket (from source, includes the full example command set)"

# Wrapper fallback: prefer the installed package's examples directory (shipped by both source and wheel); if even
# examples is absent (PyPI blocked/network fully down), pull the sdist with pip download, extract examples, then generate.
gen_wrappers(){
  local ex="$1" f base
  for f in "$ex"/*.py; do
    [ -e "$f" ] || continue
    base="$(basename "$f" .py)"
    case "$base" in __init__|logger|utils|*_help) continue ;; esac
    printf '#!/bin/sh\nexec python3 "%s/%s.py" "$@"\n' "$ex" "$base" > "/usr/local/bin/impacket-$base"
    chmod +x "/usr/local/bin/impacket-$base"
    command -v "$base" >/dev/null 2>&1 || cp "/usr/local/bin/impacket-$base" "/usr/local/bin/$base"
  done
}
exdir="$(python3 -c 'import impacket, os; print(os.path.join(os.path.dirname(impacket.__file__), "examples"))')" 2>/dev/null || exdir=""
if [ -z "$exdir" ] || [ -z "$(find "$exdir" -maxdepth 1 -name 'smbexec.py' 2>/dev/null)" ]; then
  rm -rf /tmp/impsd; mkdir -p /tmp/impsd
  if python3 -m pip download impacket --no-deps --no-binary :all: -d /tmp/impsd >/dev/null 2>&1; then
    sd="$(find /tmp/impsd -name 'impacket-*.tar.gz' | head -1)"
    [ -n "$sd" ] && tar -xzf "$sd" -C /tmp/impsd 2>/dev/null
    exdir="$(find /tmp/impsd -type d -name examples | head -1)"
  fi
fi
if [ -n "$exdir" ] && [ -f "$exdir/smbexec.py" ]; then
  gen_wrappers "$exdir"
  ok "  impacket example command wrappers (impacket-smbexec / wmiexec / secretsdump ...)"
elif [ "$imp_ok" != "1" ]; then
  warn "  impacket commands unavailable (neither PyPI nor GitHub reachable; the health page will report them as missing)"
fi

# -- SecLists wordlists: not installed at build time (v0.4.69) -----------------
# A shallow clone of SecLists is about 2.5GB, the single largest contributor to image size. Instead it is installed
# on first container start by the "catalog background preinstall" (the seclists entry in hosttools, KindScript + Detect
# dir:/opt/SecLists), slimming the main image by about 2.5GB; users can also install/reinstall it individually on the
# "Host Environment" page. Binary deployments still use install_wordlists (install.sh) unchanged.
info "SecLists wordlists moved to first-boot background preinstall (not cloned during image build)"

# -- summary health check -----------------------------------------
info "Built-in tool inventory:"
for b in nmap masscan sqlmap hydra whatweb nikto ffuf john impacket-smbexec socat proxychains4 \
         nuclei httpx subfinder naabu dnsx katana tlsx notify interactsh-client gitleaks \
         chisel amass dalfox feroxbuster gobuster wafw00f semgrep pwn; do
  if command -v "$b" >/dev/null 2>&1; then ok "  $b"; else warn "  $b missing"; fi
done
