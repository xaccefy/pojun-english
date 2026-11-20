# syntax=docker/dockerfile:1
#
# Runtime image (no compilation inside the image): install the full builtin
# toolset and drop in a **pre-built Linux single binary**. The binary is
# cross-compiled by CI's `binaries` job (pure Go, no QEMU) and placed in the
# build context at dist/<TARGETARCH>/pojun. This way multi-arch builds only
# emulate the apt layer for arm64 — not the Next/Go compile — which is much
# faster.
#
# To build the image manually, prepare the binary yourself first:
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/pojun ./cmd/pojun
#   docker build -t pojun:local .
# kerbrute / waybackurls 上游不发 linux/arm64 资产，用 Go 现场编译补齐
# （builder 走目标平台的 golang 镜像，产物架构自动正确；QEMU 下只编译这两个
# 小工具，构建时间增加可控）。
FROM golang:1.26-bookworm AS gobuild
ENV CGO_ENABLED=0 GOBIN=/go/bin
RUN go install github.com/ropnop/kerbrute@v1.0.3 \
    && go install github.com/tomnomnom/waybackurls@v0.1.0

FROM python:3.11-slim-bookworm
ARG TARGETARCH
# Build sources (official defaults; override with --build-arg on restricted
# networks, e.g. in China):
#   docker build --build-arg DEBIAN_MIRROR=mirrors.aliyun.com \
#                --build-arg PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/ .
ARG DEBIAN_MIRROR=deb.debian.org
ARG DEBIAN_SECURITY_MIRROR=deb.debian.org
ARG NODESOURCE_URL=https://deb.nodesource.com/setup_20.x
# Note: NodeSource has no official mirror substitute; on restricted networks
# use --build-arg NODESOURCE_URL=<trusted mirror's setup-script URL>
ARG PIP_INDEX_URL=https://pypi.org/simple
ENV PIP_INDEX_URL=${PIP_INDEX_URL}
RUN if [ "$DEBIAN_MIRROR" != "deb.debian.org" ]; then \
      sed -i "s|deb.debian.org|$DEBIAN_MIRROR|g; s|security.debian.org|$DEBIAN_SECURITY_MIRROR|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
      sed -i "s|deb.debian.org|$DEBIAN_MIRROR|g; s|security.debian.org|$DEBIAN_SECURITY_MIRROR|g" /etc/apt/sources.list; \
    fi
# Base packages + pentest tool group. The pentest group is installed with
# per-package tolerance: packages missing from Debian bookworm repos (e.g.
# nikto, only in Kali repos) are skipped without blocking the build, and the
# "Host Environment" health page will accurately report them missing at
# runtime; newer/fuller versions of gobuster/gitleaks etc. are installed from
# GitHub releases by docker/install-tools.sh.
# Node 20.x comes from NodeSource: bookworm's apt nodejs is 18, Playwright
# requires >=20.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         ca-certificates ripgrep curl wget vim git jq unzip \
         dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
         imagemagick libreoffice-writer libreoffice-calc libreoffice-impress poppler-utils \
    && for pkg in masscan sqlmap hydra whatweb nikto ffuf john python3-impacket socat proxychains4; do \
         apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 \
         || echo "[warn] apt package unavailable, skipping: $pkg"; \
       done \
    && curl -fsSL "$NODESOURCE_URL" | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# kerbrute/waybackurls (upstream ships no arm64 assets; built in the gobuild stage)
COPY --from=gobuild /go/bin/kerbrute /usr/local/bin/kerbrute
COPY --from=gobuild /go/bin/waybackurls /usr/local/bin/waybackurls
# nuclei (vulnerability template scanning engine, works with the
# /app/nuclei-templates intel template library): the official release binary
# is downloaded per-arch; the template tree is maintained by pojun's vulnintel
# syncer (git clone --depth 1 to /app/nuclei-templates, git pull on each sync).
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) nuclei_arch="linux_amd64" ;; \
      arm64) nuclei_arch="linux_arm64" ;; \
      *) echo "unsupported arch: $arch"; exit 1 ;; \
    esac; \
    # Dual-channel version resolution: the GitHub API frequently 403-rate-limits
    # shared CI runner IPs (the v0.4.54 build actually hung here on
    # 2026-11-05); the fallback follows the 302 Location of releases/latest —
    # the same path a browser takes, not subject to API quota. The api.github
    # domain also needs timeouts to avoid hanging forever.
    nuclei_ver="$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name)" || nuclei_ver=""; \
    [ -n "$nuclei_ver" ] && [ "$nuclei_ver" != "null" ] || \
      nuclei_ver="$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 -o /dev/null -w '%{url_effective}' https://github.com/projectdiscovery/nuclei/releases/latest | sed 's|.*/tag/||')"; \
    [ -n "$nuclei_ver" ] || { echo "cannot resolve nuclei version"; exit 1; }; \
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 "https://github.com/projectdiscovery/nuclei/releases/download/${nuclei_ver}/nuclei_${nuclei_ver#v}_${nuclei_arch}.zip" -o /tmp/nuclei.zip; \
    unzip -o /tmp/nuclei.zip -d /tmp/nuclei && install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && nuclei -version && rm -rf /tmp/nuclei /tmp/nuclei.zip
# Preinstall Playwright MCP and CLI (global) so nothing is downloaded at runtime.
# @playwright/mcp: the browser MCP runs via `npx @playwright/mcp` (installed
# globally already, no -y/@latest needed).
# @playwright/cli: provides playwright-cli; verify it is executable via --help.
# Then playwright (browser management); install chromium and its system deps
# with --with-deps so MCP/CLI work on first start inside the container without
# downloading a browser.
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Pre-built binary for the matching arch (dist/amd64/pojun or dist/arm64/pojun)
COPY dist/${TARGETARCH}/pojun /app/pojun
# Privileged install helper: lives as root on a unix socket inside the
# container; the "Host Environment" page can install/reinstall tools at
# runtime. Also used at build time to install all catalog-missing items in one
# pass (batteries included, see install-all below).
COPY dist/${TARGETARCH}/pojun-hostd /app/pojun-hostd
# Watchdog start script: decides from the exit code whether to relaunch the
# process; one-click update in the UI relies on it for the binary swap.
# It also forwards SIGTERM to pojun — docker stop only signals PID 1, and
# without forwarding pojun never sees it, cannot shut down gracefully, and is
# SIGKILLed after 10 seconds.
COPY start.sh /app/start.sh
RUN chmod +x /app/pojun /app/pojun-hostd /app/start.sh
COPY skills/ /app/skills/
# Official-document fonts: needed for docx->PDF rendering (install.sh downloads
# them from raw in binary form; the image COPYs the in-repo files directly)
COPY report/fonts/ /usr/share/fonts/gongwen/
RUN fc-cache -f /usr/share/fonts/gongwen >/dev/null 2>&1 || true
# Built-in pentest tools and wordlists (aligned with install.sh --with-tools;
# see docker/install-tools.sh):
# projectdiscovery suite / gobuster / gitleaks / chisel / amass / dalfox /
# feroxbuster + pip group (wafw00f/netexec/semgrep/pwntools) + SecLists -> /opt/SecLists
COPY docker/install-tools.sh /tmp/install-tools.sh
# Platform-bundled MCP servers (FOFA asset mapping etc.); relative paths
# resolve against start.sh's cwd (/app)
COPY mcp-servers/ /app/mcp-servers/
# uv: the "FOFA asset mapping" MCP preset uses it to launch the Python stdio server
RUN python3 -m pip install --no-cache-dir --quiet uv && uv --version
RUN bash /tmp/install-tools.sh && rm -f /tmp/install-tools.sh
# Note: provisioning the full 90-item catalog is **not** done at build time
# (it would grow the image another 1-2GB and double build time). Instead it is
# preinstalled in the background at container first start (see
# docker/docker-entrypoint.sh): the main service is not blocked, install logs
# go to data/tools-preinstall.log, and the "Host Environment" page reflects
# progress live. Already-installed items are skipped (idempotent); to disable
# background preinstall: environment: POJUN_PREINSTALL_TOOLS=0.
# entrypoint: launch hostd in the background first (root-resident, used by the
# "Host Environment" page's one-click tool install), then exec start.sh
COPY docker/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh
# data/ (SQLite + jwt.key) persistence point
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
