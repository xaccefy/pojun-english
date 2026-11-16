// Command pojun-hostd is POJUN's privileged installation helper.
//
// It runs as root under systemd, listens on a single Unix socket, and performs
// "one-click installs" according to the hosttools allowlist. The main service (pojun)
// is restricted by NoNewPrivileges + ProtectSystem=strict and cannot escalate
// privileges, so installation actions must live here.
//
// Usage:
//
//	pojun-hostd -socket /run/pojun/hostd.sock -socket-group pojun
//	pojun-hostd -check          # self-check: package manager/directory permissions/allowlist, no service started
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chu0119/pojun/hostd"
	"github.com/chu0119/pojun/hosttools"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		socketPath  = flag.String("socket", "/run/pojun/hostd.sock", "Unix socket path")
		socketMode  = flag.String("socket-mode", "0660", "socket permissions (octal)")
		socketGroup = flag.String("socket-group", "", "socket group (blank=no change, usually the main service's runtime user)")
		check       = flag.Bool("check", false, "exit after self-check (do not start the service)")
		installAll  = flag.Bool("install-all", false, "install all missing tools in the catalog, then exit")
		showVer     = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("pojun-hostd", version)
		return
	}

	mgr := hostd.DetectPkgMgr()
	if *check {
		runCheck(*socketPath, *socketGroup, mgr)
		return
	}

	if os.Geteuid() != 0 {
		log.Fatalf("[hostd] must run as root (install actions write to /usr and call the package manager)")
	}
	if mgr == hostd.PkgNone {
		log.Printf("[hostd] warning: apt/dnf not detected; GitHub/pip-type tools can still be installed")
	}
	if *installAll {
		runInstallAll(mgr)
		return
	}

	mode := parseMode(*socketMode)
	ln, err := hostd.Listen(*socketPath, mode, *socketGroup)
	if err != nil {
		log.Fatalf("[hostd] failed to listen on %s: %v", *socketPath, err)
	}
	log.Printf("[hostd] v%s ready socket=%s mode=%s group=%q pkg_mgr=%s tools=%d",
		version, *socketPath, *socketMode, *socketGroup, mgr, len(hosttools.Inventory()))

	// The parent ctx for tasks = process lifetime: on SIGTERM, cancel even in-progress installs.
	// Never pass the HTTP request's ctx — it is cancelled as soon as the handler returns, and queued jobs would instantly become cancelled.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hs := hostd.NewServer(ctx, log.New(os.Stderr, "", log.LstdFlags))
	hs.Version = version
	// The executable's own path is used for "self-replacement": even if renamed/symlinked, the real file is recognized.
	if exe, runErr := os.Executable(); runErr == nil {
		if resolved, e := filepath.EvalSymlinks(exe); e == nil {
			exe = resolved
		}
		hs.SelfPath = exe
	}

	srv := &http.Server{
		Handler:           hs.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[hostd] service error: %v", err)
		}
	}()
	<-ctx.Done()
	log.Printf("[hostd] received stop signal, exiting gracefully")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	_ = os.Remove(*socketPath)
}

// runInstallAll installs all missing tools in the catalog sequentially, for install.sh --with-tools preinstallation.
// It reuses hostd's fixed recipes and serial queue; failures are printed per item without interrupting subsequent installs.
func runInstallAll(mgr hostd.PkgMgr) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hs := hostd.NewServer(ctx, log.New(os.Stderr, "", log.LstdFlags))
	hs.Version = version
	proxy := firstNonEmpty(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy"), os.Getenv("HTTP_PROXY"), os.Getenv("http_proxy"))
	if v, err := hostd.ValidateProxy(proxy); err == nil {
		proxy = v
	} else {
		log.Printf("[hostd] ignoring invalid proxy: %v", err)
		proxy = ""
	}
	missing := 0
	failed := 0
	for _, tool := range hosttools.Inventory() {
		if tool.Available || !tool.Installable {
			continue
		}
		missing++
		fmt.Printf("[install] %-20s %s\n", tool.ID, tool.Name)
		job, err := hs.Start(ctx, tool.ID, proxy)
		if err != nil {
			failed++
			fmt.Printf("[skip] %-20s %v\n", tool.ID, err)
			continue
		}
		for job.State != hostd.StateDone && job.State != hostd.StateFailed && job.State != hostd.StateCancelled {
			select {
			case <-ctx.Done():
				fmt.Printf("[stop] %-20s interrupt received\n", tool.ID)
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
		if job.State == hostd.StateDone {
			fmt.Printf("[ok]   %-20s done\n", tool.ID)
		} else {
			failed++
			fmt.Printf("[fail] %-20s %s %s\n", tool.ID, job.State, job.Err)
		}
	}
	fmt.Printf("[hostd] preinstall finished: missing %d, failed %d\n", missing, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// runCheck does not start the service; it only reports whether the environment meets installation conditions — for deployment scripts and troubleshooting.
func runCheck(socketPath, group string, mgr hostd.PkgMgr) {
	fmt.Printf("pojun-hostd %s\n", version)
	fmt.Printf("euid        : %d (needs 0)\n", os.Geteuid())
	fmt.Printf("pkg_mgr     : %q (apt/dnf for system-repo tools)\n", string(mgr))
	fmt.Printf("socket      : %s\n", socketPath)
	fmt.Printf("socket_group: %q\n", group)
	if d := dirOf(socketPath); d != "" {
		if err := os.MkdirAll(d, 0o755); err == nil {
			fmt.Printf("socket dir  : %s creatable ✓\n", d)
		} else {
			fmt.Printf("socket dir  : %s creation failed ✗ %v\n", d, err)
		}
	}
	if _, err := net.ResolveUnixAddr("unix", socketPath); err != nil {
		fmt.Printf("unix socket : unsupported ✗ %v\n", err)
	}
	inv := hosttools.Inventory()
	miss := 0
	for _, t := range inv {
		if !t.Available {
			miss++
		}
	}
	fmt.Printf("tools       : available %d / %d, missing %d (one-click installable %d)\n",
		len(inv)-miss, len(inv), miss, countInstallable(inv))
}

func countInstallable(inv []hosttools.Tool) int {
	n := 0
	for _, t := range inv {
		if !t.Available && t.Installable {
			n++
		}
	}
	return n
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return ""
}

func parseMode(s string) os.FileMode {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		log.Fatalf("[hostd] socket-mode must be octal, got %q", s)
	}
	return os.FileMode(v)
}
