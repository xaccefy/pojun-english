// Host tool health API: returns which pentest tools are available on this host's PATH.
// Makes 'whatever the system has is what you can use' explicit for binary deploys — the
// frontend shows it on the system page; the same data reaches agents via
// graph_overview.
package server

import (
	"net/http"
	"os"

	"github.com/chu0119/pojun/hosttools"
)

func (s *Server) toolsInventory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"tools":       hosttools.Inventory(),
		"summary":     hosttools.Summary(),
		"deploy_mode": deployMode(),
	})
}

// deployMode reports the current deployment shape: Docker containers have a fixed tool
// set; host-binary deployments track what the OS has installed. Detection basis: the
// marker file written by the Dockerfile.
func deployMode() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	return "host"
}
