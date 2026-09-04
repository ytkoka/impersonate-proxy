// Package mgmt provides a local HTTP management API for runtime config updates.
// It is intentionally simple — only the fields editable from the Chrome extension
// are exposed. Bind only to loopback; there is no authentication.
package mgmt

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"impersonate-proxy/config"
)

// Controller is implemented by proxy.Server.
type Controller interface {
	GetActiveConfig() config.ActiveConfig
	UpdateConfig(patch config.ConfigPatch) error
}

// ListenAndServe starts the management HTTP server on addr.
// It blocks until the server exits.
func ListenAndServe(addr string, ctrl Controller) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/upstream", func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); strings.HasPrefix(origin, "chrome-extension://") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cfg := ctrl.GetActiveConfig()
		writeJSON(w, struct {
			Enabled           bool     `json:"enabled"`
			Select            string   `json:"select"`
			Proxies           []string `json:"proxies"`
			SuppressIPHeaders bool     `json:"suppress_ip_headers"`
		}{
			Enabled:           cfg.UpstreamEnabled,
			Select:            cfg.UpstreamSelect,
			Proxies:           cfg.UpstreamProxies,
			SuppressIPHeaders: cfg.UpstreamSuppressIPHeaders,
		})
	})

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from Chrome extensions (chrome-extension://<id>) only.
		// A plain website's fetch() Origin can never carry this scheme, so this
		// keeps arbitrary web pages from reconfiguring the proxy cross-origin
		// while still working for any locally installed extension ID.
		if origin := r.Header.Get("Origin"); strings.HasPrefix(origin, "chrome-extension://") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, ctrl.GetActiveConfig())

		case http.MethodPost:
			var patch config.ConfigPatch
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := ctrl.UpdateConfig(patch); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			log.Printf("mgmt: %s", describePatch(patch))
			writeJSON(w, ctrl.GetActiveConfig())

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	log.Printf("management API on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// describePatch renders only the fields actually present in a ConfigPatch,
// so the log line reflects what was really sent instead of implying every
// PATCH touches every field. Only proxy *names* ever appear here — never
// upstream URLs or credentials.
func describePatch(p config.ConfigPatch) string {
	var parts []string
	if p.TLSPreset != nil {
		parts = append(parts, fmt.Sprintf("tls_preset=%s", *p.TLSPreset))
	}
	if p.CustomHello != nil {
		parts = append(parts, "custom_hello=<set>")
	}
	if p.ClientIP != nil {
		parts = append(parts, fmt.Sprintf("client_ip=%q", *p.ClientIP))
	}
	if p.UserAgent != nil {
		parts = append(parts, fmt.Sprintf("user_agent=%q", *p.UserAgent))
	}
	if p.UpstreamEnabled != nil {
		parts = append(parts, fmt.Sprintf("upstream_enabled=%v", *p.UpstreamEnabled))
	}
	if p.UpstreamSelect != nil {
		parts = append(parts, fmt.Sprintf("upstream_select=%s", *p.UpstreamSelect))
	}
	if len(parts) == 0 {
		return "(empty patch)"
	}
	return strings.Join(parts, " ")
}
