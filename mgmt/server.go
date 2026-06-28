// Package mgmt provides a local HTTP management API for runtime config updates.
// It is intentionally simple — only the fields editable from the Chrome extension
// are exposed. Bind only to loopback; there is no authentication.
package mgmt

import (
	"encoding/json"
	"log"
	"net/http"

	"impersonate-proxy/config"
)

// Controller is implemented by proxy.Server.
type Controller interface {
	GetActiveConfig() config.ActiveConfig
	Update(preset, clientIP, userAgent string) error
}

// ListenAndServe starts the management HTTP server on addr.
// It blocks until the server exits.
func ListenAndServe(addr string, ctrl Controller) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from Chrome extensions (chrome-extension://<id>).
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, ctrl.GetActiveConfig())

		case http.MethodPost:
			var req struct {
				TLSPreset string `json:"tls_preset"`
				ClientIP  string `json:"client_ip"`
				UserAgent string `json:"user_agent"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := ctrl.Update(req.TLSPreset, req.ClientIP, req.UserAgent); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			log.Printf("mgmt: preset=%s client_ip=%q user_agent=%q",
				req.TLSPreset, req.ClientIP, req.UserAgent)
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
