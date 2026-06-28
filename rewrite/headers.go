package rewrite

import (
	"net/http"

	"impersonate-proxy/config"
)

type Rewriter struct {
	cfg config.HTTPConfig
}

func New(cfg config.HTTPConfig) *Rewriter {
	return &Rewriter{cfg: cfg}
}

// Apply modifies req headers in place: remove → add → User-Agent override → client IP spoof.
func (r *Rewriter) Apply(req *http.Request) {
	for _, h := range r.cfg.RemoveHeaders {
		req.Header.Del(h)
	}
	for k, v := range r.cfg.AddHeaders {
		req.Header.Set(k, v)
	}
	if r.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", r.cfg.UserAgent)
	}
	if r.cfg.ClientIP != "" {
		req.Header.Set("X-Forwarded-For", r.cfg.ClientIP)
		req.Header.Set("True-Client-IP", r.cfg.ClientIP)
	}
}

func (r *Rewriter) Order() []string {
	return r.cfg.HeaderOrder
}
