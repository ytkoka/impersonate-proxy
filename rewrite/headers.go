package rewrite

import (
	"fmt"
	"math/rand/v2"
	"net/http"

	"impersonate-proxy/config"
)

// userAgents is the pool used when user_agent is set to "random".
var userAgents = []string{
	// Chrome — Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	// Chrome — macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	// Chrome — Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	// Chrome — Android
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	// Firefox — Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
	// Firefox — macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
	// Firefox — Linux
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
	// Safari — macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	// Safari — iOS
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	// Edge — Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
}

type Rewriter struct {
	cfg config.HTTPConfig
}

func New(cfg config.HTTPConfig) *Rewriter {
	return &Rewriter{cfg: cfg}
}

// Apply modifies req headers in place: remove → add → User-Agent → client IP.
// Setting either field to "random" generates a new random value per request.
func (r *Rewriter) Apply(req *http.Request) {
	for _, h := range r.cfg.RemoveHeaders {
		req.Header.Del(h)
	}
	for k, v := range r.cfg.AddHeaders {
		req.Header.Set(k, v)
	}
	switch r.cfg.UserAgent {
	case "random":
		req.Header.Set("User-Agent", userAgents[rand.N(len(userAgents))])
	case "":
		// pass through
	default:
		req.Header.Set("User-Agent", r.cfg.UserAgent)
	}
	switch r.cfg.ClientIP {
	case "random":
		ip := randomPublicIP()
		req.Header.Set("X-Forwarded-For", ip)
		req.Header.Set("True-Client-IP", ip)
	case "":
		// disabled
	default:
		req.Header.Set("X-Forwarded-For", r.cfg.ClientIP)
		req.Header.Set("True-Client-IP", r.cfg.ClientIP)
	}
}

func (r *Rewriter) Order() []string {
	return r.cfg.HeaderOrder
}

// randomPublicIP returns a random public IPv4 address, skipping private,
// loopback, link-local, and IANA-reserved ranges (RFC 5735 / RFC 6890).
func randomPublicIP() string {
	for {
		a, b, c, d := rand.N(256), rand.N(256), rand.N(256), rand.N(256)
		if isPublicIPv4(a, b, c, d) {
			return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
		}
	}
}

func isPublicIPv4(a, b, c, _ int) bool {
	switch {
	case a == 0:                          // 0.0.0.0/8
		return false
	case a == 10:                         // 10.0.0.0/8 private
		return false
	case a == 100 && b >= 64 && b <= 127: // 100.64.0.0/10 shared address space
		return false
	case a == 127:                        // 127.0.0.0/8 loopback
		return false
	case a == 169 && b == 254:            // 169.254.0.0/16 link-local
		return false
	case a == 172 && b >= 16 && b <= 31: // 172.16.0.0/12 private
		return false
	case a == 192 && b == 0 && c == 2:   // 192.0.2.0/24 TEST-NET-1
		return false
	case a == 192 && b == 168:           // 192.168.0.0/16 private
		return false
	case a == 198 && b >= 18 && b <= 19: // 198.18.0.0/15 benchmarking
		return false
	case a == 198 && b == 51 && c == 100: // 198.51.100.0/24 TEST-NET-2
		return false
	case a == 203 && b == 0 && c == 113: // 203.0.113.0/24 TEST-NET-3
		return false
	case a >= 224:                        // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved
		return false
	}
	return true
}
