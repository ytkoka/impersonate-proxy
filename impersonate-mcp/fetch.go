package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"impersonate-proxy/hdrprofile"
)

const (
	fetchTimeout    = 30 * time.Second
	maxRedirects    = 10
	defaultMaxBody  = 51200
	hardMaxBody     = 1048576
	maxRequestBytes = 1 << 20
)

var (
	fetchMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true, "OPTIONS": true}
	// safeMethods are the only ones allowed when the server runs with --read-only.
	safeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}
)

type fetchArgs struct {
	URL             string            `json:"url" jsonschema:"Absolute http:// or https:// URL to fetch."`
	Method          string            `json:"method,omitempty" jsonschema:"GET (default), HEAD, POST, PUT, DELETE, PATCH or OPTIONS."`
	Headers         map[string]string `json:"headers,omitempty" jsonschema:"Extra request headers; they replace same-named defaults. GET and HEAD requests carry the preset browser's page-load headers (Accept, Accept-Encoding, Sec-Fetch-*, ...) by default. The proxy may still override User-Agent and client-IP headers according to its settings."`
	Body            string            `json:"body,omitempty" jsonschema:"Request body."`
	FollowRedirects *bool             `json:"follow_redirects,omitempty" jsonschema:"Follow redirects, up to 10 (default true)."`
	MaxBodyBytes    int               `json:"max_body_bytes,omitempty" jsonschema:"Largest response body to return, in bytes (default 51200, capped at 1048576). Longer bodies are cut and body_truncated is set."`
}

// FetchResult is what fetch_url returns. Failures are reported in Error rather
// than as a tool error, so the other fields (tls_preset, elapsed_ms, ...) still
// describe the attempt.
type FetchResult struct {
	Status        int               `json:"status"`
	HTTPVersion   string            `json:"http_version"`
	FinalURL      string            `json:"final_url"`
	Redirects     []string          `json:"redirects"` // URLs that answered with a redirect, in order
	Headers       map[string]string `json:"headers"`   // lower-case names; Set-Cookie values are omitted
	Body          string            `json:"body"`
	BodyTruncated bool              `json:"body_truncated"`
	BodyBytes     int               `json:"body_bytes"` // bytes of the (decoded) body returned
	ElapsedMS     int64             `json:"elapsed_ms"`
	TLSPreset     string            `json:"tls_preset"`
	UserAgent     string            `json:"user_agent"` // the proxy's user_agent setting at send time
	Error         string            `json:"error,omitempty"`
}

// fetcher implements fetch_url on top of the verifier's proxy plumbing, so
// requests take exactly the path verify_fingerprint does: through the proxy,
// with the proxy's current TLS preset, User-Agent, client IP, upstream and
// filter settings applied. It never connects to targets directly.
type fetcher struct {
	v        *verifier
	guard    targetGuard
	readOnly bool
	timeout  time.Duration // fetchTimeout when zero
}

func (f *fetcher) run(ctx context.Context, a fetchArgs) FetchResult {
	start := time.Now()
	res := FetchResult{Redirects: []string{}, Headers: map[string]string{}}
	fail := func(format string, args ...any) FetchResult {
		res.Error = fmt.Sprintf(format, args...)
		res.ElapsedMS = time.Since(start).Milliseconds()
		return res
	}

	u, err := url.Parse(strings.TrimSpace(a.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fail("invalid URL %q: want an absolute http:// or https:// URL", a.URL)
	}
	method := strings.ToUpper(strings.TrimSpace(a.Method))
	if method == "" {
		method = http.MethodGet
	}
	if !fetchMethods[method] {
		return fail("unsupported method %q (use GET, HEAD, POST, PUT, DELETE, PATCH or OPTIONS)", a.Method)
	}
	if f.readOnly && (!safeMethods[method] || a.Body != "") {
		return fail("this server is read-only: only GET, HEAD and OPTIONS without a body are allowed")
	}
	if len(a.Body) > maxRequestBytes {
		return fail("request body too large (max %d bytes)", maxRequestBytes)
	}
	maxBody := a.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxBody
	}
	maxBody = min(maxBody, hardMaxBody)
	follow := a.FollowRedirects == nil || *a.FollowRedirects

	timeout := f.timeout
	if timeout == 0 {
		timeout = fetchTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The allowlist lives in the proxy's config, so a proxy we cannot read it
	// from is a reason to refuse rather than to fetch unrestricted.
	cfg, err := f.v.mgmt.GetConfig(ctx)
	if err != nil {
		return fail("cannot read the proxy configuration (needed to enforce fetch_allow_hosts): %v", err)
	}
	res.TLSPreset = cfg.TLSPreset
	res.UserAgent = cfg.UserAgent

	proxyURL := f.v.proxyURL
	if proxyURL == "" {
		if proxyURL, err = proxyURLFromListen(cfg.Listen); err != nil {
			return fail("%v", err)
		}
	}
	client, err := f.v.httpClient(proxyURL)
	if err != nil {
		return fail("%v", err)
	}
	client.Timeout = 0 // bounded by ctx instead
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	headers := withBrowserDefaults(cfg.TLSPreset, method, a.Headers)
	body := a.Body
	cur := u
	var resp *http.Response
	for hop := 0; ; hop++ {
		if err := f.guard.check(ctx, cur, cfg.FetchAllowHosts); err != nil {
			return fail("%v", err)
		}
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, cur.String(), rd)
		if err != nil {
			return fail("building request: %v", err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err = client.Do(req)
		if err != nil {
			return fail("%s", describeFetchError(ctx, timeout, err, cur, proxyURL))
		}

		loc := resp.Header.Get("Location")
		if !follow || !isRedirect(resp.StatusCode) || loc == "" {
			break
		}
		resp.Body.Close()
		if hop >= maxRedirects {
			res.Status = resp.StatusCode
			res.FinalURL = cur.String()
			return fail("stopped after %d redirects", maxRedirects)
		}
		next, err := cur.Parse(loc)
		if err != nil || (next.Scheme != "http" && next.Scheme != "https") {
			return fail("bad redirect Location %q from %s", loc, cur)
		}
		res.Redirects = append(res.Redirects, cur.String())
		if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusPermanentRedirect {
			// 301/302/303: the follow-up is a GET without a body, as browsers do.
			if method != http.MethodHead {
				method = http.MethodGet
			}
			body = ""
		}
		if !strings.EqualFold(next.Hostname(), cur.Hostname()) {
			headers = withoutCredentials(headers)
		}
		cur = next
	}
	defer resp.Body.Close()

	res.Status = resp.StatusCode
	res.HTTPVersion = resp.Proto
	res.FinalURL = cur.String()
	for k, vs := range resp.Header {
		k = strings.ToLower(k)
		if k == "set-cookie" {
			res.Headers[k] = fmt.Sprintf("<%d cookie(s), values omitted>", len(vs))
			continue
		}
		res.Headers[k] = strings.Join(vs, ", ")
	}

	reader, closeBody, decoded, err := decodeBody(resp)
	defer closeBody()
	if err != nil {
		return fail("%v", err)
	}
	if decoded {
		// The body below is plain, so these no longer describe it.
		delete(res.Headers, "content-encoding")
		delete(res.Headers, "content-length")
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(maxBody)+1))
	if err != nil && len(data) == 0 {
		return fail("reading response body: %v", describeFetchError(ctx, timeout, err, cur, proxyURL))
	}
	if len(data) > maxBody {
		data = data[:maxBody]
		res.BodyTruncated = true
	}
	res.Body, res.BodyBytes = renderBody(data, resp.Header.Get("Content-Type"), res.BodyTruncated)
	res.ElapsedMS = time.Since(start).Milliseconds()
	return res
}

// withBrowserDefaults returns the request headers for a fetch: for GET and HEAD
// (what a browser does when it loads a page) the preset's browser's navigation
// headers — Accept, Accept-Encoding, Sec-Fetch-* and so on — with any header
// the caller gave replacing the default of the same name. Other methods get
// only what the caller gave, since those headers describe page loads.
func withBrowserDefaults(preset, method string, given map[string]string) map[string]string {
	out := make(map[string]string, len(given)+8)
	if method == http.MethodGet || method == http.MethodHead {
		for _, h := range hdrprofile.Navigation(preset) {
			if !hdrprofile.Has(given, h.Name) {
				out[h.Name] = h.Value
			}
		}
	}
	for k, v := range given {
		out[k] = v
	}
	return out
}

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// withoutCredentials drops headers that must not follow a redirect to another host.
func withoutCredentials(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		switch strings.ToLower(k) {
		case "authorization", "cookie", "proxy-authorization":
		default:
			out[k] = v
		}
	}
	return out
}

// renderBody returns the text to report for a response body and the number of
// body bytes it stands for. Text is returned as a string; anything else is
// summarised, since raw bytes are of no use in a tool result.
func renderBody(data []byte, contentType string, truncated bool) (string, int) {
	n := len(data)
	if n == 0 {
		return "", 0
	}
	ct := contentType
	if ct == "" {
		ct = http.DetectContentType(data)
	}
	if !isTextType(ct) {
		return fmt.Sprintf("<binary %d bytes, %s>", n, ct), n
	}
	if truncated {
		// Don't end on half a character.
		for i := 0; i < utf8.UTFMax && len(data) > 0 && !utf8.Valid(data); i++ {
			data = data[:len(data)-1]
		}
	}
	return strings.ToValidUTF8(string(data), "�"), n
}

func isTextType(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	}
	switch {
	case strings.HasPrefix(mt, "text/"),
		strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+xml"):
		return true
	}
	switch mt {
	case "application/json", "application/xml", "application/javascript", "application/ecmascript",
		"application/x-javascript", "application/x-www-form-urlencoded", "application/x-ndjson",
		"application/yaml", "application/x-yaml", "application/graphql", "application/xhtml+xml":
		return true
	}
	return false
}

// describeFetchError turns a transport failure into a reason an agent can act on.
func describeFetchError(ctx context.Context, timeout time.Duration, err error, u *url.URL, proxyURL string) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("timed out after %s fetching %s", timeout, u)
	case errors.Is(err, context.Canceled):
		return "request cancelled"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "Bad Gateway") || strings.Contains(msg, "502"):
		return fmt.Sprintf("the proxy could not reach %s (DNS failure, connection refused, TLS handshake failure or upstream proxy error — see the proxy's log): %v", u.Host, err)
	case strings.Contains(msg, "connection refused") && strings.Contains(msg, hostPortOf(proxyURL)):
		return fmt.Sprintf("cannot connect to the proxy at %s (is it running?): %v", proxyURL, err)
	case strings.Contains(msg, "certificate"):
		return fmt.Sprintf("the proxy's MITM CA is not trusted; pass --ca-cert <path to ca.crt> or trust it system-wide: %v", err)
	}
	return fmt.Sprintf("fetching %s via proxy %s failed: %v", u, proxyURL, err)
}

func hostPortOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return raw
}
