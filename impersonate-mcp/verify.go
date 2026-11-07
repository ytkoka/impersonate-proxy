package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"impersonate-proxy/filter"
)

// FingerprintSummary is what verify_fingerprint returns: the fingerprint a
// remote server saw, plus the proxy settings that produced it.
type FingerprintSummary struct {
	JA3Hash           string `json:"ja3_hash"`
	JA4               string `json:"ja4"`
	AkamaiFingerprint string `json:"akamai_fingerprint"`
	UserAgent         string `json:"user_agent"`
	IP                string `json:"ip"`

	TLSPreset  string   `json:"tls_preset,omitempty"`
	FilterMode string   `json:"filter_mode,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// peetResponse is the subset of the tls.peet.ws /api/all response we read.
type peetResponse struct {
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	TLS       struct {
		JA3Hash string `json:"ja3_hash"`
		JA4     string `json:"ja4"`
	} `json:"tls"`
	HTTP2 struct {
		Akamai string `json:"akamai_fingerprint"`
	} `json:"http2"`
}

type verifier struct {
	mgmt      *mgmtClient
	proxyURL  string // explicit override; derived from the active config when empty
	caCert    string
	verifyURL string
}

func (v *verifier) run(ctx context.Context) (FingerprintSummary, error) {
	var out FingerprintSummary

	target, err := url.Parse(v.verifyURL)
	if err != nil || target.Host == "" {
		return out, fmt.Errorf("invalid verify URL %q", v.verifyURL)
	}

	cfg, cfgErr := v.mgmt.GetConfig(ctx)
	if cfgErr == nil {
		out.TLSPreset = cfg.TLSPreset
		out.FilterMode = cfg.FilterMode
		if m, err := filter.New(cfg.FilterMode, cfg.FilterHosts); err == nil && !m.Impersonate(target.Host) {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"host filter (mode=%s) excludes %s, so the proxy tunnels it untouched: the result is the client's own fingerprint, not the configured preset",
				m.Mode(), target.Hostname()))
		}
	}

	proxyURL := v.proxyURL
	if proxyURL == "" {
		if cfgErr != nil {
			return out, fmt.Errorf("cannot determine the proxy address (set -proxy-url): %w", cfgErr)
		}
		if proxyURL, err = proxyURLFromListen(cfg.Listen); err != nil {
			return out, err
		}
	} else if cfgErr != nil {
		out.Warnings = append(out.Warnings, "could not read the active config: "+cfgErr.Error())
	}

	client, err := v.httpClient(proxyURL)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.verifyURL, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return out, v.explain(err, proxyURL)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("%s returned HTTP %d via proxy %s", v.verifyURL, resp.StatusCode, proxyURL)
	}

	var pr peetResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&pr); err != nil {
		return out, fmt.Errorf("decoding response from %s: %w", v.verifyURL, err)
	}
	out.JA3Hash = pr.TLS.JA3Hash
	out.JA4 = pr.TLS.JA4
	out.AkamaiFingerprint = pr.HTTP2.Akamai
	out.UserAgent = pr.UserAgent
	out.IP = hostOnly(pr.IP)
	return out, nil
}

// httpClient builds a client that goes through the proxy and trusts its MITM CA.
// The CA file is read on every call because the proxy generates it on first run.
func (v *verifier) httpClient(proxyURL string) (*http.Client, error) {
	pu, err := url.Parse(proxyURL)
	if err != nil || pu.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q", proxyURL)
	}
	tr := &http.Transport{
		Proxy:               http.ProxyURL(pu),
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if v.caCert != "" {
		pem, err := os.ReadFile(v.caCert)
		if err != nil {
			return nil, fmt.Errorf("reading CA certificate: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no PEM certificate found in %s", v.caCert)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

func (v *verifier) explain(err error, proxyURL string) error {
	var unknownCA x509.UnknownAuthorityError
	if errors.As(err, &unknownCA) {
		return fmt.Errorf("the proxy's MITM CA is not trusted; pass -ca-cert <path to ca.crt> or trust it system-wide: %w", err)
	}
	return fmt.Errorf("request to %s via proxy %s failed (is the proxy running?): %w", v.verifyURL, proxyURL, err)
}

// proxyURLFromListen turns a listen address such as ":8080" or "0.0.0.0:8080"
// into a URL a local client can dial.
func proxyURLFromListen(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("cannot derive proxy URL from listen address %q (set -proxy-url): %w", listen, err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

// hostOnly strips the port from the "ip:port" form tls.peet.ws reports.
func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
