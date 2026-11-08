// Command impersonate-mcp is a stdio MCP server that drives a running
// impersonate-proxy through its management API.
//
// It is a pure client of the management API: the proxy knows nothing about MCP.
// Protocol traffic goes over stdout, so all logging goes to stderr.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	version = "0.1.0"

	defaultMgmtURL   = "http://127.0.0.1:8081"
	defaultVerifyURL = "https://tls.peet.ws/api/all"
)

// options configures the server. Zero values are filled in by newServer.
type options struct {
	MgmtURL   string // management API base URL
	ProxyURL  string // proxy URL used by verify_fingerprint; derived from the active config when empty
	CACert    string // PEM file with the proxy's MITM CA; system roots are used when empty
	VerifyURL string // fingerprint echo endpoint
	ReadOnly  bool   // expose only the tools that cannot change settings

	// Test hooks.
	lookup       func(ctx context.Context, host string) ([]netip.Addr, error)
	fetchTimeout time.Duration
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("impersonate-mcp: ")
	log.SetOutput(os.Stderr)

	var o options
	readOnlyDefault, _ := strconv.ParseBool(getenv("IMPERSONATE_READ_ONLY"))
	flag.StringVar(&o.MgmtURL, "mgmt-url", envOr("IMPERSONATE_MGMT_URL", defaultMgmtURL),
		"management API base URL (env IMPERSONATE_MGMT_URL)")
	flag.StringVar(&o.ProxyURL, "proxy-url", getenv("IMPERSONATE_PROXY_URL"),
		"proxy URL for verify_fingerprint and fetch_url; default: derived from the proxy's `listen` (env IMPERSONATE_PROXY_URL)")
	flag.StringVar(&o.CACert, "ca-cert", getenv("IMPERSONATE_CA_CERT"),
		"path to the proxy's ca.crt for verify_fingerprint and fetch_url; default: system trust store (env IMPERSONATE_CA_CERT)")
	flag.StringVar(&o.VerifyURL, "verify-url", envOr("IMPERSONATE_VERIFY_URL", defaultVerifyURL),
		"fingerprint echo endpoint (env IMPERSONATE_VERIFY_URL)")
	flag.BoolVar(&o.ReadOnly, "read-only", readOnlyDefault,
		"hide every tool that changes proxy settings; fetch_url is limited to GET/HEAD/OPTIONS (env IMPERSONATE_READ_ONLY)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("impersonate-mcp", version)
		return
	}

	srv, err := newServer(o)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

// getenv is os.Getenv that treats an unexpanded "${...}" placeholder as unset.
// An MCPB host substitutes ${user_config.KEY} into the environment, and the
// spec does not say what an optional setting the user left blank becomes; this
// keeps a literal "${user_config.ca_cert}" from being used as a file path.
func getenv(key string) string {
	v := os.Getenv(key)
	if strings.HasPrefix(v, "${") {
		return ""
	}
	return v
}

// newServer builds the MCP server with its tools registered.
func newServer(o options) (*mcp.Server, error) {
	if o.MgmtURL == "" {
		o.MgmtURL = defaultMgmtURL
	}
	if o.VerifyURL == "" {
		o.VerifyURL = defaultVerifyURL
	}

	mgmt, err := newMgmtClient(o.MgmtURL)
	if err != nil {
		return nil, err
	}
	if !mgmt.loopback() {
		log.Printf("WARNING: management API %s is not a loopback address; it has no authentication", o.MgmtURL)
	}

	srv := mcp.NewServer(
		&mcp.Implementation{Name: "impersonate-mcp", Version: version},
		&mcp.ServerOptions{Instructions: instructions(o.ReadOnly)},
	)
	v := &verifier{mgmt: mgmt, proxyURL: o.ProxyURL, caCert: o.CACert, verifyURL: o.VerifyURL}
	registerTools(srv, mgmt, v, &fetcher{v: v, guard: targetGuard{lookup: o.lookup}, readOnly: o.ReadOnly, timeout: o.fetchTimeout}, o.ReadOnly)
	return srv, nil
}

func instructions(readOnly bool) string {
	s := "Controls a running impersonate-proxy (TLS/HTTP2/header fingerprint impersonation) via its management API. " +
		"Changes apply to new connections immediately. Use verify_fingerprint after a change to confirm what a server actually sees."
	if readOnly {
		s += " This server is read-only: configuration cannot be changed."
	}
	return s
}
