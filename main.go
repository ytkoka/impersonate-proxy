package main

import (
	"flag"
	"log"
	"strings"

	"impersonate-proxy/config"
	"impersonate-proxy/fp"
	"impersonate-proxy/mgmt"
	"impersonate-proxy/mitm"
	"impersonate-proxy/proxy"
	"impersonate-proxy/upstream"
)

func main() {
	configPath := flag.String("config", "config.yaml", "config file path")
	fetchAllow := flag.String("fetch-allow-hosts", "",
		"comma-separated hosts (and their subdomains) the MCP fetch_url tool may reach; overrides fetch_allow_hosts in the config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if *fetchAllow != "" {
		cfg.FetchAllowHosts = splitHosts(*fetchAllow)
	}

	ca, err := mitm.LoadOrCreateCA(cfg.CACert, cfg.CAKey)
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}

	dialer, err := fp.NewDialerFromConfig(cfg.TLS)
	if err != nil {
		log.Fatalf("init dialer: %v", err)
	}

	upstreamMgr, err := upstream.New(cfg.Upstream)
	if err != nil {
		log.Fatalf("init upstream: %v", err)
	}

	srv, err := proxy.New(cfg, ca, dialer, upstreamMgr)
	if err != nil {
		log.Fatalf("init proxy: %v", err)
	}
	if cfg.MgmtListen != "" {
		go func() {
			if err := mgmt.ListenAndServe(cfg.MgmtListen, srv); err != nil {
				log.Printf("management API: %v", err)
			}
		}()
	}
	log.Fatal(srv.ListenAndServe())
}

// splitHosts parses a comma-separated host list, dropping blanks.
func splitHosts(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}
