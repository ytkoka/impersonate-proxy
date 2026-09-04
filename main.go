package main

import (
	"flag"
	"log"

	"impersonate-proxy/config"
	"impersonate-proxy/fp"
	"impersonate-proxy/mgmt"
	"impersonate-proxy/mitm"
	"impersonate-proxy/proxy"
	"impersonate-proxy/upstream"
)

func main() {
	configPath := flag.String("config", "config.yaml", "config file path")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
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

	srv := proxy.New(cfg, ca, dialer, upstreamMgr)
	if cfg.MgmtListen != "" {
		go func() {
			if err := mgmt.ListenAndServe(cfg.MgmtListen, srv); err != nil {
				log.Printf("management API: %v", err)
			}
		}()
	}
	log.Fatal(srv.ListenAndServe())
}
