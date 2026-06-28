package main

import (
	"flag"
	"log"

	"impersonate-proxy/config"
	"impersonate-proxy/fp"
	"impersonate-proxy/mgmt"
	"impersonate-proxy/mitm"
	"impersonate-proxy/proxy"
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

	dialer, err := fp.NewDialer(cfg.TLS.Preset)
	if err != nil {
		log.Fatalf("init dialer: %v", err)
	}

	srv := proxy.New(cfg, ca, dialer)
	if cfg.MgmtListen != "" {
		go func() {
			if err := mgmt.ListenAndServe(cfg.MgmtListen, srv); err != nil {
				log.Printf("management API: %v", err)
			}
		}()
	}
	log.Fatal(srv.ListenAndServe())
}
