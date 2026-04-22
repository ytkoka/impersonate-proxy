package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen string     `yaml:"listen"`
	CACert string     `yaml:"ca_cert"`
	CAKey  string     `yaml:"ca_key"`
	TLS    TLSConfig  `yaml:"tls"`
	HTTP   HTTPConfig `yaml:"http"`
	HTTP2  HTTP2Config `yaml:"http2"`
}

type TLSConfig struct {
	Preset string `yaml:"preset"`
}

type HTTPConfig struct {
	UserAgent     string            `yaml:"user_agent"`
	HeaderOrder   []string          `yaml:"header_order"`
	AddHeaders    map[string]string `yaml:"add_headers"`
	RemoveHeaders []string          `yaml:"remove_headers"`
}

type HTTP2Config struct {
	Enabled           bool        `yaml:"enabled"`
	Settings          []H2Setting `yaml:"settings"`
	WindowUpdate      uint32      `yaml:"window_update"`
	PseudoHeaderOrder []string    `yaml:"pseudo_header_order"`
}

// H2Setting is one entry in the HTTP/2 SETTINGS frame.
// ID follows RFC 7540 §11.3 (1=HEADER_TABLE_SIZE, 2=ENABLE_PUSH,
// 3=MAX_CONCURRENT_STREAMS, 4=INITIAL_WINDOW_SIZE, 5=MAX_FRAME_SIZE,
// 6=MAX_HEADER_LIST_SIZE).
type H2Setting struct {
	ID  uint16 `yaml:"id"`
	Val uint32 `yaml:"val"`
}

func Load(path string) (*Config, error) {
	cfg := defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	return cfg, yaml.Unmarshal(data, cfg)
}

func defaults() *Config {
	return &Config{
		Listen: "127.0.0.1:8080",
		CACert: "ca.crt",
		CAKey:  "ca.key",
		TLS:    TLSConfig{Preset: "chrome"},
		HTTP2: HTTP2Config{
			Enabled: true,
			// Chrome-like SETTINGS (order matters for fingerprint)
			Settings: []H2Setting{
				{ID: 1, Val: 65536},   // HEADER_TABLE_SIZE
				{ID: 2, Val: 0},       // ENABLE_PUSH
				{ID: 4, Val: 6291456}, // INITIAL_WINDOW_SIZE
				{ID: 6, Val: 262144},  // MAX_HEADER_LIST_SIZE
			},
			WindowUpdate:      15663105,
			PseudoHeaderOrder: []string{"method", "authority", "scheme", "path"},
		},
	}
}
