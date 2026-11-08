package main

import "testing"

func TestGetenvIgnoresUnexpandedPlaceholder(t *testing.T) {
	t.Setenv("IMPERSONATE_TEST_CA", "${user_config.ca_cert}")
	if got := getenv("IMPERSONATE_TEST_CA"); got != "" {
		t.Fatalf("getenv = %q, want empty for an unexpanded placeholder", got)
	}
	t.Setenv("IMPERSONATE_TEST_CA", "/etc/ca.crt")
	if got := getenv("IMPERSONATE_TEST_CA"); got != "/etc/ca.crt" {
		t.Fatalf("getenv = %q, want the real value", got)
	}
}

func TestEnvOrFallsBackOnPlaceholder(t *testing.T) {
	t.Setenv("IMPERSONATE_TEST_URL", "${user_config.mgmt_url}")
	if got := envOr("IMPERSONATE_TEST_URL", "http://127.0.0.1:8081"); got != "http://127.0.0.1:8081" {
		t.Fatalf("envOr = %q, want the default", got)
	}
}
