package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestClientsEnv(t *testing.T) {
	t.Setenv("LIMITED_CLIENTS", " 100.100.232.87, ,100.81.231.4 ")
	cfg := NewConfig()

	want := []string{"100.100.232.87", "100.81.231.4"}
	if !reflect.DeepEqual(cfg.LimitedClients, want) {
		t.Fatalf("LimitedClients = %v, want %v", cfg.LimitedClients, want)
	}
	if !cfg.IsLimited("100.81.231.4") {
		t.Error("listed client should be limited")
	}
	if cfg.IsLimited("100.87.232.74") {
		t.Error("unlisted client must not be limited")
	}
}

func TestNoClientsEnvLimitsEveryone(t *testing.T) {
	t.Setenv("LIMITED_CLIENTS", "")
	cfg := NewConfig()

	if !cfg.IsLimited("100.87.232.74") {
		t.Error("with LIMITED_CLIENTS unset every client should be limited (upstream behaviour)")
	}
}

func TestDomainsEnvOverridesDefault(t *testing.T) {
	t.Setenv("TRACKED_DOMAINS", "*youtube*,*.ytimg.com")
	cfg := NewConfig()

	want := []string{"*youtube*", "*.ytimg.com"}
	if !reflect.DeepEqual(cfg.DomainsToCheck, want) {
		t.Fatalf("DomainsToCheck = %v, want %v", cfg.DomainsToCheck, want)
	}
}

func TestStringRedactsSecrets(t *testing.T) {
	t.Setenv("PIHOLE_PASSWORD", "pihole-pw-123")
	t.Setenv("TELEGRAM_BOT_TOKEN", "tg-token-456")
	t.Setenv("UI_PASSWORD", "ui-pw-789")
	out := fmt.Sprintf("%v", NewConfig())

	for _, secret := range []string{"pihole-pw-123", "tg-token-456", "ui-pw-789"} {
		if strings.Contains(out, secret) {
			t.Errorf("config log line leaks %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, "[redacted]") {
		t.Errorf("expected redaction marker in %s", out)
	}
}

func TestDomainsDefaultWhenUnset(t *testing.T) {
	t.Setenv("TRACKED_DOMAINS", "")
	cfg := NewConfig()

	if len(cfg.DomainsToCheck) != 7 || cfg.DomainsToCheck[0] != "*youtube*" {
		t.Fatalf("expected upstream default domains, got %v", cfg.DomainsToCheck)
	}
}
