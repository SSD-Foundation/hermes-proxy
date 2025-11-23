package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Cleanup(func() { getenv = os.Getenv })
	getenv = func(string) string { return "secret" }

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.GRPCAddress != defaultGRPCAddress {
		t.Fatalf("expected default grpc address %s, got %s", defaultGRPCAddress, cfg.GRPCAddress)
	}
	if cfg.LogLevel != defaultLogLevel {
		t.Fatalf("expected default log level %s, got %s", defaultLogLevel, cfg.LogLevel)
	}
	if cfg.ShutdownGracePeriod != defaultShutdownGracePeriod {
		t.Fatalf("expected default grace %s, got %s", defaultShutdownGracePeriod, cfg.ShutdownGracePeriod)
	}
	if cfg.Keystore.Path != defaultKeystorePath {
		t.Fatalf("expected default keystore path %s, got %s", defaultKeystorePath, cfg.Keystore.Path)
	}
}

func TestLoadWithFileAndEnvOverride(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(`
grpc_address: "127.0.0.1:7001"
log_level: "debug"
shutdown_grace_period: "5s"
keystore:
  path: "/tmp/keystore.json"
  passphrase_env: "CUSTOM_ENV"
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("HERMES_GRPC_ADDRESS", ":6000")

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.GRPCAddress != ":6000" {
		t.Fatalf("expected env override for grpc address, got %s", cfg.GRPCAddress)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("expected log level debug, got %s", cfg.LogLevel)
	}
	if cfg.ShutdownGracePeriod != 5*time.Second {
		t.Fatalf("expected grace 5s, got %s", cfg.ShutdownGracePeriod)
	}
	if cfg.Keystore.Path != "/tmp/keystore.json" {
		t.Fatalf("expected keystore path from file, got %s", cfg.Keystore.Path)
	}
	if cfg.Keystore.PassphraseEnv != "CUSTOM_ENV" {
		t.Fatalf("expected passphrase env CUSTOM_ENV, got %s", cfg.Keystore.PassphraseEnv)
	}
}

func TestPassphraseFetch(t *testing.T) {
	t.Cleanup(func() { getenv = os.Getenv })
	getenv = func(key string) string {
		if key == "CUSTOM_ENV" {
			return "hunter2"
		}
		return ""
	}

	cfg := Config{Keystore: KeystoreConfig{PassphraseEnv: "CUSTOM_ENV"}}
	pass, err := cfg.Passphrase()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pass != "hunter2" {
		t.Fatalf("expected passphrase from env, got %s", pass)
	}

	cfg.Keystore.PassphraseEnv = "MISSING_ENV"
	if _, err := cfg.Passphrase(); err == nil {
		t.Fatal("expected error when passphrase env is missing")
	}
}
