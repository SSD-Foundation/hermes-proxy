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
	if cfg.Mesh.NodeID != defaultMeshNodeID {
		t.Fatalf("expected default mesh node id %s, got %s", defaultMeshNodeID, cfg.Mesh.NodeID)
	}
	if cfg.Mesh.PublicAddress != defaultMeshPublicAddress {
		t.Fatalf("expected default mesh public address %s, got %s", defaultMeshPublicAddress, cfg.Mesh.PublicAddress)
	}
	if cfg.Mesh.IdentitySecret != defaultMeshIdentitySecret {
		t.Fatalf("expected default mesh identity secret %s, got %s", defaultMeshIdentitySecret, cfg.Mesh.IdentitySecret)
	}
	if cfg.Mesh.Gossip.DialInterval != defaultMeshDialInterval {
		t.Fatalf("expected default dial interval %s, got %s", defaultMeshDialInterval, cfg.Mesh.Gossip.DialInterval)
	}
	if cfg.Mesh.Gossip.HeartbeatInterval != defaultMeshHeartbeat {
		t.Fatalf("expected default heartbeat %s, got %s", defaultMeshHeartbeat, cfg.Mesh.Gossip.HeartbeatInterval)
	}
	if cfg.Crypto.HKDFHash != defaultHKDFHash {
		t.Fatalf("expected default hkdf hash %s, got %s", defaultHKDFHash, cfg.Crypto.HKDFHash)
	}
	if cfg.Crypto.HKDFInfoLabel != defaultHKDFInfoLabel {
		t.Fatalf("expected default hkdf info label %s, got %s", defaultHKDFInfoLabel, cfg.Crypto.HKDFInfoLabel)
	}
	if cfg.Crypto.MaxKeyLifetime != defaultMaxKeyLifetime {
		t.Fatalf("expected default max key lifetime %s, got %s", defaultMaxKeyLifetime, cfg.Crypto.MaxKeyLifetime)
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
mesh:
  node_id: "node-b"
  public_address: "node-b.example:1234"
  identity_secret: "custom_secret"
  bootstrap_peers:
    - node_id: "node-a"
      address: "node-a.example:1234"
  gossip:
    dial_interval: "1s"
    heartbeat_interval: "2s"
crypto:
  hkdf_hash: "sha512"
  hkdf_info_label: "custom-info"
  max_key_lifetime: "36h"
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
	if cfg.Mesh.NodeID != "node-b" {
		t.Fatalf("expected mesh node id node-b, got %s", cfg.Mesh.NodeID)
	}
	if cfg.Mesh.PublicAddress != "node-b.example:1234" {
		t.Fatalf("expected mesh public address override, got %s", cfg.Mesh.PublicAddress)
	}
	if cfg.Mesh.IdentitySecret != "custom_secret" {
		t.Fatalf("expected mesh identity secret custom_secret, got %s", cfg.Mesh.IdentitySecret)
	}
	if len(cfg.Mesh.BootstrapPeers) != 1 || cfg.Mesh.BootstrapPeers[0].NodeID != "node-a" {
		t.Fatalf("expected bootstrap peer node-a, got %+v", cfg.Mesh.BootstrapPeers)
	}
	if cfg.Mesh.Gossip.DialInterval != time.Second {
		t.Fatalf("expected dial interval 1s, got %s", cfg.Mesh.Gossip.DialInterval)
	}
	if cfg.Mesh.Gossip.HeartbeatInterval != 2*time.Second {
		t.Fatalf("expected heartbeat interval 2s, got %s", cfg.Mesh.Gossip.HeartbeatInterval)
	}
	if cfg.Crypto.HKDFHash != "sha512" {
		t.Fatalf("expected hkdf hash sha512, got %s", cfg.Crypto.HKDFHash)
	}
	if cfg.Crypto.HKDFInfoLabel != "custom-info" {
		t.Fatalf("expected hkdf info label custom-info, got %s", cfg.Crypto.HKDFInfoLabel)
	}
	if cfg.Crypto.MaxKeyLifetime != 36*time.Hour {
		t.Fatalf("expected max key lifetime 36h, got %s", cfg.Crypto.MaxKeyLifetime)
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

func TestCryptoValidation(t *testing.T) {
	if err := validateCryptoConfig(CryptoConfig{
		HKDFHash:       "md5",
		HKDFInfoLabel:  "ok",
		MaxKeyLifetime: time.Hour,
	}); err == nil {
		t.Fatal("expected invalid hash error")
	}
	if err := validateCryptoConfig(CryptoConfig{
		HKDFHash:       "sha256",
		HKDFInfoLabel:  "",
		MaxKeyLifetime: time.Hour,
	}); err == nil {
		t.Fatal("expected info label error")
	}
	if err := validateCryptoConfig(CryptoConfig{
		HKDFHash:       "sha256",
		HKDFInfoLabel:  "ok",
		MaxKeyLifetime: 10 * time.Second,
	}); err == nil {
		t.Fatal("expected max key lifetime bounds error")
	}
	if err := validateCryptoConfig(CryptoConfig{
		HKDFHash:       "sha256",
		HKDFInfoLabel:  "ok",
		MaxKeyLifetime: time.Hour,
	}); err != nil {
		t.Fatalf("expected valid crypto config, got %v", err)
	}
}
