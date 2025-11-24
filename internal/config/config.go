package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config captures the node runtime parameters.
type Config struct {
	GRPCAddress         string         `mapstructure:"grpc_address"`
	LogLevel            string         `mapstructure:"log_level"`
	ShutdownGracePeriod time.Duration  `mapstructure:"shutdown_grace_period"`
	Keystore            KeystoreConfig `mapstructure:"keystore"`
	Mesh                MeshConfig     `mapstructure:"mesh"`
	Admin               AdminConfig    `mapstructure:"admin"`
	Cleanup             CleanupConfig  `mapstructure:"cleanup"`
	GRPCServer          GRPCServer     `mapstructure:"grpc_server"`
}

// KeystoreConfig describes how the keystore backend is initialized.
type KeystoreConfig struct {
	Path          string `mapstructure:"path"`
	PassphraseEnv string `mapstructure:"passphrase_env"`
}

// MeshConfig describes node identity, bootstrap peers, and TLS for node-to-node traffic.
type MeshConfig struct {
	NodeID         string           `mapstructure:"node_id"`
	PublicAddress  string           `mapstructure:"public_address"`
	Wallet         string           `mapstructure:"wallet"`
	IdentitySecret string           `mapstructure:"identity_secret"`
	BootstrapPeers []MeshPeer       `mapstructure:"bootstrap_peers"`
	TLS            MeshTLS          `mapstructure:"tls"`
	Gossip         MeshGossipConfig `mapstructure:"gossip"`
}

// MeshPeer seeds bootstrap dialing to other nodes.
type MeshPeer struct {
	NodeID  string `mapstructure:"node_id"`
	Address string `mapstructure:"address"`
}

// MeshTLS defines TLS materials for node↔node traffic.
type MeshTLS struct {
	Enabled            bool   `mapstructure:"enabled"`
	CertPath           string `mapstructure:"cert_path"`
	KeyPath            string `mapstructure:"key_path"`
	CAPath             string `mapstructure:"ca_path"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
}

// MeshGossipConfig tunes dial/heartbeat intervals for bootstrap + gossip streams.
type MeshGossipConfig struct {
	DialInterval      time.Duration `mapstructure:"dial_interval"`
	HeartbeatInterval time.Duration `mapstructure:"heartbeat_interval"`
}

// AdminConfig controls the HTTP endpoints for health and metrics.
type AdminConfig struct {
	Address           string        `mapstructure:"address"`
	ReadHeaderTimeout time.Duration `mapstructure:"read_header_timeout"`
}

// CleanupConfig governs sweepers for idle chats/sessions.
type CleanupConfig struct {
	SweepInterval      time.Duration `mapstructure:"sweep_interval"`
	SessionIdleTimeout time.Duration `mapstructure:"session_idle_timeout"`
	ChatIdleTimeout    time.Duration `mapstructure:"chat_idle_timeout"`
}

// GRPCServer tunes keep-alives and message limits.
type GRPCServer struct {
	MaxRecvMsgSize    int           `mapstructure:"max_recv_msg_size"`
	MaxSendMsgSize    int           `mapstructure:"max_send_msg_size"`
	KeepaliveTime     time.Duration `mapstructure:"keepalive_time"`
	KeepaliveTimeout  time.Duration `mapstructure:"keepalive_timeout"`
	MaxConnectionIdle time.Duration `mapstructure:"max_connection_idle"`
}

const (
	defaultGRPCAddress         = "0.0.0.0:50051"
	defaultLogLevel            = "info"
	defaultShutdownGracePeriod = 10 * time.Second
	defaultPassphraseEnv       = "HERMES_KEYSTORE_PASSPHRASE"
	defaultKeystorePath        = "data/keystore.json"
	defaultMeshNodeID          = "hermes-dev"
	defaultMeshPublicAddress   = "127.0.0.1:50051"
	defaultMeshIdentitySecret  = "mesh_identity"
	defaultMeshDialInterval    = 3 * time.Second
	defaultMeshHeartbeat       = 15 * time.Second
	defaultAdminAddress        = "0.0.0.0:8080"
	defaultReadHeaderTimeout   = 5 * time.Second
	defaultCleanupInterval     = time.Minute
	defaultSessionIdleTimeout  = 5 * time.Minute
	defaultChatIdleTimeout     = 15 * time.Minute
	defaultMaxRecvMsgSize      = 4 * 1024 * 1024
	defaultMaxSendMsgSize      = 4 * 1024 * 1024
	defaultKeepaliveTime       = 2 * time.Minute
	defaultKeepaliveTimeout    = 20 * time.Second
	defaultMaxConnectionIdle   = time.Duration(0)
)

// Load reads configuration from the provided file path (if any) and the environment.
// Environment variables are prefixed with HERMES_ and can override file values.
func Load(path string) (Config, error) {
	v := viper.New()
	v.SetEnvPrefix("HERMES")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	v.SetDefault("grpc_address", defaultGRPCAddress)
	v.SetDefault("log_level", defaultLogLevel)
	v.SetDefault("shutdown_grace_period", defaultShutdownGracePeriod.String())
	v.SetDefault("keystore.path", defaultKeystorePath)
	v.SetDefault("keystore.passphrase_env", defaultPassphraseEnv)
	v.SetDefault("mesh.node_id", defaultMeshNodeID)
	v.SetDefault("mesh.public_address", defaultMeshPublicAddress)
	v.SetDefault("mesh.identity_secret", defaultMeshIdentitySecret)
	v.SetDefault("mesh.gossip.dial_interval", defaultMeshDialInterval.String())
	v.SetDefault("mesh.gossip.heartbeat_interval", defaultMeshHeartbeat.String())
	v.SetDefault("admin.address", defaultAdminAddress)
	v.SetDefault("admin.read_header_timeout", defaultReadHeaderTimeout.String())
	v.SetDefault("cleanup.sweep_interval", defaultCleanupInterval.String())
	v.SetDefault("cleanup.session_idle_timeout", defaultSessionIdleTimeout.String())
	v.SetDefault("cleanup.chat_idle_timeout", defaultChatIdleTimeout.String())
	v.SetDefault("grpc_server.max_recv_msg_size", defaultMaxRecvMsgSize)
	v.SetDefault("grpc_server.max_send_msg_size", defaultMaxSendMsgSize)
	v.SetDefault("grpc_server.keepalive_time", defaultKeepaliveTime.String())
	v.SetDefault("grpc_server.keepalive_timeout", defaultKeepaliveTimeout.String())
	v.SetDefault("grpc_server.max_connection_idle", defaultMaxConnectionIdle.String())

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("read config %s: %w", path, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}

	// Viper leaves durations as strings; normalize them here.
	var err error
	if cfg.ShutdownGracePeriod, err = durationFromConfig(v, "shutdown_grace_period", defaultShutdownGracePeriod); err != nil {
		return Config{}, err
	}
	if cfg.Admin.ReadHeaderTimeout, err = durationFromConfig(v, "admin.read_header_timeout", defaultReadHeaderTimeout); err != nil {
		return Config{}, err
	}
	if cfg.Cleanup.SweepInterval, err = durationFromConfig(v, "cleanup.sweep_interval", defaultCleanupInterval); err != nil {
		return Config{}, err
	}
	if cfg.Cleanup.SessionIdleTimeout, err = durationFromConfig(v, "cleanup.session_idle_timeout", defaultSessionIdleTimeout); err != nil {
		return Config{}, err
	}
	if cfg.Cleanup.ChatIdleTimeout, err = durationFromConfig(v, "cleanup.chat_idle_timeout", defaultChatIdleTimeout); err != nil {
		return Config{}, err
	}
	if cfg.GRPCServer.KeepaliveTime, err = durationFromConfig(v, "grpc_server.keepalive_time", defaultKeepaliveTime); err != nil {
		return Config{}, err
	}
	if cfg.GRPCServer.KeepaliveTimeout, err = durationFromConfig(v, "grpc_server.keepalive_timeout", defaultKeepaliveTimeout); err != nil {
		return Config{}, err
	}
	if cfg.GRPCServer.MaxConnectionIdle, err = durationFromConfig(v, "grpc_server.max_connection_idle", defaultMaxConnectionIdle); err != nil {
		return Config{}, err
	}
	if cfg.Mesh.Gossip.DialInterval, err = durationFromConfig(v, "mesh.gossip.dial_interval", defaultMeshDialInterval); err != nil {
		return Config{}, err
	}
	if cfg.Mesh.Gossip.HeartbeatInterval, err = durationFromConfig(v, "mesh.gossip.heartbeat_interval", defaultMeshHeartbeat); err != nil {
		return Config{}, err
	}

	if cfg.GRPCAddress == "" {
		cfg.GRPCAddress = defaultGRPCAddress
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = defaultLogLevel
	}
	if cfg.Admin.Address == "" {
		cfg.Admin.Address = defaultAdminAddress
	}
	if cfg.Admin.ReadHeaderTimeout == 0 {
		cfg.Admin.ReadHeaderTimeout = defaultReadHeaderTimeout
	}
	if cfg.Cleanup.SweepInterval == 0 {
		cfg.Cleanup.SweepInterval = defaultCleanupInterval
	}
	if cfg.Cleanup.SessionIdleTimeout == 0 {
		cfg.Cleanup.SessionIdleTimeout = defaultSessionIdleTimeout
	}
	if cfg.Cleanup.ChatIdleTimeout == 0 {
		cfg.Cleanup.ChatIdleTimeout = defaultChatIdleTimeout
	}
	if cfg.GRPCServer.MaxRecvMsgSize == 0 {
		cfg.GRPCServer.MaxRecvMsgSize = defaultMaxRecvMsgSize
	}
	if cfg.GRPCServer.MaxSendMsgSize == 0 {
		cfg.GRPCServer.MaxSendMsgSize = defaultMaxSendMsgSize
	}
	if cfg.GRPCServer.KeepaliveTime == 0 {
		cfg.GRPCServer.KeepaliveTime = defaultKeepaliveTime
	}
	if cfg.GRPCServer.KeepaliveTimeout == 0 {
		cfg.GRPCServer.KeepaliveTimeout = defaultKeepaliveTimeout
	}
	if cfg.GRPCServer.MaxConnectionIdle == 0 {
		cfg.GRPCServer.MaxConnectionIdle = cfg.Cleanup.SessionIdleTimeout
	}
	if cfg.Keystore.PassphraseEnv == "" {
		cfg.Keystore.PassphraseEnv = defaultPassphraseEnv
	}
	if cfg.Keystore.Path == "" {
		cfg.Keystore.Path = defaultKeystorePath
	}
	if cfg.Mesh.NodeID == "" {
		cfg.Mesh.NodeID = defaultMeshNodeID
	}
	if cfg.Mesh.PublicAddress == "" {
		cfg.Mesh.PublicAddress = defaultMeshPublicAddress
	}
	if cfg.Mesh.IdentitySecret == "" {
		cfg.Mesh.IdentitySecret = defaultMeshIdentitySecret
	}
	if cfg.Mesh.Gossip.DialInterval == 0 {
		cfg.Mesh.Gossip.DialInterval = defaultMeshDialInterval
	}
	if cfg.Mesh.Gossip.HeartbeatInterval == 0 {
		cfg.Mesh.Gossip.HeartbeatInterval = defaultMeshHeartbeat
	}

	return cfg, nil
}

func durationFromConfig(v *viper.Viper, key string, fallback time.Duration) (time.Duration, error) {
	if v.IsSet(key) {
		dur, err := time.ParseDuration(v.GetString(key))
		if err != nil {
			return 0, fmt.Errorf("invalid %s: %w", key, err)
		}
		return dur, nil
	}
	return fallback, nil
}

// Passphrase fetches the keystore passphrase from the configured environment variable.
func (c Config) Passphrase() (string, error) {
	env := c.Keystore.PassphraseEnv
	if env == "" {
		env = defaultPassphraseEnv
	}
	val := strings.TrimSpace(getenv(env))
	if val == "" {
		return "", fmt.Errorf("keystore passphrase env %s is empty", env)
	}
	return val, nil
}

// split out for testing.
var getenv = os.Getenv
