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
}

// KeystoreConfig describes how the keystore backend is initialized.
type KeystoreConfig struct {
	Path          string `mapstructure:"path"`
	PassphraseEnv string `mapstructure:"passphrase_env"`
}

const (
	defaultGRPCAddress         = "0.0.0.0:50051"
	defaultLogLevel            = "info"
	defaultShutdownGracePeriod = 10 * time.Second
	defaultPassphraseEnv       = "HERMES_KEYSTORE_PASSPHRASE"
	defaultKeystorePath        = "data/keystore.json"
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
	if v.IsSet("shutdown_grace_period") {
		dur, err := time.ParseDuration(v.GetString("shutdown_grace_period"))
		if err != nil {
			return Config{}, fmt.Errorf("invalid shutdown_grace_period: %w", err)
		}
		cfg.ShutdownGracePeriod = dur
	} else {
		cfg.ShutdownGracePeriod = defaultShutdownGracePeriod
	}

	if cfg.GRPCAddress == "" {
		cfg.GRPCAddress = defaultGRPCAddress
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = defaultLogLevel
	}
	if cfg.Keystore.PassphraseEnv == "" {
		cfg.Keystore.PassphraseEnv = defaultPassphraseEnv
	}
	if cfg.Keystore.Path == "" {
		cfg.Keystore.Path = defaultKeystorePath
	}

	return cfg, nil
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
