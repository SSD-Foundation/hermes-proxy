package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hermes-proxy/hermes-proxy/internal/config"
	"github.com/hermes-proxy/hermes-proxy/internal/keystore"
	"github.com/hermes-proxy/hermes-proxy/internal/logging"
	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/internal/server"
	"go.uber.org/zap"
)

func main() {
	configPath := flag.String("config", "", "Path to YAML/JSON config file (optional)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := logging.NewLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() // best-effort flush

	passphrase, err := cfg.Passphrase()
	if err != nil {
		logger.Fatal("keystore passphrase unavailable", zap.Error(err))
	}

	fileBackend := keystore.NewFileBackend(cfg.Keystore.Path)
	fileBackend.MarkNonChatSecretIDs(cfg.Mesh.IdentitySecret)
	var keyBackend keystore.KeyBackend = fileBackend
	initOrUnlockKeystore(logger, keyBackend, passphrase)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg := registry.NewInMemory(0)
	srv := server.NewNodeServer(cfg, logger, reg, keyBackend)

	if err := srv.Start(ctx); err != nil {
		logger.Fatal("server exited with error", zap.Error(err))
	}
}

func initOrUnlockKeystore(log *zap.Logger, backend keystore.KeyBackend, passphrase string) {
	ctx := context.Background()
	if err := backend.Unlock(ctx, passphrase); err != nil {
		if errors.Is(err, keystore.ErrNotInitialized) {
			if err := backend.Initialize(ctx, passphrase); err != nil {
				log.Fatal("initialize keystore", zap.Error(err))
			}
			log.Info("initialized new keystore", zap.String("path", getBackendPath(backend)))
			return
		}
		log.Fatal("unlock keystore", zap.Error(err))
		return
	}
	log.Info("keystore unlocked")
}

// getBackendPath extracts the path if the backend is the FileBackend implementation.
func getBackendPath(backend keystore.KeyBackend) string {
	if fb, ok := backend.(*keystore.FileBackend); ok {
		return fb.Path()
	}
	return ""
}
