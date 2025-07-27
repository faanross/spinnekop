package main

import (
	"github.com/faanross/spinnekop/internal/logging"
	"github.com/faanross/spinnekop/internal/models/srv_models"
	"os"
)

func printStartUpInfo(configPath string, config *srv_models.Config) {
	logging.Info("🕷️ Spinnekop DNS Server initializing",
		"version", "1.0.0",
		"config_path", configPath,
		"pid", os.Getpid())

	// Log configuration summary
	logging.Debug("Configuration loaded",
		"zones", len(config.Zones),
		"workers", config.Server.MaxWorkers,
		"log_level", config.Logging.Level,
		"log_format", config.Logging.Format)
}
