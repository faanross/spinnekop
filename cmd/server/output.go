package main

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/logging"
	"github.com/faanross/spinnekop/internal/models/srv_models"
	"os"
)

func printStartUpInfo(configPath string, config *srv_models.Config) {

	fmt.Println("🕷️ Spinnekop DNS Server initializing")
	fmt.Printf("=====================================\n\n")

	logging.Info("Application Loaded",
		"version", "1.0.0",
		"config_path", configPath,
		"pid", os.Getpid())

	// Log configuration summary
	logging.Debug("Configuration Loaded",
		"log_level", config.Logging.Level,
		"log_format", config.Logging.Format)

	logging.Info("DNS Server Loaded",
		"server address", fmt.Sprintf("%s:%d", config.Server.BindAddress, config.Server.Port),
		"total zones", len(config.Zones),
		"workers", config.Server.MaxWorkers,
		"packet size limit", config.Server.MaxWorkers,
		"read timeout", config.Server.ReadTimeout,
		"write timeout", config.Server.WriteTimeout,
	)

	for i, zone := range config.Zones {

		logging.Debug("Configured Zone Info",
			"#", i,
			"name", zone.Name,
			"description", zone.Description,
			"a records", len(zone.ARecords),
			"aaaa records", len(zone.AAAARecords),
			"cname records", len(zone.CNAMERecords),
			"mx records", len(zone.MXRecords),
		)
	}

	logging.Debug("Security Settings",
		"rate limiting", config.Security.RateLimiting,
		"refuse recursion", config.Security.ResponsePolicies.RefuseRecursion,
		"ttl minimum", config.Security.ResponsePolicies.MinimumTTL,
		"ttl maximum", config.Security.ResponsePolicies.MaximumTTL,
	)

	fmt.Printf("=====================================\n\n")

}
