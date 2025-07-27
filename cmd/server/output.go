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
		"version", currentVersion,
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
		"worker_channel_buffer_size", config.Server.WorkerChannelBufferSize,
		"packet size limit", config.Server.MaxWorkers,
		"read timeout", config.Server.ReadTimeout,
		"write timeout", config.Server.WriteTimeout,
	)

	zoneLogger := logging.WithComponent("zone_loader")

	for _, zone := range config.Zones {
		recordCount := len(zone.ARecords) + len(zone.AAAARecords) +
			len(zone.CNAMERecords) + len(zone.MXRecords) + len(zone.TXTRecords)

		zoneLogger.Info("Zone loaded",
			"zone", zone.Name,
			"description", zone.Description,
			"total_records", recordCount,
			"ttl", zone.TTL)

		// Debug level for detailed info
		zoneLogger.Debug("Zone record breakdown",
			"zone", zone.Name,
			"a_records", len(zone.ARecords),
			"aaaa_records", len(zone.AAAARecords),
			"cname_records", len(zone.CNAMERecords),
			"mx_records", len(zone.MXRecords),
			"txt_records", len(zone.TXTRecords))
	}

	logging.Debug("Security Settings",
		"rate limiting", config.Security.RateLimiting,
		"refuse recursion", config.Security.ResponsePolicies.RefuseRecursion,
		"ttl minimum", config.Security.ResponsePolicies.MinimumTTL,
		"ttl maximum", config.Security.ResponsePolicies.MaximumTTL,
	)

	fmt.Printf("=====================================\n\n")

}
