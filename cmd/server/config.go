package main

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/logging"
	"github.com/faanross/spinnekop/internal/models/srv_models"
	"gopkg.in/yaml.v3"
	"os"
)

// ConfigLoader handles loading and validating configuration files
type ConfigLoader struct {
	configPath string
	config     *srv_models.Config
}

// NewConfigLoader is ConfigLoader's constructor
func NewConfigLoader(configPath string) *ConfigLoader {
	return &ConfigLoader{
		configPath: configPath,
	}
}

// Load reads, validates, and parses/unmarshalls the configuration file
func (cl *ConfigLoader) Load() (*srv_models.Config, error) {

	// Step 1: Ensure that config file exists
	if _, err := os.Stat(cl.configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", cl.configPath)
	}

	// Step 2: Read the file
	yamlData, err := os.ReadFile(cl.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Step 3: Parse YAML
	var config srv_models.Config
	if err := yaml.Unmarshal(yamlData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML configuration: %w", err)
	}

	// Step 4: Apply defaults for missing values
	cl.applyDefaults(&config)

	// Step 5: Validate the configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	cl.config = &config
	return &config, nil

}

// applyDefaults sets sensible default values for any missing configuration
func (cl *ConfigLoader) applyDefaults(config *srv_models.Config) {
	// Server defaults
	if config.Server.BindAddress == "" {
		config.Server.BindAddress = "0.0.0.0"
	}
	if config.Server.Port == 0 {
		config.Server.Port = 53
	}
	if config.Server.MaxWorkers == 0 {
		config.Server.MaxWorkers = 4
	}
	if config.Server.ReadTimeout == 0 {
		config.Server.ReadTimeout = 5
	}
	if config.Server.WriteTimeout == 0 {
		config.Server.WriteTimeout = 3
	}
	if config.Server.MaxPacketSize == 0 {
		config.Server.MaxPacketSize = 512
	}

	// Logging defaults
	if config.Logging.Level == "" {
		config.Logging.Level = "INFO"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "TEXT"
	}
	if config.Logging.Output == "" {
		config.Logging.Output = "STDOUT"
	}

	// Security defaults
	if config.Security.ResponsePolicies.MinimumTTL == 0 {
		config.Security.ResponsePolicies.MinimumTTL = 60
	}
	if config.Security.ResponsePolicies.MaximumTTL == 0 {
		config.Security.ResponsePolicies.MaximumTTL = 86400
	}

	// Apply defaults to each zone
	for i := range config.Zones {
		cl.applyZoneDefaults(&config.Zones[i])
	}
}

// applyZoneDefaults sets default values for zone configuration
func (cl *ConfigLoader) applyZoneDefaults(zone *srv_models.ZoneConfig) {
	// Default TTL if not specified
	if zone.TTL == 0 {
		zone.TTL = 300
	}

	// Apply default TTLs to records that don't have them
	for i := range zone.ARecords {
		if zone.ARecords[i].TTL == 0 {
			zone.ARecords[i].TTL = zone.TTL
		}
	}

	for i := range zone.AAAARecords {
		if zone.AAAARecords[i].TTL == 0 {
			zone.AAAARecords[i].TTL = zone.TTL
		}
	}

	for i := range zone.CNAMERecords {
		if zone.CNAMERecords[i].TTL == 0 {
			zone.CNAMERecords[i].TTL = zone.TTL
		}
	}

	for i := range zone.MXRecords {
		if zone.MXRecords[i].TTL == 0 {
			zone.MXRecords[i].TTL = zone.TTL
		}
	}

	for i := range zone.TXTRecords {
		if zone.TXTRecords[i].TTL == 0 {
			zone.TXTRecords[i].TTL = zone.TTL
		}
	}
}

// ValidateZoneConsistency performs advanced validation checks
func (cl *ConfigLoader) ValidateZoneConsistency() error {
	if cl.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	for _, zone := range cl.config.Zones {
		if err := cl.validateZoneConsistency(&zone); err != nil {
			return fmt.Errorf("zone %s consistency check failed: %w", zone.Name, err)
		}
	}

	return nil
}

// validateZoneConsistency checks for logical consistency within a zone
// it enforces 3 key DNS rules: (1) Nameserver "Glue" Records, (2) CNAME Record Exclusivity, (3) Valid Mail Server Targets
func (cl *ConfigLoader) validateZoneConsistency(zone *srv_models.ZoneConfig) error {
	// Check 1: Ensure nameservers have corresponding A or AAAA "glue" records
	for _, ns := range zone.Nameservers {
		found := false

		// Check for a matching A record
		for _, aRecord := range zone.ARecords {
			if aRecord.Name == ns.Name && aRecord.IP == ns.IP {
				found = true
				break
			}
		}

		// If not found, check for a matching AAAA record
		if !found {
			for _, aaaaRecord := range zone.AAAARecords {
				if aaaaRecord.Name == ns.Name && aaaaRecord.IP == ns.IP {
					found = true
					break
				}
			}
		}

		if !found {
			return fmt.Errorf("nameserver %s (IP: %s) should have a corresponding A or AAAA record",
				ns.Name, ns.IP)
		}
	}

	// Check 2: Ensure CNAME records don't conflict with other records
	for _, cname := range zone.CNAMERecords {
		// CNAME records cannot coexist with other record types for the same name
		for _, aRecord := range zone.ARecords {
			if aRecord.Name == cname.Name {
				return fmt.Errorf("CNAME record %s conflicts with A record of same name",
					cname.Name)
			}
		}
		for _, aaaaRecord := range zone.AAAARecords {
			if aaaaRecord.Name == cname.Name {
				return fmt.Errorf("CNAME record %s conflicts with AAAA record of same name",
					cname.Name)
			}
		}
	}

	// Check 3: Ensure MX records point to valid targets
	for _, mx := range zone.MXRecords {
		// MX target should either be in this zone or be a FQDN
		if !cl.isValidMXTarget(mx.Target, zone) {
			fmt.Printf("Warning: MX record target %s may not be resolvable\n", mx.Target)
		}
	}

	return nil
}

// isValidMXTarget checks if an MX target is valid
func (cl *ConfigLoader) isValidMXTarget(target string, zone *srv_models.ZoneConfig) bool {
	// Check if target exists as an A record in this zone
	for _, aRecord := range zone.ARecords {
		if aRecord.Name == target {
			return true
		}
	}

	// Check if target exists as quad-A record in this zone
	for _, aaaaRecord := range zone.AAAARecords {
		if aaaaRecord.Name == target {
			return true
		}
	}

	// Check if target exists as a CNAME in this zone
	for _, cname := range zone.CNAMERecords {
		if cname.Name == target {
			return true
		}
	}

	// If it's a FQDN pointing outside our zone, assume it's valid
	return false
}

func performZoneConsistencyChecks(loader *ConfigLoader) {
	// perform zone consistency checks
	logging.Info("Performing Zone Consistency Checks")
	if err := loader.ValidateZoneConsistency(); err != nil {
		logging.Error("Zone consistency check failed",
			"error", err)
		os.Exit(1)
	}
	logging.Info("✅ Zone consistency checks passed")
}
