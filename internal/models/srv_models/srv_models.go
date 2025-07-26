package srv_models

// Config represents the complete DNS server configuration
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Logging LoggingConfig         `yaml:"logging"`
	Zones       []ZoneConfig      `yaml:"zones"`
	Security    SecurityConfig    `yaml:"security"`
	Monitoring  MonitoringConfig  `yaml:"monitoring"`
	Development DevelopmentConfig `yaml:"development"`
}
