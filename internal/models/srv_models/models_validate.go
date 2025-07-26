package srv_models

import (
	"fmt"
	"net"
	"strings"
)

// Validate checks if the entire configuration is valid
func (c *Config) Validate() error {
	if err := c.Server.Validate(); err != nil {
		return fmt.Errorf("server configuration invalid: %w", err)
	}

	if err := c.Logging.Validate(); err != nil {
		return fmt.Errorf("logging configuration invalid: %w", err)
	}

	if len(c.Zones) == 0 {
		return fmt.Errorf("at least one zone must be configured")
	}

	for i, zone := range c.Zones {
		if err := zone.Validate(); err != nil {
			return fmt.Errorf("zone %d (%s) invalid: %w", i, zone.Name, err)
		}
	}

	if err := c.Security.Validate(); err != nil {
		return fmt.Errorf("security configuration invalid: %w", err)
	}

	return nil
}

// Validate checks if server configuration is valid
func (s *ServerConfig) Validate() error {
	// Validate bind address
	if s.BindAddress == "" {
		return fmt.Errorf("bind_address cannot be empty")
	}

	if ip := net.ParseIP(s.BindAddress); ip == nil {
		return fmt.Errorf("bind_address '%s' is not a valid IP address", s.BindAddress)
	}

	// Validate port
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("port %d is not in valid range (1-65535)", s.Port)
	}

	// Validate worker count
	if s.MaxWorkers < 1 {
		return fmt.Errorf("max_workers must be at least 1, got %d", s.MaxWorkers)
	}
	if s.MaxWorkers > 1000 {
		return fmt.Errorf("max_workers %d seems excessive, maximum recommended is 1000", s.MaxWorkers)
	}

	// Validate timeouts
	if s.ReadTimeout < 1 {
		return fmt.Errorf("read_timeout must be at least 1 second, got %d", s.ReadTimeout)
	}
	if s.WriteTimeout < 1 {
		return fmt.Errorf("write_timeout must be at least 1 second, got %d", s.WriteTimeout)
	}

	// Validate packet size
	if s.MaxPacketSize < 512 {
		return fmt.Errorf("max_packet_size must be at least 512 bytes (DNS minimum), got %d", s.MaxPacketSize)
	}
	if s.MaxPacketSize > 65535 {
		return fmt.Errorf("max_packet_size cannot exceed 65535 bytes (UDP maximum), got %d", s.MaxPacketSize)
	}

	return nil
}

// Validate checks if logging configuration is valid
func (l *LoggingConfig) Validate() error {
	// Validate log level
	validLevels := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	levelValid := false
	for _, level := range validLevels {
		if strings.ToUpper(l.Level) == level {
			levelValid = true
			break
		}
	}
	if !levelValid {
		return fmt.Errorf("invalid log level '%s', must be one of: %v", l.Level, validLevels)
	}

	// Validate log format
	validFormats := []string{"TEXT", "JSON"}
	formatValid := false
	for _, format := range validFormats {
		if strings.ToUpper(l.Format) == format {
			formatValid = true
			break
		}
	}
	if !formatValid {
		return fmt.Errorf("invalid log format '%s', must be one of: %v", l.Format, validFormats)
	}

	// Validate output (basic check - STDOUT, STDERR, or file path)
	if l.Output == "" {
		return fmt.Errorf("log output cannot be empty")
	}

	return nil
}

// Validate checks if zone configuration is valid
func (z *ZoneConfig) Validate() error {
	// Validate zone name
	if z.Name == "" {
		return fmt.Errorf("zone name cannot be empty")
	}

	// Zone names should end with a dot (FQDN)
	if !strings.HasSuffix(z.Name, ".") {
		return fmt.Errorf("zone name '%s' should be a FQDN ending with '.'", z.Name)
	}

	// Validate TTL
	if z.TTL == 0 {
		return fmt.Errorf("zone TTL cannot be zero")
	}

	// Validate SOA record
	if err := z.SOA.Validate(); err != nil {
		return fmt.Errorf("SOA record invalid: %w", err)
	}

	// At least one nameserver is required
	if len(z.Nameservers) == 0 {
		return fmt.Errorf("at least one nameserver must be configured")
	}

	// Validate individual records
	for i, record := range z.ARecords {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("A record %d invalid: %w", i, err)
		}
	}

	for i, record := range z.AAAARecords {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("AAAA record %d invalid: %w", i, err)
		}
	}

	// Continue validation for other record types...

	return nil
}

// Validate checks if SOA record is valid
func (soa *SOARecord) Validate() error {
	if soa.Primary == "" {
		return fmt.Errorf("SOA primary nameserver cannot be empty")
	}
	if soa.Admin == "" {
		return fmt.Errorf("SOA admin email cannot be empty")
	}
	if soa.Serial == 0 {
		return fmt.Errorf("SOA serial cannot be zero")
	}
	// Add more validations as needed...
	return nil
}

// Validate checks if A record is valid
func (a *ARecord) Validate() error {
	if a.Name == "" {
		return fmt.Errorf("A record name cannot be empty")
	}
	if ip := net.ParseIP(a.IP); ip == nil || ip.To4() == nil {
		return fmt.Errorf("A record IP '%s' is not a valid IPv4 address", a.IP)
	}
	if a.TTL == 0 {
		return fmt.Errorf("A record TTL cannot be zero")
	}
	return nil
}

// Validate checks if AAAA record is valid
func (aaaa *AAAARecord) Validate() error {
	if aaaa.Name == "" {
		return fmt.Errorf("AAAA record name cannot be empty")
	}
	if ip := net.ParseIP(aaaa.IP); ip == nil || ip.To4() != nil {
		return fmt.Errorf("AAAA record IP '%s' is not a valid IPv6 address", aaaa.IP)
	}
	if aaaa.TTL == 0 {
		return fmt.Errorf("AAAA record TTL cannot be zero")
	}
	return nil
}

// Validate checks if security configuration is valid
func (s *SecurityConfig) Validate() error {
	// Validate rate limiting
	if s.RateLimiting.Enabled {
		if s.RateLimiting.MaxQueriesPerSecond < 1 {
			return fmt.Errorf("max_queries_per_second must be at least 1")
		}
		if s.RateLimiting.MaxQueriesPerMinute < s.RateLimiting.MaxQueriesPerSecond {
			return fmt.Errorf("max_queries_per_minute must be >= max_queries_per_second")
		}
	}

	// Validate IP addresses in filtering rules
	for _, ip := range s.QueryFiltering.BlockedIPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("blocked IP '%s' is not a valid IP address", ip)
		}
	}

	for _, ip := range s.QueryFiltering.AllowedIPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("allowed IP '%s' is not a valid IP address", ip)
		}
	}

	return nil
}
