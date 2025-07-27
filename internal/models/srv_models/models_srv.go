package srv_models

// Config represents the complete DNS server configuration
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Logging     LoggingConfig     `yaml:"logging"`
	Zones       []ZoneConfig      `yaml:"zones"`
	Security    SecurityConfig    `yaml:"security"`
	Monitoring  MonitoringConfig  `yaml:"monitoring"`
	Development DevelopmentConfig `yaml:"development"`
}

// ServerConfig controls the core server behavior
type ServerConfig struct {
	BindAddress             string `yaml:"bind_address"`
	Port                    int    `yaml:"port"`
	MaxWorkers              int    `yaml:"max_workers"`
	WorkerChannelBufferSize int    `yaml:"worker_channel_buffer_size"` // worker channel buffer size
	ReadTimeout             int    `yaml:"read_timeout"`               // seconds
	WriteTimeout            int    `yaml:"write_timeout"`              // seconds
	MaxPacketSize           int    `yaml:"max_packet_size"`
}

// LoggingConfig controls how the server logs information
type LoggingConfig struct {
	Level        string `yaml:"level"`  // DEBUG, INFO, WARN, ERROR
	Format       string `yaml:"format"` // TEXT, JSON
	Output       string `yaml:"output"` // STDOUT, STDERR, or file path
	LogQueries   bool   `yaml:"log_queries"`
	LogResponses bool   `yaml:"log_responses"`
	PacketDump   bool   `yaml:"packet_dump"`
}

// ZoneConfig represents a DNS zone (domain) the server is authoritative for
type ZoneConfig struct {
	Name         string        `yaml:"name"`
	Description  string        `yaml:"description"`
	TTL          uint32        `yaml:"ttl"`
	SOA          SOARecord     `yaml:"soa"`
	Nameservers  []NSRecord    `yaml:"nameservers"`
	ARecords     []ARecord     `yaml:"a_records"`
	AAAARecords  []AAAARecord  `yaml:"aaaa_records"`
	CNAMERecords []CNAMERecord `yaml:"cname_records"`
	MXRecords    []MXRecord    `yaml:"mx_records"`
	TXTRecords   []TXTRecord   `yaml:"txt_records"`
}

// SOARecord represents a Start of Authority record
type SOARecord struct {
	Primary string `yaml:"primary"` // Primary nameserver
	Admin   string `yaml:"admin"`   // Admin email (with . instead of @)
	Serial  uint32 `yaml:"serial"`  // Zone serial number
	Refresh uint32 `yaml:"refresh"` // Refresh interval
	Retry   uint32 `yaml:"retry"`   // Retry interval
	Expire  uint32 `yaml:"expire"`  // Expire time
	Minimum uint32 `yaml:"minimum"` // Minimum TTL
}

// NSRecord represents a Name Server record
type NSRecord struct {
	Name string `yaml:"name"`
	IP   string `yaml:"ip"`
}

// ARecord represents an A (IPv4 address) record
type ARecord struct {
	Name string `yaml:"name"`
	IP   string `yaml:"ip"`
	TTL  uint32 `yaml:"ttl"`
}

// AAAARecord represents an AAAA (IPv6 address) record
type AAAARecord struct {
	Name string `yaml:"name"`
	IP   string `yaml:"ip"`
	TTL  uint32 `yaml:"ttl"`
}

// CNAMERecord represents a CNAME (canonical name) record
type CNAMERecord struct {
	Name   string `yaml:"name"`
	Target string `yaml:"target"`
	TTL    uint32 `yaml:"ttl"`
}

// MXRecord represents a Mail Exchange record
type MXRecord struct {
	Name     string `yaml:"name"`
	Priority uint16 `yaml:"priority"`
	Target   string `yaml:"target"`
	TTL      uint32 `yaml:"ttl"`
}

// TXTRecord represents a Text record
type TXTRecord struct {
	Name string `yaml:"name"`
	Text string `yaml:"text"`
	TTL  uint32 `yaml:"ttl"`
}

// SecurityConfig controls security-related features
type SecurityConfig struct {
	RateLimiting     RateLimitingConfig     `yaml:"rate_limiting"`
	QueryFiltering   QueryFilteringConfig   `yaml:"query_filtering"`
	ResponsePolicies ResponsePoliciesConfig `yaml:"response_policies"`
}

// RateLimitingConfig controls query rate limiting
type RateLimitingConfig struct {
	Enabled             bool `yaml:"enabled"`
	MaxQueriesPerSecond int  `yaml:"max_queries_per_second"`
	MaxQueriesPerMinute int  `yaml:"max_queries_per_minute"`
	BlacklistDuration   int  `yaml:"blacklist_duration"` // seconds
}

// QueryFilteringConfig controls which queries to allow/block
type QueryFilteringConfig struct {
	AllowedTypes []string `yaml:"allowed_types"`
	BlockedIPs   []string `yaml:"blocked_ips"`
	AllowedIPs   []string `yaml:"allowed_ips"`
}

// ResponsePoliciesConfig controls how to handle edge cases
type ResponsePoliciesConfig struct {
	RefuseRecursion bool   `yaml:"refuse_recursion"`
	CaseSensitive   bool   `yaml:"case_sensitive"`
	MinimumTTL      uint32 `yaml:"minimum_ttl"`
	MaximumTTL      uint32 `yaml:"maximum_ttl"`
}

// MonitoringConfig controls monitoring and metrics
type MonitoringConfig struct {
	Metrics     MetricsConfig     `yaml:"metrics"`
	HealthCheck HealthCheckConfig `yaml:"health_check"`
	Statistics  StatisticsConfig  `yaml:"statistics"`
}

// MetricsConfig controls metrics endpoint
type MetricsConfig struct {
	Enabled     bool   `yaml:"enabled"`
	BindAddress string `yaml:"bind_address"`
	Port        int    `yaml:"port"`
	Path        string `yaml:"path"`
}

// HealthCheckConfig controls health check endpoint
type HealthCheckConfig struct {
	Enabled     bool   `yaml:"enabled"`
	BindAddress string `yaml:"bind_address"`
	Port        int    `yaml:"port"`
	Path        string `yaml:"path"`
}

// StatisticsConfig controls query statistics tracking
type StatisticsConfig struct {
	Enabled       bool `yaml:"enabled"`
	ResetInterval int  `yaml:"reset_interval"` // seconds
}

// DevelopmentConfig controls development and testing features
type DevelopmentConfig struct {
	EnableDebugEndpoints bool                   `yaml:"enable_debug_endpoints"`
	SimulateFailures     SimulateFailuresConfig `yaml:"simulate_failures"`
	PacketCapture        PacketCaptureConfig    `yaml:"packet_capture"`
}

// SimulateFailuresConfig controls failure simulation for testing
type SimulateFailuresConfig struct {
	Enabled     bool    `yaml:"enabled"`
	FailureRate float64 `yaml:"failure_rate"` // 0.0 to 1.0
}

// PacketCaptureConfig controls packet capture for debugging
type PacketCaptureConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Directory string `yaml:"directory"`
	MaxFiles  int    `yaml:"max_files"`
}
