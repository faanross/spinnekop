# Spinnekop Configuration Reference

Complete reference for all configuration options in Spinnekop.

## Configuration Files

| File | Purpose | Used By |
|------|---------|---------|
| `configs/server.yaml` | Server settings, zones, security | Server |
| `configs/response.yaml` | Agent configuration (embedded at build) | Agent |
| `configs/request.yaml` | Request templates (testing) | Development |

## Server Configuration

### Server Settings

```yaml
server:
  bind_address: "0.0.0.0"
  port: 53
  max_workers: 4
  worker_channel_buffer_size: 10
  read_timeout: 5
  write_timeout: 5
  max_packet_size: 512
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `bind_address` | string | `"0.0.0.0"` | IP address to bind to |
| `port` | int | `53` | UDP port for DNS server |
| `max_workers` | int | `4` | Concurrent query handler goroutines |
| `worker_channel_buffer_size` | int | `10` | Buffer size per worker channel |
| `read_timeout` | int | `5` | Seconds to wait for incoming packets |
| `write_timeout` | int | `5` | Seconds to wait when sending responses |
| `max_packet_size` | int | `512` | Maximum UDP packet size to accept |

### Logging Configuration

```yaml
logging:
  level: "DEBUG"
  format: "TEXT"
  output: "STDOUT"
  log_queries: true
  log_responses: true
  packet_dump: false
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `level` | string | `"DEBUG"` | Log verbosity: `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `format` | string | `"TEXT"` | Output format: `TEXT` or `JSON` |
| `output` | string | `"STDOUT"` | Output destination: `STDOUT`, `STDERR`, or file path |
| `log_queries` | bool | `true` | Log every DNS query received |
| `log_responses` | bool | `true` | Log every DNS response sent |
| `packet_dump` | bool | `false` | Include hex dumps (very verbose) |

### Zone Configuration

```yaml
zones:
  - name: "timeserversync.com."
    description: "Primary zone"
    ttl: 300

    soa:
      primary: "ns1.timeserversync.com."
      admin: "admin.timeserversync.com."
      serial: 2024012001
      refresh: 3600
      retry: 1800
      expire: 604800
      minimum: 86400

    nameservers:
      - name: "ns1.timeserversync.com."
        ip: "143.198.3.13"

    a_records:
      - name: "*.timeserversync.com."
        ip: "143.198.3.13"
        ttl: 300

    aaaa_records:
      - name: "timeserversync.com."
        ip: "2001:db8::42"
        ttl: 300

    cname_records:
      - name: "mail.timeserversync.com."
        target: "timeserversync.com."
        ttl: 300

    mx_records:
      - name: "timeserversync.com."
        priority: 10
        target: "mail.timeserversync.com."
        ttl: 300

    txt_records:
      - name: "timeserversync.com."
        text: "v=spf1 include:_spf.google.com ~all"
        ttl: 300
```

#### Zone Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `name` | string | Yes | Zone name (with trailing dot) |
| `description` | string | No | Human-readable description |
| `ttl` | int | No | Default TTL for records |

#### SOA Record Options

| Option | Type | Description |
|--------|------|-------------|
| `primary` | string | Primary nameserver FQDN |
| `admin` | string | Admin email (@ → .) |
| `serial` | int | Zone version (YYYYMMDDNN) |
| `refresh` | int | Secondary refresh interval (seconds) |
| `retry` | int | Retry interval after failed transfer |
| `expire` | int | How long secondaries keep data |
| `minimum` | int | Minimum TTL for negative caching |

#### Record Types

**A Records:**
```yaml
a_records:
  - name: "www.example.com."
    ip: "1.2.3.4"
    ttl: 300
```

**AAAA Records:**
```yaml
aaaa_records:
  - name: "www.example.com."
    ip: "2001:db8::1"
    ttl: 300
```

**CNAME Records:**
```yaml
cname_records:
  - name: "alias.example.com."
    target: "www.example.com."
    ttl: 300
```

**MX Records:**
```yaml
mx_records:
  - name: "example.com."
    priority: 10
    target: "mail.example.com."
    ttl: 300
```

**TXT Records:**
```yaml
txt_records:
  - name: "example.com."
    text: "Some text value"
    ttl: 300
```

### Security Settings

```yaml
security:
  rate_limiting:
    enabled: true
    max_queries_per_second: 10
    max_queries_per_minute: 100
    blacklist_duration: 3000

  query_filtering:
    allowed_types: ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
    blocked_ips: []
    allowed_ips: []

  response_policies:
    refuse_recursion: true
    case_sensitive: false
    minimum_ttl: 60
    maximum_ttl: 86400
```

#### Rate Limiting

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable rate limiting |
| `max_queries_per_second` | int | `10` | Max queries/second per IP |
| `max_queries_per_minute` | int | `100` | Max queries/minute per IP |
| `blacklist_duration` | int | `3000` | Blacklist duration (ms) |

#### Query Filtering

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allowed_types` | []string | All common | Query types to respond to |
| `blocked_ips` | []string | `[]` | IPs to never respond to |
| `allowed_ips` | []string | `[]` | If set, only respond to these |

#### Response Policies

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `refuse_recursion` | bool | `true` | Refuse recursive queries |
| `case_sensitive` | bool | `false` | Case-sensitive domain matching |
| `minimum_ttl` | int | `60` | Minimum TTL to return |
| `maximum_ttl` | int | `86400` | Maximum TTL to return |

### Monitoring Configuration

```yaml
monitoring:
  metrics:
    enabled: true
    bind_address: "127.0.0.1"
    port: 8080
    path: "/metrics"

  health_check:
    enabled: true
    bind_address: "127.0.0.1"
    port: 8081
    path: "/health"

  statistics:
    enabled: true
    reset_interval: 3600
```

| Section | Option | Description |
|---------|--------|-------------|
| `metrics` | `enabled` | Enable Prometheus metrics |
| `metrics` | `bind_address` | Metrics server bind address |
| `metrics` | `port` | Metrics server port |
| `metrics` | `path` | Metrics endpoint path |
| `health_check` | `enabled` | Enable health endpoint |
| `health_check` | `port` | Health check port |
| `statistics` | `reset_interval` | Stats reset interval (seconds) |

### Development Settings

```yaml
development:
  enable_debug_endpoints: false

  simulate_failures:
    enabled: false
    failure_rate: 0.01

  packet_capture:
    enabled: false
    directory: "./packet_captures"
    max_files: 1000
```

| Option | Type | Description |
|--------|------|-------------|
| `enable_debug_endpoints` | bool | Expose debug endpoints (NEVER in production) |
| `simulate_failures.enabled` | bool | Randomly fail requests for testing |
| `simulate_failures.failure_rate` | float | Percentage of requests to fail |
| `packet_capture.enabled` | bool | Save packets to files |
| `packet_capture.directory` | string | Directory for packet files |
| `packet_capture.max_files` | int | Maximum capture files to keep |

## Agent Configuration

### Resolver Settings

```yaml
resolver:
  use_system_defaults: false
  ip: "143.198.3.13"
  port: 53
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `use_system_defaults` | bool | `false` | Use OS DNS resolver |
| `ip` | string | Required | C2 server IP address |
| `port` | int | `53` | DNS port |

**Note:** Set `use_system_defaults: false` and specify your C2 server IP to ensure queries go directly to your server.

### Header Settings

```yaml
header:
  id: 0
  qr: false
  opcode: "QUERY"
  authoritative: false
  truncated: false
  recursion_desired: true
  recursion_available: false
  z: 0
  rcode: 0
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | int | `0` | Transaction ID (0 = random) |
| `qr` | bool | `false` | Query/Response flag |
| `opcode` | string | `"QUERY"` | Operation type |
| `authoritative` | bool | `false` | Authoritative answer flag |
| `truncated` | bool | `false` | Truncation flag |
| `recursion_desired` | bool | `true` | Request recursion |
| `recursion_available` | bool | `false` | Recursion available (server sets) |
| `z` | int | `0` | Reserved bits (0-7) |
| `rcode` | int | `0` | Response code |

#### Opcode Values

| Value | Name | Description |
|-------|------|-------------|
| `"QUERY"` | Standard Query | Normal DNS lookup |
| `"IQUERY"` | Inverse Query | Deprecated |
| `"STATUS"` | Status Request | Server status |

### Question Settings

```yaml
question:
  name: "www.timeserversync.com."
  type: "A"
  class: "IN"
  std_class: true
  custom_class: 0
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | string | Required | Domain to query (with trailing dot) |
| `type` | string | `"A"` | Record type |
| `class` | string | `"IN"` | Query class |
| `std_class` | bool | `true` | Use standard class |
| `custom_class` | int | `0` | Custom class value (if std_class=false) |

#### Supported Record Types

| Type | Description |
|------|-------------|
| `"A"` | IPv4 address |
| `"AAAA"` | IPv6 address |
| `"CNAME"` | Canonical name |
| `"MX"` | Mail exchange |
| `"TXT"` | Text record |
| `"NS"` | Name server |
| `"SOA"` | Start of authority |
| `"PTR"` | Pointer record |

#### Class Values

| Class | Value | Description |
|-------|-------|-------------|
| `"IN"` | 1 | Internet (standard) |
| `"CS"` | 2 | CSNET (obsolete) |
| `"CH"` | 3 | CHAOS |
| `"HS"` | 4 | Hesiod |
| Custom | 0-65535 | Via `custom_class` |

## Agent Runtime Settings

These are compile-time constants in `cmd/agent/main.go`:

```go
var Delay = 5   // Base beacon interval (seconds)
var Jitter = 50 // Jitter percentage (0-100)
```

| Setting | Default | Description |
|---------|---------|-------------|
| `Delay` | `5` | Base interval between beacons (seconds) |
| `Jitter` | `50` | Random variance (±50% = 2.5-7.5s range) |

### Calculated Intervals

With default settings:
- Minimum sleep: `5 - (5 * 0.5) = 2.5 seconds`
- Maximum sleep: `5 + (5 * 0.5) = 7.5 seconds`
- Average: ~5 seconds

### Extended Sleep (Z=1)

When Z=1 is received:
- Duration: 1 hour (hardcoded in `zhandler`)
- Configurable in `internal/zhandler/handler.go`

## Build Configuration

Build tool paths in `cmd/build/main.go`:

```go
const (
    yamlConfigSourcePath   = "./configs/response.yaml"
    embeddedGoConfigTarget = "./cmd/agent/config.go"
    agentMainPackagePath   = "./cmd/agent"
    defaultOutputDir       = "./bin"
    defaultBinaryNameBase  = "spinnekop_Agent"
)
```

| Constant | Description |
|----------|-------------|
| `yamlConfigSourcePath` | Agent YAML config location |
| `embeddedGoConfigTarget` | Generated Go config output |
| `agentMainPackagePath` | Agent package for compilation |
| `defaultOutputDir` | Binary output directory |
| `defaultBinaryNameBase` | Binary naming prefix |

### Build Targets

```bash
go run ./cmd/build -target=<target>
```

| Target | OS | Architecture |
|--------|-----|-------------|
| `current` | Host OS | Host arch |
| `windows-amd64` | Windows | x64 |
| `linux-amd64` | Linux | x64 |
| `darwin-amd64` | macOS | Intel |
| `darwin-arm64` | macOS | Apple Silicon |
| `all` | All above | All above |

## Environment Variables

The server respects standard Go environment variables:

| Variable | Description |
|----------|-------------|
| `GOOS` | Target operating system |
| `GOARCH` | Target architecture |
| `CGO_ENABLED` | Enable/disable CGO |

## Configuration Validation

The build tool validates agent configuration at compile time:

### Validated Fields

| Field | Validation |
|-------|------------|
| `resolver.ip` | Valid IP address format |
| `resolver.port` | 1-65535 |
| `header.id` | 0-65535 |
| `header.z` | 0-7 |
| `header.rcode` | 0-15 |
| `question.name` | Valid FQDN |
| `question.type` | Known record type |

### Validation Errors

```bash
Build Error: Configuration is invalid:
  - resolver.ip: invalid IP address format
  - header.z: must be between 0 and 7
```

## Example Configurations

### Minimal Server Config

```yaml
server:
  bind_address: "0.0.0.0"
  port: 53

zones:
  - name: "c2domain.com."
    a_records:
      - name: "*.c2domain.com."
        ip: "YOUR_SERVER_IP"
        ttl: 300
```

### Minimal Agent Config

```yaml
resolver:
  use_system_defaults: false
  ip: "YOUR_SERVER_IP"
  port: 53

header:
  id: 0
  qr: false
  opcode: "QUERY"
  recursion_desired: true
  z: 0

question:
  name: "www.c2domain.com."
  type: "A"
  class: "IN"
  std_class: true
```

### High-Security Server Config

```yaml
server:
  bind_address: "0.0.0.0"
  port: 53
  max_workers: 2

logging:
  level: "WARN"
  log_queries: false
  log_responses: false

security:
  rate_limiting:
    enabled: true
    max_queries_per_second: 5
    blacklist_duration: 60000

  query_filtering:
    allowed_types: ["A", "TXT"]
    allowed_ips: ["192.168.1.0/24"]

  response_policies:
    refuse_recursion: true
    minimum_ttl: 300
```

## Next Steps

- [Server Guide](server-guide.md) - Server setup and operation
- [Agent Guide](agent-guide.md) - Agent deployment
- [Architecture](architecture.md) - System design
