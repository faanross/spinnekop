# Spinnekop: DNS + HTTPS Hybrid C2 Simulator

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org/) [![License](https://img.shields.io/badge/License-Educational-orange.svg)](LICENSE) [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/)

> **WARNING: EDUCATIONAL PURPOSE ONLY**
>
> This tool is designed exclusively for security research, threat hunting education, and authorized penetration testing. Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical.

## Overview

Spinnekop ("spider" in Afrikaans) is a proof-of-concept Command and Control (C2) framework that demonstrates hybrid covert communication using DNS queries for initial beaconing and command dispatch, with optional HTTPS channel escalation for data exfiltration. The project is inspired by the SUNBURST malware's sophisticated use of DNS for C2 communication, particularly its innovative abuse of the DNS header's reserved Z-flag bits for command signaling.

The project serves as an educational tool for cybersecurity professionals, threat hunters, and network defenders to understand and detect advanced DNS-based evasion techniques.

### Key Features

- **Z-Value Command Dispatch**: Abuses the reserved 3-bit Z-flag in DNS headers for covert command signaling (inspired by SUNBURST)
- **Hybrid C2 Channels**: DNS for beaconing and commands, HTTPS for bulk data exfiltration
- **Subdomain Encoding**: Base64-encoded data exfiltration via DNS subdomain queries
- **Time-Based Z-Simulation**: Server-side scheduling of Z-value sequences for realistic C2 scenarios
- **Cross-Platform Agent**: Build targets for Windows, Linux, and macOS
- **Static Configuration Embedding**: Compile-time YAML validation and embedding for OpSec
- **PCAP Analyzer**: Interactive TUI tool for analyzing DNS C2 traffic captures
- **Wildcard DNS Support**: Authoritative DNS server with wildcard record handling
- **Jittered Beaconing**: Configurable delay and jitter for evasion

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              DNS CHANNEL (Beaconing + Commands)             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    DNS Query (A record)   ┌─────────────┐  │
│  │             │ ────────────────────────► │             │  │
│  │    AGENT    │   subdomain.domain.com    │   SERVER    │  │
│  │             │                           │ (Authority) │  │
│  │  - Beacon   │ ◄──────────────────────── │             │  │
│  │  - Execute  │  DNS Response + Z-Command │ - DNS Srv   │  │
│  │  - Exfil    │                           │ - HTTP Srv  │  │
│  └─────────────┘                           │ - Z-Sched   │  │
│         │                                  └─────────────┘  │
│         │         HTTPS CHANNEL (Exfil)          ▲          │
│         │  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘          │
│         └──► POST /upload (chunked base64)                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Go 1.23 or higher
- Root/Administrator privileges for DNS server (port 53)
- libpcap-dev (Linux) for the PCAP analyzer component

### Installation

```bash
# Clone the repository
git clone https://github.com/faanross/spinnekop.git
cd spinnekop

# Install dependencies
go mod download

# Build server
go build -o bin/server ./cmd/server

# Build agent (using the build tool for config embedding)
go run ./cmd/build -target=current

# Build for all platforms
go run ./cmd/build -target=all
```

### Configuration

#### Server Configuration

Edit `configs/server.yaml`:

```yaml
server:
  bind_address: "0.0.0.0"
  port: 53
  max_workers: 4

zones:
  - name: "timeserversync.com."
    a_records:
      - name: "*.timeserversync.com."
        ip: "143.198.3.13"
        ttl: 300
```

#### Agent Configuration

Edit `configs/response.yaml` before building:

```yaml
resolver:
  use_system_defaults: false
  ip: "YOUR_C2_SERVER_IP"
  port: 53

header:
  id: 0  # Random if 0
  qr: false
  opcode: "QUERY"
  recursion_desired: true
  z: 0  # Initial Z-value

question:
  name: "www.timeserversync.com."
  type: "A"
  class: "IN"
  std_class: true
```

### Running the Demo

**Start the C2 Server:**

```bash
sudo ./bin/server
```

**Run the Agent:**

```bash
./bin/spinnekop_Agent_linux_amd64
# or on Windows
.\bin\spinnekop_Agent_windows_amd64.exe
```

**Analyze PCAP Captures:**

```bash
./bin/analyzer -pcap capture.pcap
```

## How It Works

### The Z-Value Command Protocol

Spinnekop abuses the reserved Z-flag bits (bits 9-11) in the DNS header for covert command signaling. Per RFC 1035, these 3 bits "must be zero in all queries and responses." By encoding commands in these bits, C2 traffic appears as standard DNS while carrying hidden instructions.

```
DNS Header Flags (16 bits):
┌──┬────────┬──┬──┬──┬──┬───┬────────┐
│QR│ OPCODE │AA│TC│RD│RA│ Z │ RCODE  │
│1 │   4    │1 │1 │1 │1 │ 3 │   4    │
└──┴────────┴──┴──┴──┴──┴───┴────────┘
                        ▲
                        │
              Z-Value Command (0-7)
```

### Z-Value Command Meanings

| Z-Value | Command | Description |
|---------|---------|-------------|
| 0 | CONTINUE | Standard check-in, continue beaconing |
| 1 | SLEEP | Extended sleep period (1 hour) |
| 2 | ENUMERATE | Enable subdomain encoding for data exfil |
| 3 | HTTP_MODE | Switch to HTTPS channel for bulk transfer |
| 4-7 | RESERVED | Future command expansion |

### Communication Flow

```
PHASE 1: DNS Beaconing
──────────────────────────────────────────────────
Agent                                       Server
  │                                            │
  │─── DNS Query: www.timeserversync.com ─────►│
  │                                            │
  │◄── DNS Response + Z=0 (continue) ──────────│
  │                                            │
  │    [Sleep with jitter]                     │
  │                                            │

PHASE 2: Enumeration Mode (Z=2)
──────────────────────────────────────────────────
Agent                                       Server
  │                                            │
  │─── DNS Query: www.timeserversync.com ─────►│
  │                                            │
  │◄── DNS Response + Z=2 (enumerate) ─────────│
  │                                            │
  │    [Agent enables subdomain encoding]      │
  │                                            │
  │─── DNS: ZGVza3RvcC05...timeserversync.com─►│
  │    (Base64 hostname\username)              │
  │                                            │

PHASE 3: HTTP Escalation (Z=3)
──────────────────────────────────────────────────
Agent                                       Server
  │                                            │
  │─── DNS Query: www.timeserversync.com ─────►│
  │                                            │
  │◄── DNS Response + Z=3 (HTTP mode) ─────────│
  │                                            │
  │─── HTTP GET / (verify connectivity) ──────►│
  │                                            │
  │◄── HTTP 200 OK ────────────────────────────│
  │                                            │
  │─── HTTP POST /upload?chunk=0&total=N ─────►│
  │    (Base64 encoded file chunks)            │
  │                                            │
```

### Subdomain Data Encoding

When Z=2 is received, the agent encodes reconnaissance data in DNS subdomains:

```
Standard Query:
  www.timeserversync.com

Encoded Query (hostname\user):
  ZGVza3RvcC05NGJjZ2lsXHZ1aWxob25k.timeserversync.com
  └────────────────────────────────┘
           Base64: "desktop-94bcgil\vuilhond"
```

The server decodes these subdomains to extract exfiltrated data while maintaining the appearance of legitimate DNS traffic.

## Detection Guide

### Network-Based Detection

#### DNS Z-Flag Anomalies

**Primary Indicator:** Non-zero Z-values in DNS responses are a clear protocol violation.

**Zeek Script:**

```zeek
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) {
    # Extract Z-value from flags
    local z_value = (msg$flags / 16) % 8;

    if (z_value != 0) {
        NOTICE([
            $note=DNS::Suspicious_Z_Flag,
            $msg=fmt("Non-zero DNS Z-flag detected: %d", z_value),
            $conn=c
        ]);
    }
}
```

**Suricata Rule:**

```
alert dns any any -> any any (msg:"Suspicious DNS Z-flag non-zero";
    dns.flags; content:"|00|"; offset:2; depth:1;
    byte_test:1,&,0x70,3; sid:1000001; rev:1;)
```

#### High-Entropy Subdomains

**Detection Logic:**
- Subdomains with high entropy (>4.0 bits/char)
- Base64-like character patterns
- Unusual subdomain length (>20 characters)

**Python Detection:**

```python
import math
from collections import Counter

def detect_suspicious_subdomain(fqdn):
    subdomain = fqdn.split('.')[0]

    # Length check
    if len(subdomain) > 20:
        return True, "Unusual length"

    # Entropy calculation
    entropy = -sum(
        (c/len(subdomain)) * math.log2(c/len(subdomain))
        for c in Counter(subdomain).values()
    )

    if entropy > 4.0:
        return True, f"High entropy: {entropy:.2f}"

    # Base64 pattern check
    import re
    if re.match(r'^[A-Za-z0-9+/]+=*$', subdomain) and len(subdomain) > 10:
        return True, "Base64-like pattern"

    return False, "Normal"
```

#### DNS-to-HTTPS Correlation

**Behavioral Pattern:**
1. DNS query to domain X
2. Immediate HTTPS connection to resolved IP
3. Large POST requests with chunked data

**Splunk Query:**

```spl
index=network sourcetype=dns
| join src_ip [search index=network sourcetype=proxy method=POST]
| where _time_dns < _time_http AND _time_http - _time_dns < 60
| stats count by src_ip, query, dest_ip, url
| where count > 10
```

### Host-Based Detection

#### Process Behavior

**Indicators:**
- Process making periodic DNS queries to same domain
- Sudden protocol switch from DNS to HTTPS
- Base64-encoded data in network traffic
- Outbound connections shortly after DNS resolution

**Sysmon Configuration:**

```xml
<RuleGroup name="Spinnekop Detection" groupRelation="or">
    <NetworkConnect onmatch="include">
        <!-- DNS to suspicious domains -->
        <DestinationPort condition="is">53</DestinationPort>
        <DestinationHostname condition="contains">timeserversync</DestinationHostname>
    </NetworkConnect>
    <NetworkConnect onmatch="include">
        <!-- HTTP file upload pattern -->
        <DestinationPort condition="is">8080</DestinationPort>
        <Initiated condition="is">true</Initiated>
    </NetworkConnect>
</RuleGroup>
```

### PCAP Analysis with Built-in Analyzer

Spinnekop includes an interactive TUI analyzer for examining DNS C2 traffic:

```bash
./analyzer -pcap suspicious_traffic.pcap
```

**Features:**
- Z-value extraction and highlighting
- Base64/Hex detection in TXT records
- RDATA capacity analysis
- Per-packet header inspection

## Limitations

### Technical Limitations

1. **Z-Value Range**: Only 3 bits available (values 0-7)
2. **DNS Packet Size**: Limited subdomain encoding capacity (~63 chars per label)
3. **Network Visibility**: Requires DNS egress to C2-controlled domain
4. **Protocol Compliance**: Z-flag abuse violates RFC 1035

### Detection Surface

Despite stealth techniques, Spinnekop is detectable via:
- Non-zero Z-flag values (protocol violation)
- High-entropy subdomain patterns
- Periodic DNS beaconing behavior
- DNS-to-HTTPS correlation
- Base64 patterns in DNS queries
- TXT record capacity utilization

## Project Structure

```
spinnekop/
├── cmd/
│   ├── agent/              # Agent entry point
│   │   ├── main.go         # Agent main loop
│   │   └── config.go       # Generated embedded config
│   ├── analyzer/           # PCAP analyzer TUI
│   │   ├── main.go         # Analyzer entry point
│   │   └── app.go          # TUI implementation
│   ├── build/              # Agent build tool
│   │   ├── main.go         # Config embedding & cross-compile
│   │   └── template.go     # Go code generation template
│   └── server/             # C2 server entry point
│       ├── main.go         # Server initialization
│       ├── config.go       # Config loader
│       └── output.go       # Formatted output
├── configs/
│   ├── server.yaml         # Server zone configuration
│   ├── response.yaml       # Agent config (pre-build)
│   └── request.yaml        # Request templates
├── internal/
│   ├── analyzer/           # RDATA analysis
│   ├── crafter/            # DNS packet construction
│   ├── httpclient/         # Agent HTTP client
│   ├── httphandler/        # Server HTTP handler
│   ├── logging/            # Structured logging
│   ├── models/             # Data structures
│   ├── network/            # Network utilities
│   ├── parser/             # DNS packet parsing
│   ├── pcap/               # PCAP extraction
│   ├── server/             # DNS server implementation
│   ├── subdomain/          # Subdomain generation
│   ├── validate/           # Config validation
│   ├── visualizer/         # Packet visualization
│   └── zhandler/           # Z-value handling
├── docs/
│   └── request_opts.md     # Request options documentation
├── go.mod
├── go.sum
└── README.md
```

## Legal Disclaimer

This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool. The authors assume no liability for misuse or damage caused by this program.

**By using this software, you agree to:**

- Use it only in authorized environments
- Comply with all applicable laws and regulations
- Take full responsibility for your actions
- Not use it for malicious purposes

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by the SUNBURST malware's DNS C2 techniques
- Built for the cybersecurity education community
- Thanks to the miekg/dns and gopacket projects

## References

- [DNS RFC 1035](https://tools.ietf.org/html/rfc1035)
- [SUNBURST Technical Analysis (Microsoft)](https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/)
- [MITRE ATT&CK: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK: Application Layer Protocol - DNS](https://attack.mitre.org/techniques/T1071/004/)

## Contact

For questions, issues, or security concerns, please open an issue on GitHub.
