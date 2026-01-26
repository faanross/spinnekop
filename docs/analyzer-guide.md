# Spinnekop PCAP Analyzer Guide

This guide covers using the built-in TUI analyzer for examining DNS C2 traffic in packet captures.

## Overview

The Spinnekop analyzer is an interactive terminal application for analyzing DNS traffic in PCAP files. It's designed to help:

- Detect Z-flag anomalies in DNS responses
- Identify encoded data in TXT records
- Analyze RDATA capacity utilization
- Inspect individual packet headers

## Prerequisites

### Build Requirements

```bash
# Linux: Install libpcap development files
sudo apt-get install libpcap-dev    # Debian/Ubuntu
sudo yum install libpcap-devel      # RHEL/CentOS

# macOS: libpcap is included

# Windows: Install Npcap or WinPcap
```

### Building the Analyzer

```bash
cd spinnekop

# Build analyzer binary
go build -o bin/analyzer ./cmd/analyzer
```

## Usage

### Basic Usage

```bash
./bin/analyzer -pcap capture.pcap
```

### Capturing Traffic

Before analysis, capture DNS traffic:

```bash
# tcpdump
sudo tcpdump -i any port 53 -w dns_capture.pcap

# tshark
tshark -i any -f "port 53" -w dns_capture.pcap

# Wireshark
# File → Save As → dns_capture.pcap
```

## Interface Overview

### Packet List View

```
Source IP         Dest IP           Type     Record   Size
──────────────────────────────────────────────────────────
192.168.1.100     143.198.3.13      Query    A        45
143.198.3.13      192.168.1.100     Response A        89
192.168.1.100     143.198.3.13      Query    A        67
143.198.3.13      192.168.1.100     Response A        93

↑/↓: Navigate  Enter: View Details  q: Quit
```

| Column | Description |
|--------|-------------|
| Source IP | Packet source address |
| Dest IP | Packet destination address |
| Type | Query or Response |
| Record | DNS record type (A, TXT, etc.) |
| Size | Raw packet size in bytes |

### Navigation

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move selection up/down |
| `Enter` | View packet details |
| `q` | Quit (or return from detail view) |
| `Esc` | Quit application |

### Packet Detail View

```
╔══════════════════╗
║   DNS PACKET DETAILS   ║
╚══════════════════╝

📦PACKET INFORMATION
   Source: 143.198.3.13  → Destination: 192.168.1.100
   Type: Response | Record: A | Size: 93 bytes

🏷️DNS HEADER
├──────────────────
├ ID: 12345
├ QR: 1 (Response)
├ Opcode: 0 (QUERY)
├ AA: 0 (Authoritative Answer: No)
├ TC: 0 (Truncated: No)
├ RD: 1 (Recursion Desired: Yes)
├ RA: 1 (Recursion Available: Yes)
├ Z: 2 (Reserved - should be 0)
├ ⚠️  WARNING: Non-zero Z value detected!
├ RCODE: 0 (NOERROR)
├──────────────────
├ Questions:  1
├ Answers:    1
├ Authority:  0
├ Additional: 0
└──────────────────

❓ QUESTION SECTION
1. Name: www.timeserversync.com.
   Type: A (1)
   Class: IN (1)

✅ ANSWER SECTION (1 records)
1. www.timeserversync.com.    300    IN    A    143.198.3.13

Press 'q' to return to packet list
```

## Key Features

### 1. Z-Value Detection

The analyzer automatically highlights non-zero Z-values:

```
├ Z: 2 (Reserved - should be 0)
├ ⚠️  WARNING: Non-zero Z value detected!
```

Z-value meanings in Spinnekop:
| Value | Command | Indicator |
|-------|---------|-----------|
| 0 | CONTINUE | Normal |
| 1 | SLEEP | Suspicious |
| 2 | ENUMERATE | Suspicious |
| 3 | HTTP_MODE | Suspicious |
| 7 | TERMINATE | Suspicious |

### 2. RDATA Analysis

For responses containing TXT records, the analyzer provides:

```
🔍 RDATA ANALYSIS
├──────────────────
├ HEX DETECTED: TRUE
├ Base64 DETECTED: TRUE
├ Capacity: 87.3%
└──────────────────
```

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| HEX DETECTED | Hex-encoded data in RDATA | Any detection |
| Base64 DETECTED | Base64-encoded data in RDATA | Any detection |
| Capacity | RDATA utilization percentage | >90% |

### 3. Non-Standard Class Detection

The analyzer warns about non-IN classes:

```
   Class: NO (67)
   ⚠️  WARNING: Non-IN class detected!
```

This can indicate:
- Protocol manipulation
- Covert channel abuse
- Malformed packets

## Analysis Workflow

### Step 1: Capture Traffic

```bash
# Capture all DNS traffic
sudo tcpdump -i eth0 port 53 -w capture.pcap

# Or capture specific host
sudo tcpdump -i eth0 host 143.198.3.13 and port 53 -w capture.pcap
```

### Step 2: Load in Analyzer

```bash
./bin/analyzer -pcap capture.pcap
```

### Step 3: Review Packet List

Scan for:
- Unusual source/destination pairs
- Large packet sizes
- TXT record queries

### Step 4: Inspect Suspicious Packets

Press `Enter` on suspicious packets to view:
- Header flags (especially Z-value)
- Question/Answer sections
- RDATA analysis

### Step 5: Document Findings

Note any:
- Non-zero Z-values and their values
- High-entropy subdomains
- Encoded RDATA content
- Unusual timing patterns

## Example Analysis Session

### Loading a Capture

```bash
$ ./bin/analyzer -pcap test_capture.pcap
```

### Identifying C2 Traffic

1. **Look for Z-value anomalies**
   - Filter responses with Z != 0
   - Note the Z-value (indicates command)

2. **Check for encoded subdomains**
   - Long, random-looking subdomains
   - Base64 character patterns

3. **Examine TXT record responses**
   - Check RDATA analysis section
   - Note hex/base64 detection flags

### Sample Finding Report

```
Finding: DNS Z-Flag Command Channel
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Packets Analyzed: 150
Suspicious Packets: 12

Z-Value Distribution:
  Z=0: 138 packets (normal)
  Z=2: 8 packets (ENUMERATE command)
  Z=3: 4 packets (HTTP_MODE command)

Affected Hosts:
  192.168.1.100 → 143.198.3.13

Domain: timeserversync.com

Encoded Subdomains Detected:
  - REVTS1RPUC1BQkMxMjM.timeserversync.com
    Decoded: "DESKTOP-ABC123"

Recommendation: Block domain, isolate host
```

## Troubleshooting

### "No DNS packets found"

Causes:
- PCAP doesn't contain DNS traffic
- PCAP is encrypted (e.g., from VPN)
- Wrong capture filter

Solutions:
```bash
# Verify PCAP has DNS
tcpdump -r capture.pcap port 53 | head

# Re-capture with correct filter
sudo tcpdump -i any port 53 -w new_capture.pcap
```

### "Failed to open pcap"

Causes:
- File doesn't exist
- Permission denied
- Corrupted PCAP

Solutions:
```bash
# Check file exists
ls -la capture.pcap

# Check permissions
chmod 644 capture.pcap

# Verify PCAP integrity
capinfos capture.pcap
```

### Display Issues

If terminal doesn't render correctly:
```bash
# Ensure terminal supports termbox
export TERM=xterm-256color

# Try a different terminal emulator
```

## Integration with Other Tools

### Wireshark Pre-filtering

Before using the analyzer, filter in Wireshark:
```
dns.flags.z != 0
```

Export filtered packets:
- File → Export Specified Packets
- Select "Displayed" packets only

### Zeek Log Correlation

```bash
# Generate Zeek logs
zeek -r capture.pcap

# Find Z-flag anomalies in logs
grep -E "z_flag.*[1-7]" dns.log
```

### Splunk Import

```bash
# Convert PCAP to JSON for Splunk
tshark -r capture.pcap -T json > dns_packets.json
```

## Limitations

| Limitation | Workaround |
|------------|------------|
| No live capture | Use tcpdump first |
| Large PCAPs slow | Pre-filter with tshark |
| No export function | Manual documentation |
| Terminal-only UI | Use on SSH sessions |

## Next Steps

- [Detection Guide](detection-guide.md) - Comprehensive detection strategies
- [Z-Value Protocol](z-value-protocol.md) - Protocol specification
- [Architecture](architecture.md) - System design
