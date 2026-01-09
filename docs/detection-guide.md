# Spinnekop Detection Guide

This guide covers detection strategies for Spinnekop C2 traffic, intended for blue teams, threat hunters, and security researchers.

## Detection Overview

Spinnekop generates detectable artifacts across multiple layers:

| Layer | Indicator | Detection Difficulty |
|-------|-----------|---------------------|
| DNS Protocol | Non-zero Z-flag | Easy (clear RFC violation) |
| DNS Behavior | High-entropy subdomains | Medium |
| DNS Timing | Periodic beaconing | Medium |
| Network | DNS→HTTPS correlation | Medium |
| Host | Process behavior | Easy-Medium |

## Network-Based Detection

### 1. Z-Flag Anomaly Detection

**The Primary Indicator**

RFC 1035 states the Z bits "must be zero in all queries and responses." Any non-zero Z-value is a clear protocol violation.

#### Zeek Script

```zeek
# z_flag_detection.zeek
module DNS_ZFlag;

export {
    redef enum Notice::Type += {
        Suspicious_Z_Flag
    };
}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) {
    # Extract Z-value from flags (bits 9-11)
    local flags = msg$flags;
    local z_value = (flags / 16) % 8;

    if (z_value != 0) {
        NOTICE([
            $note=Suspicious_Z_Flag,
            $msg=fmt("Non-zero DNS Z-flag detected: Z=%d", z_value),
            $conn=c,
            $identifier=cat(c$id$orig_h, c$id$resp_h, z_value)
        ]);
    }
}
```

#### Suricata Rule

```
# Detect non-zero Z bits in DNS responses
alert dns any any -> any any (
    msg:"SPINNEKOP - Non-zero DNS Z-flag in response";
    flow:from_server;
    byte_test:1,&,0x70,3;  # Check if any Z bits set
    classtype:trojan-activity;
    sid:1000001;
    rev:1;
)
```

#### Wireshark Filter

```
# Simple filter for Z-flag anomalies
dns.flags.z != 0

# Combined with response filter
dns.flags.response == 1 && dns.flags.z != 0
```

#### tcpdump + Python

```python
#!/usr/bin/env python3
"""Detect non-zero Z-flag in DNS traffic."""

from scapy.all import sniff, DNS, IP, UDP

def check_z_flag(pkt):
    if pkt.haslayer(DNS):
        # Get raw DNS layer bytes
        dns_layer = bytes(pkt[DNS])
        if len(dns_layer) >= 4:
            # Flags are bytes 2-3 of DNS payload
            flags = (dns_layer[2] << 8) | dns_layer[3]
            z_value = (flags >> 4) & 0x7

            if z_value != 0:
                print(f"[ALERT] Z-flag anomaly detected!")
                print(f"  Source: {pkt[IP].src}:{pkt[UDP].sport}")
                print(f"  Dest:   {pkt[IP].dst}:{pkt[UDP].dport}")
                print(f"  Z-Value: {z_value}")
                print(f"  Command: {interpret_z_value(z_value)}")
                print()

def interpret_z_value(z):
    commands = {
        0: "CONTINUE",
        1: "SLEEP",
        2: "ENUMERATE",
        3: "HTTP_MODE",
        7: "TERMINATE"
    }
    return commands.get(z, f"RESERVED ({z})")

if __name__ == "__main__":
    print("Monitoring DNS traffic for Z-flag anomalies...")
    sniff(filter="udp port 53", prn=check_z_flag, store=0)
```

### 2. High-Entropy Subdomain Detection

When Spinnekop encodes data in subdomains, the entropy is abnormally high.

#### Python Entropy Calculator

```python
#!/usr/bin/env python3
"""Detect high-entropy DNS subdomains."""

import math
from collections import Counter

def calculate_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0

    freq = Counter(s)
    length = len(s)

    entropy = 0
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

def analyze_subdomain(fqdn, threshold=3.5):
    """Analyze a DNS query for suspicious subdomain."""
    parts = fqdn.rstrip('.').split('.')

    if len(parts) < 2:
        return False, "Too few labels"

    subdomain = parts[0]

    # Check length
    if len(subdomain) > 30:
        return True, f"Unusual length: {len(subdomain)} chars"

    # Check entropy
    entropy = calculate_entropy(subdomain)
    if entropy > threshold:
        return True, f"High entropy: {entropy:.2f} bits/char"

    # Check for Base64 patterns
    import re
    if re.match(r'^[A-Za-z0-9+/]+=*$', subdomain) and len(subdomain) > 15:
        return True, "Base64-like pattern"

    return False, "Normal"

# Example usage
test_queries = [
    "www.example.com",                                    # Normal
    "REVTS1RPUC1BQkMxMjM.timeserversync.com",            # Base64 encoded
    "api.timeserversync.com",                             # Normal
    "a8f3b2c1d4e5f6g7h8i9.timeserversync.com",           # High entropy
]

for query in test_queries:
    suspicious, reason = analyze_subdomain(query)
    status = "SUSPICIOUS" if suspicious else "OK"
    print(f"[{status}] {query}")
    print(f"         Reason: {reason}")
    print()
```

#### Zeek Script for Entropy

```zeek
# subdomain_entropy.zeek
module DNS_Entropy;

export {
    redef enum Notice::Type += {
        High_Entropy_Subdomain
    };

    # Entropy threshold (bits per character)
    const entropy_threshold = 3.5 &redef;
}

function calculate_entropy(s: string): double {
    local freq: table[string] of count;
    local length = |s|;

    if (length == 0)
        return 0.0;

    for (i in s) {
        local c = s[i];
        if (c !in freq)
            freq[c] = 0;
        freq[c] += 1;
    }

    local entropy = 0.0;
    for (c in freq) {
        local p = freq[c] * 1.0 / length;
        entropy -= p * log2(p);
    }

    return entropy;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    local parts = split_string(query, /\./);
    if (|parts| < 2)
        return;

    local subdomain = parts[0];

    # Skip short subdomains
    if (|subdomain| < 10)
        return;

    local entropy = calculate_entropy(subdomain);

    if (entropy > entropy_threshold) {
        NOTICE([
            $note=High_Entropy_Subdomain,
            $msg=fmt("High-entropy subdomain: %s (entropy=%.2f)", subdomain, entropy),
            $conn=c,
            $identifier=cat(c$id$orig_h, subdomain)
        ]);
    }
}
```

### 3. Beacon Detection (Time-Series Analysis)

Spinnekop's jittered beaconing creates detectable patterns.

#### Splunk Query

```spl
index=dns sourcetype=dns
| stats count as query_count,
        avg(duration) as avg_interval,
        stdev(duration) as interval_stdev
  by src_ip, query
| where query_count > 10
| eval coefficient_of_variation = interval_stdev / avg_interval
| where coefficient_of_variation < 0.5
| where avg_interval > 2 AND avg_interval < 60
| sort - query_count
| table src_ip, query, query_count, avg_interval, coefficient_of_variation
```

#### Python Beacon Detector

```python
#!/usr/bin/env python3
"""Detect DNS beaconing patterns."""

import statistics
from collections import defaultdict
from datetime import datetime

class BeaconDetector:
    def __init__(self, min_samples=10, cv_threshold=0.5):
        self.queries = defaultdict(list)  # {(src_ip, domain): [timestamps]}
        self.min_samples = min_samples
        self.cv_threshold = cv_threshold

    def add_query(self, src_ip, domain, timestamp):
        """Add a DNS query observation."""
        key = (src_ip, domain)
        self.queries[key].append(timestamp)

    def analyze(self):
        """Analyze all queries for beaconing patterns."""
        suspicious = []

        for (src_ip, domain), timestamps in self.queries.items():
            if len(timestamps) < self.min_samples:
                continue

            # Calculate intervals between queries
            timestamps = sorted(timestamps)
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(interval)

            if not intervals:
                continue

            # Calculate statistics
            mean_interval = statistics.mean(intervals)
            if mean_interval == 0:
                continue

            stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
            cv = stdev_interval / mean_interval  # Coefficient of variation

            # Low CV indicates regular beaconing
            if cv < self.cv_threshold:
                suspicious.append({
                    'src_ip': src_ip,
                    'domain': domain,
                    'query_count': len(timestamps),
                    'mean_interval': mean_interval,
                    'cv': cv
                })

        return suspicious

# Example usage
detector = BeaconDetector()

# Simulate beacon traffic
import random
base_time = datetime.now()
for i in range(50):
    # Jittered interval: 5s ± 50%
    jitter = random.uniform(-2.5, 2.5)
    interval = 5 + jitter
    timestamp = base_time.replace(second=int((i * interval) % 60))
    detector.add_query("192.168.1.100", "www.timeserversync.com", timestamp)

results = detector.analyze()
for r in results:
    print(f"[BEACON] {r['src_ip']} -> {r['domain']}")
    print(f"         Queries: {r['query_count']}, Interval: {r['mean_interval']:.2f}s, CV: {r['cv']:.2f}")
```

### 4. DNS→HTTPS Correlation

Spinnekop's HTTP mode creates a detectable protocol transition.

#### Splunk Correlation Query

```spl
# Find DNS queries followed by HTTP to resolved IP
index=dns sourcetype=dns query="*timeserversync.com*"
| rename src_ip as dns_client, answer as resolved_ip
| join dns_client [
    search index=proxy sourcetype=proxy_logs method=POST
    | rename src_ip as dns_client, dest_ip as http_dest
]
| where resolved_ip = http_dest
| eval time_delta = _time_http - _time_dns
| where time_delta > 0 AND time_delta < 300
| stats count by dns_client, query, http_dest, uri
| where count > 5
```

#### Zeek Correlation Script

```zeek
# dns_http_correlation.zeek
module DNS_HTTP_Correlation;

export {
    redef enum Notice::Type += {
        DNS_HTTP_Correlation
    };
}

global dns_resolutions: table[addr] of set[addr] &create_expire=5min;

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) {
    local client = c$id$orig_h;
    if (client !in dns_resolutions)
        dns_resolutions[client] = set();
    add dns_resolutions[client][a];
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    local client = c$id$orig_h;
    local server = c$id$resp_h;

    if (client in dns_resolutions && server in dns_resolutions[client]) {
        if (method == "POST" && /upload/ in original_URI) {
            NOTICE([
                $note=DNS_HTTP_Correlation,
                $msg=fmt("DNS resolution followed by HTTP POST to %s%s",
                        server, original_URI),
                $conn=c
            ]);
        }
    }
}
```

## Host-Based Detection

### Process Monitoring

#### Sysmon Configuration

```xml
<Sysmon schemaversion="4.50">
    <EventFiltering>
        <!-- Network connections -->
        <NetworkConnect onmatch="include">
            <!-- DNS to suspicious domains -->
            <DestinationPort condition="is">53</DestinationPort>
        </NetworkConnect>

        <!-- Process creation -->
        <ProcessCreate onmatch="include">
            <Image condition="contains">spinnekop</Image>
        </ProcessCreate>

        <!-- DNS query logging (Windows 8.1+) -->
        <DnsQuery onmatch="include">
            <QueryName condition="contains">timeserversync</QueryName>
        </DnsQuery>
    </EventFiltering>
</Sysmon>
```

#### Windows Event Log Query

```powershell
# Find DNS queries to suspicious domains
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-DNS-Client/Operational'
    Id = 3008
} | Where-Object {
    $_.Message -match 'timeserversync'
} | Select-Object TimeCreated, Message
```

#### Linux Process Monitoring

```bash
# Monitor DNS connections from a specific process
strace -f -e trace=network -p $(pgrep -f spinnekop) 2>&1 | grep -E "connect|sendto"

# Check active DNS connections
ss -tunp | grep ':53'

# Monitor with auditd
auditctl -a exit,always -F arch=b64 -S connect -F a0=2 -k dns_connections
```

### Memory Analysis

#### Volatility3 Commands

```bash
# List processes
python3 vol.py -f memory.dmp windows.pslist

# Check network connections
python3 vol.py -f memory.dmp windows.netscan

# Search for domain strings
python3 vol.py -f memory.dmp windows.strings --pattern "timeserversync"

# Dump suspicious process
python3 vol.py -f memory.dmp windows.memmap --pid 1234 --dump
```

## SIEM Integration

### Sigma Rules

#### Z-Flag Detection

```yaml
title: DNS Z-Flag Anomaly (Spinnekop C2)
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects non-zero Z-flag in DNS responses, indicating potential Spinnekop C2
author: Security Research
date: 2024/01/20
references:
    - https://github.com/faanross/spinnekop
logsource:
    category: dns
    product: zeek
detection:
    selection:
        z_flag|gt: 0
    condition: selection
falsepositives:
    - Misconfigured DNS servers (rare)
level: high
tags:
    - attack.command_and_control
    - attack.t1071.004
```

#### High-Entropy Subdomain

```yaml
title: High-Entropy DNS Subdomain (Data Exfiltration)
id: b2c3d4e5-f6a7-8901-bcde-f23456789012
status: experimental
description: Detects high-entropy DNS subdomains indicating data encoding
logsource:
    category: dns
detection:
    selection:
        query|re: '^[A-Za-z0-9+/]{20,}=*\.'
    condition: selection
level: medium
tags:
    - attack.exfiltration
    - attack.t1048.003
```

### Elasticsearch Queries

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "type": "dns" }},
        { "range": { "dns.flags.z": { "gt": 0 }}}
      ]
    }
  }
}
```

## Detection Limitations

### Why Detection Can Be Difficult

| Challenge | Description |
|-----------|-------------|
| Volume | High DNS traffic makes analysis resource-intensive |
| Encryption | DoH/DoT hides DNS payload from inspection |
| Caching | Responses may be cached, hiding command frequency |
| Tooling | Many tools don't inspect Z-bits by default |
| Awareness | Analysts may not know to look for this technique |

### Evasion Considerations

Sophisticated attackers might:
- Use very low Z-value change frequency
- Combine with legitimate DNS traffic
- Use DNS-over-HTTPS to hide payload
- Rotate C2 domains frequently

## Hunting Workflow

### Step 1: Baseline Normal DNS

```
1. Identify your organization's DNS patterns
2. Document expected query volumes by domain
3. Note typical subdomain structures
4. Establish timing baselines
```

### Step 2: Hunt for Anomalies

```
1. Search for Z-flag != 0 (highest confidence)
2. Calculate subdomain entropy scores
3. Identify periodic query patterns
4. Correlate DNS with subsequent HTTP
```

### Step 3: Investigate Findings

```
1. Examine source hosts
2. Check process making DNS queries
3. Review historical DNS for same domain
4. Analyze response content
```

### Step 4: Document and Respond

```
1. Document indicators of compromise
2. Block C2 domains at DNS resolver
3. Isolate affected hosts
4. Preserve evidence for forensics
```

## Quick Reference

### IOC Patterns

| Indicator | Type | Confidence |
|-----------|------|------------|
| `dns.flags.z != 0` | Network | High |
| `*.[base64].timeserversync.com` | Domain | High |
| Periodic DNS every 2-8 seconds | Behavior | Medium |
| DNS followed by HTTP POST | Behavior | Medium |
| Process name `spinnekop*` | Host | High |

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| DNS | T1071.004 | Application Layer Protocol: DNS |
| Exfiltration Over C2 | T1041 | Data exfiltration via command channel |
| Ingress Tool Transfer | T1105 | HTTP file transfer |
| Data Encoding | T1132 | Base64 data encoding |

## Next Steps

- [PCAP Analyzer](analyzer-guide.md) - Analyze captured traffic
- [Architecture](architecture.md) - Understand system design
- [Z-Value Protocol](z-value-protocol.md) - Protocol specification
