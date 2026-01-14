# Protocol-Specific Features for Multi-Class DDoS Detection

## Overview

This document specifies new features to add to the MIRA detector to support detection of 13+ attack types from the CIC-DDoS-2019 dataset.

---

## Current Features (14)

```c
1.  total_packets
2.  total_bytes
3.  udp_packets
4.  tcp_packets
5.  icmp_packets
6.  syn_packets
7.  http_requests
8.  dns_queries
9.  baseline_packets  // 10.10.2.x
10. attack_packets    // 10.10.3.x
11. udp_tcp_ratio
12. syn_total_ratio
13. baseline_attack_ratio
14. bytes_per_packet
```

---

## NEW Features to Add (26 additional)

### NTP Amplification Detection (3 features)

```c
// In struct worker_stats:
uint64_t ntp_monlist_queries;      // NTP mode 7 MON_GETLIST packets
uint64_t ntp_responses;             // NTP responses
uint16_t avg_ntp_response_size;     // Average NTP response size

// Detection logic (in packet processing):
if (udp_dst_port == 123 || udp_src_port == 123) {
    // Check for mode 7 (private/monlist command)
    if (pkt_len >= 48) {
        uint8_t ntp_mode = (udp_payload[0] >> 0) & 0x07;
        if (ntp_mode == 7) {  // Private mode
            local_ntp_monlist_queries++;
        }
    }

    if (udp_src_port == 123) {  // Response
        local_ntp_responses++;
        ntp_response_size_sum += pkt_len;
    }
}
```

### DNS Amplification Detection (4 features)

```c
// In struct worker_stats:
uint64_t dns_any_queries;           // DNS type ANY queries (used in amplification)
uint64_t dns_txt_queries;           // DNS TXT queries
uint64_t dns_responses;             // DNS responses
uint16_t avg_dns_response_size;     // Average DNS response size

// Detection logic:
if (udp_dst_port == 53 || udp_src_port == 53) {
    if (pkt_len >= 42) {  // Eth + IP + UDP + DNS header
        uint8_t *dns_header = udp_payload;
        uint16_t dns_flags = (dns_header[2] << 8) | dns_header[3];
        bool is_response = (dns_flags & 0x8000) != 0;

        if (!is_response) {  // Query
            // Check query type (offset 12 onwards)
            // Type ANY = 255 (0x00FF)
            // Type TXT = 16 (0x0010)
            // This requires more parsing...
            local_dns_queries++;
        } else {
            local_dns_responses++;
            dns_response_size_sum += pkt_len;
        }
    }
}
```

### SNMP Amplification Detection (3 features)

```c
// In struct worker_stats:
uint64_t snmp_getbulk_requests;     // SNMP GetBulkRequest packets
uint64_t snmp_responses;            // SNMP responses
uint16_t avg_snmp_response_size;    // Average SNMP response size

// Detection logic:
if (udp_dst_port == 161 || udp_src_port == 161) {
    // SNMP GetBulkRequest has PDU type 0x05
    // Simple heuristic: check for large UDP payloads (>200 bytes)
    if (pkt_len > 200) {
        local_snmp_getbulk_requests++;
    }
}
```

### SSDP Amplification Detection (2 features)

```c
// In struct worker_stats:
uint64_t ssdp_msearch_packets;      // SSDP M-SEARCH packets
uint64_t ssdp_responses;            // SSDP responses

// Detection logic:
if (udp_dst_port == 1900 || udp_src_port == 1900) {
    // Check for "M-SEARCH" string in payload
    if (pkt_len >= 60) {
        if (memcmp(udp_payload, "M-SEARCH", 8) == 0) {
            local_ssdp_msearch_packets++;
        }
    }
}
```

### PortMapper/RPC Detection (2 features)

```c
// In struct worker_stats:
uint64_t portmap_getport_calls;     // RPC portmapper GETPORT calls
uint64_t portmap_dump_calls;        // RPC portmapper DUMP calls

// Detection logic:
if (udp_dst_port == 111 || tcp_dst_port == 111) {
    // Portmapper uses RPC protocol
    // Amplification uses DUMP procedure (procedure #4)
    local_portmap_getport_calls++;
}
```

### NetBIOS Detection (2 features)

```c
// In struct worker_stats:
uint64_t netbios_name_queries;      // NetBIOS name service queries
uint64_t netbios_dgram_packets;     // NetBIOS datagram service

// Detection logic:
if (udp_dst_port == 137 || udp_dst_port == 138) {
    if (udp_dst_port == 137) {
        local_netbios_name_queries++;  // Name service
    } else {
        local_netbios_dgram_packets++; // Datagram service
    }
}
```

### LDAP Detection (2 features)

```c
// In struct worker_stats:
uint64_t ldap_bind_requests;        // LDAP Bind requests
uint64_t ldap_search_requests;      // LDAP Search requests

// Detection logic:
if (tcp_dst_port == 389 || tcp_dst_port == 636) {  // LDAP/LDAPS
    // Simple heuristic: count packets to LDAP port
    local_ldap_bind_requests++;
}
```

### MSSQL Detection (2 features)

```c
// In struct worker_stats:
uint64_t mssql_sqlbatch_packets;    // MSSQL SQLBatch packets
uint64_t mssql_rpc_packets;         // MSSQL RPC packets

// Detection logic:
if (tcp_dst_port == 1433 || udp_dst_port == 1434) {  // MSSQL
    local_mssql_sqlbatch_packets++;
}
```

### TFTP Detection (2 features)

```c
// In struct worker_stats:
uint64_t tftp_rrq_packets;          // TFTP Read Request packets
uint64_t tftp_wrq_packets;          // TFTP Write Request packets

// Detection logic:
if (udp_dst_port == 69) {  // TFTP
    if (pkt_len >= 44) {
        uint16_t tftp_opcode = (udp_payload[0] << 8) | udp_payload[1];
        if (tftp_opcode == 1) {
            local_tftp_rrq_packets++;  // Read Request
        } else if (tftp_opcode == 2) {
            local_tftp_wrq_packets++;  // Write Request
        }
    }
}
```

### Derived Amplification Features (6 ratios)

```c
// Calculated in feature extraction:
float ntp_amplification_factor;     // avg_ntp_response_size / avg_ntp_query_size
float dns_amplification_factor;     // avg_dns_response_size / avg_dns_query_size
float snmp_amplification_factor;    // avg_snmp_response_size / avg_request_size
float query_response_ratio;         // total_queries / total_responses (imbalance)
float fragmentation_ratio;          // fragmented_packets / total_packets
float syn_ack_ratio;                // syn_packets / ack_packets
```

---

## Total Features After Enhancement

**Original**: 14 features
**New protocol-specific**: 26 features
**Derived ratios**: 6 features
**TOTAL**: **46 features**

---

## Implementation Priority

### Phase 1 (Critical for CIC-DDoS-2019):
1. NTP features (3)
2. DNS features (4)
3. SNMP features (3)
4. SSDP features (2)
5. Amplification factors (6)

**Total**: 18 new features → **32 features total**

### Phase 2 (Additional protocols):
1. PortMap (2)
2. NetBIOS (2)
3. LDAP (2)
4. MSSQL (2)
5. TFTP (2)

**Total**: 10 new features → **42 features total**

### Phase 3 (Advanced):
1. Fragmentation detection
2. Packet size distribution
3. Inter-arrival time statistics
4. Flow-level features

---

## Multi-Class Labels

### Attack Type Classification (13+ classes):

```python
ATTACK_TYPES = [
    'benign',            # Normal traffic
    'portmap',           # RPC portmapper amplification
    'netbios',           # NetBIOS name service amplification
    'ldap',              # LDAP amplification
    'mssql',             # MSSQL amplification
    'udp_flood',         # Generic UDP flood
    'udp_lag',           # UDP with lag/delay
    'syn_flood',         # SYN flood attack
    'ntp',               # NTP amplification
    'dns',               # DNS amplification
    'snmp',              # SNMP amplification
    'ssdp',              # SSDP amplification
    'webddos',           # HTTP/HTTPS flood
    'tftp',              # TFTP amplification
    'mixed'              # Multiple attack types simultaneously
]
```

---

## Data Collection Strategy for Multi-Class

### Training Set (Day 1 - 7 attack types):
```bash
# Run detector for each attack type separately:
# 1. Benign baseline (3 runs × 30 min)
# 2. PortMap attack (3 runs × 20 min)
# 3. NetBIOS attack (3 runs × 20 min)
# 4. LDAP attack (3 runs × 20 min)
# 5. MSSQL attack (3 runs × 20 min)
# 6. UDP flood (3 runs × 20 min)
# 7. UDP-Lag (3 runs × 20 min)
# 8. SYN flood (3 runs × 20 min)

# Total training time: 90 + 7×60 = 510 minutes (8.5 hours)
# Expected samples: ~5100 (10 samples/min × 510 min)
```

### Validation Set (Day 1 - same types, 30%):
- Same attack types, different runs
- ~1500 samples

### Test Set (Day 2 - 13 attack types including NEW ones):
```bash
# NEW attack types NOT in training:
# - NTP amplification
# - DNS amplification
# - SNMP amplification
# - SSDP amplification
# - WebDDoS
# - TFTP amplification

# Total test time: ~13 × 30 min = 390 minutes (6.5 hours)
# Expected samples: ~3900
```

---

## Updated Feature Extractor

Modify `feature_extractor.py` to:

1. Accept `--label <attack_type>` instead of just `benign/attack/mixed`
2. Extract 32-46 features from logs
3. Support multi-class output

Example:
```bash
python3 feature_extractor.py \
    --input benign_run1.log \
    --output benign_run1.csv \
    --label benign

python3 feature_extractor.py \
    --input ntp_attack_run1.log \
    --output ntp_attack_run1.csv \
    --label ntp
```

---

## Expected Performance Improvement

**Current (3 classes, 14 features, 630 samples)**:
- Validation accuracy: 100% (overfitted)
- Cannot distinguish attack types

**Target (14 classes, 32 features, 5000+ samples)**:
- Validation accuracy: 92-96% (realistic)
- Test accuracy on unseen attacks: 85-90% (generalization)
- Per-class precision/recall: >80% for most attack types

---

## Next Steps

1. Modify `detectorML.c` to add protocol-specific features
2. Update `feature_extractor.py` for multi-class labels
3. Collect training data (8.5 hours)
4. Retrain with conservative hyperparameters
5. Test on Day 2 attacks (unseen types)
