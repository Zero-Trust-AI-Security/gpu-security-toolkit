# Monitoring Overview

Complete monitoring and detection stack for GPU security.

## Monitoring Stack

```
┌─────────────────────────────────────────────────────┐
│ SIEM (Splunk/ELK) - Centralized log aggregation    │
└─────────────────────────────────────────────────────┘
                     ↑
┌─────────────────────────────────────────────────────┐
│ Prometheus - Metrics collection & alerting          │
└─────────────────────────────────────────────────────┘
                     ↑
┌─────────────────────────────────────────────────────┐
│ DCGM - GPU metrics & health monitoring              │
└─────────────────────────────────────────────────────┘
                     ↑
┌─────────────────────────────────────────────────────┐
│ GPU Infrastructure                                   │
└─────────────────────────────────────────────────────┘
```

## Components

### [DCGM Configuration](./dcgm.md)
**Data Center GPU Manager** - Foundation of GPU monitoring
- Installation & setup
- Policy configuration for security events
- Alert rules for anomalies
- Health checks

### [Prometheus Integration](./prometheus.md)
**Metrics & Alerting** - Time-series monitoring
- DCGM exporter setup
- Alert rules for security events
- Grafana dashboard examples

### [SIEM Integration](./siem.md)
**Log Aggregation & Correlation**
- [Splunk Configuration](./siem-splunk.md)
- [ELK Stack Configuration](./siem-elk.md)
- [Detection Queries](./siem-queries.md)

### [Anomaly Detection](./anomaly-detection.md)
**Behavioral Analysis**
- [Cryptomining Detection](./anomaly-cryptomining.md)
- [Data Exfiltration Detection](./anomaly-exfiltration.md)
- [Insider Threat Detection](./anomaly-insider.md)

## Quick Start

### Install DCGM (5 minutes)

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y datacenter-gpu-manager

# Start service
sudo systemctl enable dcgm
sudo systemctl start dcgm

# Configure security policies
dcgmi policy --set 4,20  # Cryptomining: >90% util for >20min
dcgmi policy --set 5,10  # Fault injection: >10 ECC errors/min
```

### Deploy Prometheus (15 minutes)

```bash
# Install DCGM exporter
docker run -d --gpus all --rm -p 9400:9400 \
  nvcr.io/nvidia/k8s/dcgm-exporter:3.1.3-3.1.4-ubuntu20.04

# Add to Prometheus scrape config
# See: monitoring/prometheus.md
```

### Configure Alerts (10 minutes)

Example Prometheus alert rules available in:
- [configs/prometheus/gpu-security-alerts.yml](../../configs/prometheus/)

## Detection Coverage

| Threat | Detection Method | Alert Latency | False Positive Rate |
|--------|-----------------|---------------|-------------------|
| **Cryptomining** | GPU util >90% for 20min | ~20 minutes | Low |
| **Model Theft** | High memory bandwidth | ~5 minutes | Medium |
| **Container Escape** | Pod security violations | Immediate | Low |
| **Firmware Tampering** | Hash mismatch | On boot | Very Low |
| **Fault Injection** | ECC error spike | ~1 minute | Low |
| **Insider Threat** | After-hours access | Immediate | Medium |

## Next Steps

1. ✅ [Install DCGM](./dcgm.md) - Foundation monitoring
2. ✅ [Configure Prometheus](./prometheus.md) - Alerting
3. ✅ [SIEM Integration](./siem.md) - Log aggregation
4. ✅ [Test Alerts](../appendix/testing.md) - Validate detection

