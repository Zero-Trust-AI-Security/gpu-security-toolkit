#!/bin/bash
# Integrate all existing GPU security documentation into mdBook structure

set -e

echo "=== GPU Security Toolkit - Content Integration ==="
echo ""

# Function to create chapter file
create_chapter() {
    local file=$1
    local content=$2
    
    mkdir -p "$(dirname "$file")"
    echo "$content" > "$file"
    echo "✓ Created: $file"
}

# Part I: Controls - From nvidia_gpu_security_controls.md
echo "[1/7] Integrating NIST 800-53 Controls..."

create_chapter "src/controls/README.md" "# NIST 800-53 Security Controls

This section provides complete implementation guidance for all NIST 800-53 control families as they apply to GPU infrastructure.

## Control Families Covered

- **[Access Control (AC)](./access-control.md)** - User authentication, resource allocation, least privilege
- **[Audit & Accountability (AU)](./audit-accountability.md)** - Logging, monitoring, audit trails
- **[Configuration Management (CM)](./configuration-management.md)** - Baseline configs, change control
- **[Identification & Authentication (IA)](./identification-authentication.md)** - MFA, SSO integration
- **[System & Communications Protection (SC)](./system-communications.md)** - Encryption, network security
- **[System & Information Integrity (SI)](./system-integrity.md)** - Malware protection, integrity verification
- **[Risk Assessment (RA)](./risk-assessment.md)** - Vulnerability scanning, risk analysis
- **[Physical & Environmental Protection (PE)](./physical-environmental.md)** - Physical security, environmental monitoring

## Zero Trust Implementation

- **[Zero Trust Architecture](./zero-trust.md)** - Never trust, always verify principles
- **[Performance Impact Analysis](./performance-impact.md)** - Quantified overhead for each control

## Quick Reference

| Control | GPU Implementation | Performance Impact |
|---------|-------------------|-------------------|
| AC-2 | MIG isolation, RBAC | <1% |
| AU-2 | DCGM logging | 1-2% |
| CM-7 | Least functionality | +2-3% (gain) |
| SC-8 | NVLink encryption | 5-8% |
| SC-28 | GPU memory encryption (H100 CC) | 2-4% |
| SI-4 | Anomaly detection | 1-2% |

See [Performance Impact Analysis](./performance-impact.md) for complete breakdown.
"

# Part II: Threats - From gpu_threat_model_frameworks.md  
echo "[2/7] Integrating Threat Model & Frameworks..."

create_chapter "src/threats/README.md" "# Threat Model Overview

This section covers the complete threat landscape for GPU infrastructure, including attack vectors, threat actors, and comprehensive mitigation strategies.

## What's Covered

### [GPU Attack Surface](./attack-surface.md)
Understanding the 6 layers where GPUs can be attacked:
- Application layer (malicious CUDA kernels)
- Software layer (driver vulnerabilities)
- Firmware layer (persistent backdoors)
- Hardware layer (physical tampering)
- Network layer (fabric attacks)
- Physical layer (fault injection)

### [Security Frameworks](./frameworks.md)
Mapping of 10 security frameworks to GPU infrastructure:
- [MITRE ATT&CK for GPUs](./mitre-attack.md)
- [CIS Controls](./cis-controls.md)
- [OWASP Cloud-Native](./owasp.md)
- [NIST AI RMF](./ai-rmf.md)
- [HIPAA](./hipaa.md)
- [PCI DSS](./pci-dss.md)
- [FedRAMP](./fedramp.md)
- [CMMC](./cmmc.md)
- ISO 27001, ENISA

### [Threat Scenarios](./scenarios.md)
8 detailed threat scenarios with complete attack chains:
1. [Cryptomining Hijacking](./scenario-cryptomining.md) - Resource theft
2. [Model Theft](./scenario-model-theft.md) - IP exfiltration
3. [Container Escape](./scenario-container-escape.md) - Isolation bypass
4. [Firmware Compromise](./scenario-firmware.md) - Persistent backdoors
5. [Resource DoS](./scenario-dos.md) - Availability attacks
6. [Driver Exploitation](./scenario-driver.md) - Privilege escalation
7. [Fault Injection](./scenario-fault-injection.md) - Physical attacks
8. [Model Poisoning](./scenario-poisoning.md) - AI supply chain

### Risk Analysis
- [Risk Matrix](./risk-matrix.md) - Pre/post-mitigation risk assessment
- [Defense in Depth](./defense-in-depth.md) - Layered security architecture

## Threat Priorities

| Threat | Likelihood | Impact | Risk Level | Priority |
|--------|-----------|--------|-----------|----------|
| Cryptomining | High | Medium | **HIGH** | 1 |
| Model Theft | Medium | Critical | **HIGH** | 2 |
| Container Escape | Medium | Critical | **HIGH** | 3 |
| Firmware Backdoor | Low | Critical | **MEDIUM** | 4 |

## Quick Start

**For defenders:** Start with [Scenario 1: Cryptomining](./scenario-cryptomining.md) - most common threat

**For compliance:** Review [Security Frameworks](./frameworks.md) for your industry

**For architects:** Read [Defense in Depth](./defense-in-depth.md) for architecture guidance
"

# Part III: Use Cases - From gpu_use_case_security_guide.md
echo "[3/7] Integrating Platform-Specific Security..."

create_chapter "src/use-cases/README.md" "# GPU Deployment Scenarios

Security guidance for every GPU deployment type, from single workstations to massive datacenter clusters.

## Deployment Types

### [Single GPU Workstation](./workstation.md)
**Profile:** Developer/data scientist workstation
- 1x GPU (RTX 6000 Ada, A6000, RTX 4090)
- Windows 11 Pro or Ubuntu 22.04 LTS
- Local user with admin rights
- **Security Level:** ⭐⭐⭐ Medium
- **Performance Impact:** 1-2%

### [Multi-GPU Training Server](./training-server.md)
**Profile:** 8-GPU AI/ML training server
- 8x H100, H200, A100, or L40S
- Ubuntu 22.04 LTS Server
- NVLink/NVSwitch fabric
- Multi-tenant workloads
- **Security Level:** ⭐⭐⭐⭐⭐ Critical
- **Performance Impact:** 5-12%

### [HPC Compute Node](./hpc.md)
**Profile:** Scientific computing
- 4x H200, A100 80GB
- RHEL 8 or Rocky Linux
- InfiniBand HDR interconnect
- SLURM job scheduler
- **Security Level:** ⭐⭐⭐⭐ High
- **Performance Impact:** 2-3%

### [Virtualized GPU Server](./vgpu.md)
**Profile:** VDI and multi-tenant
- 4x A100, A40, L40, RTX 6000 Ada
- VMware vSphere 8.0 or KVM
- 20-40 VMs per server
- **Security Level:** ⭐⭐⭐ Medium-High
- **Performance Impact:** 3-5%

### [Container/Kubernetes GPU](./kubernetes.md)
**Profile:** Cloud-native GPU workloads
- Multiple nodes, 4-8 GPUs each
- Kubernetes 1.28+ with GPU Operator
- Container runtime with nvidia-toolkit
- **Security Level:** ⭐⭐⭐⭐ High
- **Performance Impact:** 2-4%

## GPU Hardware Reference

### [Hardware Security Features](./hardware.md)
Complete security feature matrix for every GPU family:

- [Hopper Architecture (H100/H200)](./hardware-hopper.md) - **Full security features**
- [Ampere Architecture (A100/A30)](./hardware-ampere.md) - MIG + ECC
- [Ada Lovelace (L40S/L4)](./hardware-ada.md) - ECC + vGPU
- [Professional RTX (RTX 6000 Ada)](./hardware-professional.md) - Workstation
- [GPU Selection Matrix](./hardware-selection.md) - Choose based on security needs

## Quick Selection Guide

**Need Confidential Computing?** → H100/H200 only  
**Need Hardware Isolation?** → H100/A100 (MIG support)  
**Need vGPU?** → A40, L40S, RTX 6000 Ada  
**Budget Workstation?** → RTX 6000 Ada (not consumer RTX!)

## Configuration Scripts

Each platform includes production-ready baseline configuration scripts:
- `baseline-workstation.sh`
- `baseline-multigpu.sh`
- `baseline-hpc.sh`
- `baseline-k8s.sh`

See [Scripts section](../scripts/baselines.md) for details.
"

# Part IV: Forensics - From gpu_forensics_complete_guide.md
echo "[4/7] Integrating Forensics & Incident Response..."

create_chapter "src/forensics/README.md" "# Incident Response Overview

Complete forensic and incident response procedures for GPU security incidents.

## Incident Types

| Type | Indicators | Priority | Response Time |
|------|-----------|----------|---------------|
| **Cryptomining** | 100% GPU util, mining pools | P1 - Critical | Immediate |
| **Model Theft** | Large transfers, memory dumps | P1 - Critical | Immediate |
| **Container Escape** | Host access, privilege escalation | P1 - Critical | Immediate |
| **Firmware Compromise** | Hash mismatch, unexpected behavior | P1 - Critical | Immediate |

## Quick Response

**Active incident RIGHT NOW?** → [Quick Start Guide](../introduction/quick-start.md#active-incident-response)

## What's Covered

### Evidence Collection
- [Volatile Evidence](./volatile-evidence.md) - GPU state, memory, processes
- [Non-Volatile Evidence](./non-volatile-evidence.md) - Firmware, configuration
- [Network Traffic Capture](./network-capture.md) - Packet analysis
- [Timeline Reconstruction](./timeline.md) - Event correlation

### Response Procedures
- [Incident Types & Priorities](./incident-types.md)
- [Response Team Roles](./team-roles.md)
- [Evidence Collection Principles](./evidence-principles.md)

### Forensic Analysis
- [Packet Capture Analysis](./pcap-analysis.md) - Wireshark techniques
- [Binary Analysis](./binary-analysis.md) - Malware identification
- [Memory Forensics](./memory-forensics.md) - GPU memory dumps
- [Threat Intelligence Lookup](./threat-intel.md) - IoC verification

### Recovery
- [System Hardening](./hardening.md) - Post-incident strengthening
- [Baseline Restoration](./baseline.md) - Return to secure state
- [Verification Procedures](./verification.md) - Confirm clean state

## Incident Response Playbooks

Ready-to-execute playbooks for immediate response:
- [Playbook 1: Cryptomining](../playbooks/cryptomining.md)
- [Playbook 2: Model Theft](../playbooks/model-theft.md)
- [Playbook 3: Container Escape](../playbooks/container-escape.md)
- [Playbook 4: Firmware Compromise](../playbooks/firmware.md)

## Evidence Collection Scripts

Production scripts in `/usr/local/bin/`:
- `collect_gpu_evidence.sh` - Complete evidence snapshot (<5 min)
- `analyze_gpu_process.sh` - Live process investigation
- `capture_gpu_network.sh` - Network traffic capture
- `reconstruct_timeline.sh` - Event timeline building

See [Scripts section](../scripts/README.md) for complete documentation.
"

# Part V: Scripts - Documentation for all scripts
echo "[5/7] Creating Script Documentation..."

create_chapter "src/scripts/README.md" "# Forensic Scripts

Production-ready bash scripts for GPU security operations.

## Evidence Collection

### [collect_gpu_evidence.sh](./collect-evidence.md)
**Purpose:** Complete volatile evidence collection  
**Runtime:** <5 minutes  
**Evidence Collected:**
- GPU process snapshot
- GPU configuration state
- Network connections
- CUDA contexts
- System logs
- Firmware hashes
- Container information

**Usage:**
\`\`\`bash
sudo collect_gpu_evidence.sh INCIDENT-2026-001
\`\`\`

### [analyze_gpu_process.sh](./analyze-process.md)
**Purpose:** Deep dive on suspicious GPU process  
**Runtime:** ~2 minutes  
**Analysis Includes:**
- Command line and environment
- Network connections
- Open files and handles
- Memory maps
- Binary hash verification
- Parent process tree

**Usage:**
\`\`\`bash
sudo analyze_gpu_process.sh <PID>
\`\`\`

### [capture_gpu_network.sh](./capture-network.md)
**Purpose:** Network traffic capture from GPU processes  
**Runtime:** 5-30 minutes (configurable)  
**Captures:**
- Full packet capture (PCAP)
- DNS queries
- Remote IP addresses
- Mining pool detection

**Usage:**
\`\`\`bash
sudo capture_gpu_network.sh 300  # 5 minutes
\`\`\`

## Incident Response Automation

### [respond_cryptomining.sh](./respond-cryptomining.md)
**Purpose:** Automated cryptomining incident response  
**Runtime:** ~10 minutes  
**Actions:**
1. Collect forensic evidence
2. Identify mining processes
3. Block mining pool IPs
4. Terminate malicious processes
5. Check for persistence
6. Generate incident report

### [respond_model_theft.sh](./respond-model-theft.md)
**Purpose:** Model theft / data exfiltration response  
**Runtime:** ~15 minutes  
**Actions:**
1. Preserve GPU memory state
2. Capture network transfers
3. Identify data destinations
4. Network isolation options
5. Check CC encryption status

### [respond_container_escape.sh](./respond-container-escape.md)
**Purpose:** Container escape incident response  
**Runtime:** ~10 minutes  
**Actions:**
1. Identify privileged containers
2. Check host filesystem access
3. Find escaped processes
4. Container isolation/removal

## Security Baselines

### [baseline-workstation.sh](./baseline-workstation.md)
**Platform:** Single GPU workstation  
**Runtime:** ~5 minutes  
**Configures:**
- Persistence mode
- ECC (if supported)
- Exclusive process mode
- Audit logging

### [baseline-multigpu.sh](./baseline-multigpu.md)
**Platform:** 8-GPU server (H100/A100)  
**Runtime:** ~15 minutes  
**Configures:**
- MIG mode (7 instances per GPU)
- Confidential Computing (H100)
- NVLink encryption (H100)
- DCGM monitoring

### [baseline-hpc.sh](./baseline-hpc.md)
**Platform:** HPC compute node  
**Runtime:** ~10 minutes  
**Configures:**
- ECC memory
- SLURM integration
- InfiniBand isolation
- ECC monitoring

### [baseline-k8s.sh](./baseline-k8s.md)
**Platform:** Kubernetes GPU cluster  
**Runtime:** ~10 minutes  
**Applies:**
- ResourceQuotas
- Pod Security Standards
- Network Policies
- GPU Operator security

## Installation

\`\`\`bash
# Install all scripts
sudo make install-scripts

# Verify installation
ls -l /usr/local/bin/*gpu* /usr/local/bin/respond_*

# Test script syntax
for script in /usr/local/bin/*gpu*; do
    bash -n \$script && echo \"✓ \$script\" || echo \"✗ \$script\"
done
\`\`\`

## Script Locations

**After installation:**
- Scripts: `/usr/local/bin/`
- Evidence: `/forensics/`
- Configs: `/etc/gpu-security/`

## Dependencies

All scripts require:
- NVIDIA Driver 535+
- `lsof`, `tcpdump`, `jq` (installed automatically)
- Root/sudo access

See [Installation](../../introduction/quick-start.md#installation) for details.
"

# Part VI: Monitoring
echo "[6/7] Creating Monitoring Documentation..."

create_chapter "src/monitoring/README.md" "# Monitoring Overview

Complete monitoring and detection stack for GPU security.

## Monitoring Stack

\`\`\`
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
\`\`\`

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

\`\`\`bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y datacenter-gpu-manager

# Start service
sudo systemctl enable dcgm
sudo systemctl start dcgm

# Configure security policies
dcgmi policy --set 4,20  # Cryptomining: >90% util for >20min
dcgmi policy --set 5,10  # Fault injection: >10 ECC errors/min
\`\`\`

### Deploy Prometheus (15 minutes)

\`\`\`bash
# Install DCGM exporter
docker run -d --gpus all --rm -p 9400:9400 \\
  nvcr.io/nvidia/k8s/dcgm-exporter:3.1.3-3.1.4-ubuntu20.04

# Add to Prometheus scrape config
# See: monitoring/prometheus.md
\`\`\`

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
"

# Part VII: Appendix
echo "[7/7] Creating Appendix..."

create_chapter "src/appendix/glossary.md" "# Glossary

## GPU Terms

**MIG (Multi-Instance GPU):** Hardware partitioning feature on H100/A100 that creates up to 7 isolated GPU instances per physical GPU.

**Confidential Computing (CC):** H100/H200 feature that encrypts GPU memory with AES-256 to protect models and data.

**ECC (Error-Correcting Code):** Memory error detection and correction to ensure data integrity.

**NVLink:** High-speed GPU-to-GPU interconnect (600 GB/s on H100).

**DCGM:** Data Center GPU Manager - NVIDIA's monitoring and management tool.

**vGPU:** Virtual GPU technology for sharing physical GPUs across multiple VMs.

## Security Terms

**Zero Trust:** Security model that requires continuous verification; never implicitly trust.

**Defense in Depth:** Layered security approach with multiple independent controls.

**MITRE ATT&CK:** Framework of adversary tactics and techniques.

**IoC (Indicator of Compromise):** Artifact indicating a system has been breached.

**SIEM:** Security Information and Event Management system.

## Compliance Terms

**NIST 800-53:** Security controls framework from National Institute of Standards and Technology.

**FedRAMP:** Federal Risk and Authorization Management Program for cloud services.

**HIPAA:** Health Insurance Portability and Accountability Act.

**PCI DSS:** Payment Card Industry Data Security Standard.

**CMMC:** Cybersecurity Maturity Model Certification for DoD contractors.

## Complete glossary with 100+ terms in development...
"

echo ""
echo "✓ Content integration complete!"
echo ""
echo "Created:"
echo "  - src/controls/README.md"
echo "  - src/threats/README.md"
echo "  - src/use-cases/README.md"
echo "  - src/forensics/README.md"
echo "  - src/scripts/README.md"
echo "  - src/monitoring/README.md"
echo "  - src/appendix/glossary.md"
echo ""
echo "Next steps:"
echo "  1. Run: mdbook build"
echo "  2. Run: mdbook serve --open"
echo "  3. Review locally before pushing to GitHub"
