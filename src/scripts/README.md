# Forensic Scripts

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
```bash
sudo collect_gpu_evidence.sh INCIDENT-2026-001
```

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
```bash
sudo analyze_gpu_process.sh <PID>
```

### [capture_gpu_network.sh](./capture-network.md)
**Purpose:** Network traffic capture from GPU processes  
**Runtime:** 5-30 minutes (configurable)  
**Captures:**
- Full packet capture (PCAP)
- DNS queries
- Remote IP addresses
- Mining pool detection

**Usage:**
```bash
sudo capture_gpu_network.sh 300  # 5 minutes
```

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

```bash
# Install all scripts
sudo make install-scripts

# Verify installation
ls -l /usr/local/bin/*gpu* /usr/local/bin/respond_*

# Test script syntax
for script in /usr/local/bin/*gpu*; do
    bash -n $script && echo "✓ $script" || echo "✗ $script"
done
```

## Script Locations

**After installation:**
- Scripts: 
- Evidence: 
- Configs: 

## Dependencies

All scripts require:
- NVIDIA Driver 535+
- , ,  (installed automatically)
- Root/sudo access

See [Installation](../../introduction/quick-start.md#installation) for details.

