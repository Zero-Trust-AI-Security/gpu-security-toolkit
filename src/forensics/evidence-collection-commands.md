# EVIDENCE COLLECTION COMMANDS

### Complete System Evidence Collection

```bash
# Full evidence collection (use during ANY incident)
sudo collect_gpu_evidence.sh INCIDENT-2026-001

# Output:
# /forensics/gpu-incident-YYYYMMDD-HHMMSS/
# ├── gpu_processes.csv              # All GPU processes at incident time
# ├── gpu_state.csv                  # Full GPU configuration
# ├── network_connections.txt        # Network activity
# ├── cuda_contexts.txt              # Active CUDA workloads
# ├── firmware_hashes.txt            # GPU ROM hashes
# ├── driver_hashes.txt              # Driver integrity
# ├── container_details.txt          # Container info (if applicable)
# ├── auth_ssh.log                   # SSH authentication
# ├── auth_sudo.log                  # Sudo usage
# └── CHECKSUMS.sha256              # Evidence integrity

# Evidence is automatically archived:
# gpu-evidence-hostname-YYYYMMDD-HHMMSS.tar.gz
```

### Individual Component Collection

```bash
# GPU state only
nvidia-smi -q > gpu_full_state_$(date +%Y%m%d-%H%M%S).txt

# GPU process snapshot
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv \
  > gpu_processes_$(date +%Y%m%d-%H%M%S).csv

# Network connections from GPU processes
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader); do
    echo "=== PID $pid ==="
    lsof -n -P -i -a -p $pid
done > gpu_network_$(date +%Y%m%d-%H%M%S).txt

# GPU firmware hashes
for pci in /sys/bus/pci/devices/0000:*/rom; do
    if [ -e "$pci" ]; then
        addr=$(basename $(dirname $pci))
        echo "$addr:"
        echo 1 > /sys/bus/pci/devices/$addr/rom
        sha256sum $pci
        echo 0 > /sys/bus/pci/devices/$addr/rom
    fi
done > firmware_hashes_$(date +%Y%m%d-%H%M%S).txt
```

### Live Process Analysis

```bash
# Analyze specific suspicious process
sudo analyze_gpu_process.sh 12345

# Output:
# /forensics/gpu-process-12345-YYYYMMDD-HHMMSS/
# ├── process_info.txt               # Process details
# ├── process_cmdline.txt            # Command line args
# ├── process_environment.txt        # Environment variables (check for secrets!)
# ├── process_network.txt            # Network connections
# ├── binary_hash.txt                # Binary SHA256 (compare against known-good)
# ├── gpu_usage.txt                  # GPU memory usage
# ├── remote_hosts.csv               # All contacted IPs/domains
# └── ANALYSIS_SUMMARY.txt           # Investigation guidance
```

### Network Traffic Capture

```bash
# Capture GPU process network traffic for 5 minutes
sudo capture_gpu_network.sh 300

# Capture for 30 minutes
sudo capture_gpu_network.sh 1800

# Output:
# /forensics/gpu-network-YYYYMMDD-HHMMSS/
# ├── gpu_traffic.pcap               # Full packet capture (open in Wireshark)
# ├── dns_queries.txt                # All DNS lookups
# ├── connections_all.txt            # Connection timeline
# ├── mining_pool_ips.txt            # Suspected mining pools (if detected)
# └── indicator_analysis.txt         # Automated threat detection
```

### Timeline Reconstruction

```bash
# Build incident timeline for last 24 hours
sudo reconstruct_timeline.sh

# Timeline for specific period
sudo reconstruct_timeline.sh "2026-01-30 08:00:00" "2026-01-31 17:00:00"

# Timeline for last week
sudo reconstruct_timeline.sh "1 week ago" "now"

# Output:
# /forensics/gpu-timeline-YYYYMMDD-HHMMSS/
# ├── unified_timeline.txt           # Human-readable chronological events
# ├── unified_timeline.json          # Machine-readable for SIEM import
# ├── pattern_analysis.txt           # Suspicious pattern detection
# └── TIMELINE_SUMMARY.txt           # Investigation guidance
```

---
