# GPU Security Forensics & Incident Response Guide
## Complete Evidence Collection and Investigation Procedures

**Document Version:** 1.0  
**Last Updated:** January 31, 2026  
**Classification:** Internal Use - Security Operations

---

## TABLE OF CONTENTS

1. [Incident Response Overview](#1-incident-response-overview)
2. [Forensic Evidence Collection Scripts](#2-forensic-evidence-collection-scripts)
3. [Incident Response Playbooks](#3-incident-response-playbooks)
4. [Investigation Procedures](#4-investigation-procedures)
5. [Recovery and Remediation](#5-recovery-and-remediation)

---

## 1. INCIDENT RESPONSE OVERVIEW

### 1.1 GPU Security Incident Priority Matrix

| Incident Type | Indicators | Priority | Response Time | Evidence Collection |
|---------------|-----------|----------|---------------|-------------------|
| **Cryptomining Hijacking** | 100% GPU util, mining pool connections | P1 - Critical | Immediate | Volatile + Network |
| **Model Theft / Data Exfiltration** | Unusual memory access, large transfers | P1 - Critical | Immediate | Memory dump + Network |
| **Container Escape** | Unexpected host access, privilege escalation | P1 - Critical | Immediate | Container + Process |
| **Firmware Compromise** | Firmware hash mismatch, unexpected behavior | P1 - Critical | Immediate | Firmware + ROM |
| **Resource DoS** | GPU exhaustion, users blocked | P2 - High | <15 min | State snapshot |
| **Driver Vulnerability Exploit** | Kernel crashes, unexpected privileges | P1 - Critical | Immediate | Kernel logs + Memory |
| **Side-Channel Attack** | Timing anomalies, power fluctuations | P2 - High | <1 hour | Thermal + Power logs |
| **Insider Threat** | After-hours access, data copying | P2 - High | <1 hour | Timeline + Audit logs |

---

## 2. FORENSIC EVIDENCE COLLECTION SCRIPTS

### 2.1 Master Evidence Collection Script

**Location:** `/usr/local/bin/collect_gpu_evidence.sh`

**Purpose:** First responder script - captures all volatile GPU state before any containment actions

```bash
#!/bin/bash
# GPU Volatile Evidence Collection Script
# Run IMMEDIATELY upon incident detection - DO NOT REBOOT OR RESET GPU

set -euo pipefail

EVIDENCE_DIR="/forensics/gpu-incident-$(date +%Y%m%d-%H%M%S)"
HOSTNAME=$(hostname)
INCIDENT_ID=${1:-"UNKNOWN"}

# Create evidence directory
mkdir -p "$EVIDENCE_DIR"
cd "$EVIDENCE_DIR"

# Start logging
exec 1> >(tee -a evidence.log)
exec 2>&1

echo "=== GPU FORENSIC EVIDENCE COLLECTION ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Hostname: $HOSTNAME"
echo "Incident ID: $INCIDENT_ID"
echo "Operator: $(whoami)"
echo ""

# 1. CAPTURE GPU PROCESS SNAPSHOT (before anything changes)
echo "[1/15] Capturing GPU process snapshot..."
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv > gpu_processes.csv
nvidia-smi pmon -c 1 > gpu_process_monitor.txt
ps auxww > system_processes.txt
echo "  ✓ Process snapshot captured"

# 2. CAPTURE FULL GPU STATE
echo "[2/15] Capturing GPU configuration state..."
nvidia-smi -q > gpu_full_query.txt
nvidia-smi --query-gpu=timestamp,name,pci.bus_id,driver_version,vbios_version,uuid,compute_mode,memory.total,memory.used,memory.free,utilization.gpu,utilization.memory,temperature.gpu,power.draw,clocks.current.graphics,clocks.current.sm,clocks.current.memory,ecc.mode.current,ecc.errors.corrected.aggregate.total,ecc.errors.uncorrected.aggregate.total --format=csv > gpu_state.csv
echo "  ✓ GPU state captured"

# 3. CAPTURE MIG CONFIGURATION
echo "[3/15] Capturing MIG configuration..."
if nvidia-smi --query-gpu=mig.mode.current --format=csv,noheader 2>/dev/null | grep -q "Enabled"; then
    nvidia-smi mig -lgi > mig_instances.txt 2>&1
    nvidia-smi mig -lci >> mig_instances.txt 2>&1
    echo "  ✓ MIG configuration captured"
else
    echo "  - MIG not enabled, skipped"
fi

# 4. CAPTURE NVLINK STATUS
echo "[4/15] Capturing NVLink status..."
nvidia-smi nvlink --status > nvlink_status.txt 2>&1 || echo "  - NVLink not available"

# 5. CAPTURE RUNNING CUDA CONTEXTS
echo "[5/15] Capturing active CUDA contexts..."
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null); do
    {
        echo "=== Process $pid ==="
        cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' '
        echo ""
        ls -la /proc/$pid/fd 2>/dev/null
        echo ""
    } >> cuda_contexts.txt
done
echo "  ✓ CUDA contexts captured"

# 6. CAPTURE NETWORK CONNECTIONS
echo "[6/15] Capturing network connections..."
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null); do
    {
        echo "=== Network for PID $pid ==="
        lsof -n -P -i -a -p $pid 2>/dev/null
        netstat -tnp 2>/dev/null | grep " $pid/"
        echo ""
    } >> network_connections.txt
done
ss -tupn > all_network_sockets.txt
echo "  ✓ Network connections captured"

# 7. CAPTURE MEMORY MAPS
echo "[7/15] Capturing GPU memory maps..."
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null); do
    {
        echo "=== Memory map for PID $pid ==="
        cat /proc/$pid/maps 2>/dev/null
        echo ""
    } >> memory_maps.txt
done
echo "  ✓ Memory maps captured"

# 8. CAPTURE SYSTEM LOGS
echo "[8/15] Capturing system logs..."
journalctl -u nvidia-persistenced --since "24 hours ago" > nvidia_persistenced.log 2>&1 || true
journalctl -u nvidia-fabricmanager --since "24 hours ago" > nvidia_fabricmanager.log 2>&1 || true
journalctl -k --since "24 hours ago" | grep -i nvidia > kernel_nvidia.log 2>&1 || true
dmesg | grep -i nvidia > dmesg_nvidia.log 2>&1 || true
echo "  ✓ System logs captured"

# 9. CAPTURE DCGM METRICS
echo "[9/15] Capturing DCGM metrics..."
if command -v dcgmi &> /dev/null; then
    dcgmi discovery -l > dcgm_discovery.txt 2>&1 || true
    dcgmi health -c > dcgm_health.txt 2>&1 || true
    dcgmi diag -r 1 > dcgm_diag.txt 2>&1 || true
    echo "  ✓ DCGM metrics captured"
else
    echo "  - DCGM not available"
fi

# 10. CAPTURE FIRMWARE/DRIVER INTEGRITY
echo "[10/15] Capturing firmware and driver integrity..."
{
    find /usr/lib/x86_64-linux-gnu -name "libnvidia*.so*" -exec sha256sum {} \;
    find /lib/modules/$(uname -r)/kernel/drivers/video -name "nvidia*.ko*" -exec sha256sum {} \;
} > driver_hashes.txt 2>&1 || true

for gpu_rom in /sys/bus/pci/devices/0000:*/rom; do
    if [[ -e "$gpu_rom" && $(cat /sys/bus/pci/devices/$(basename $(dirname $gpu_rom))/vendor 2>/dev/null) == "0x10de" ]]; then
        pci_addr=$(basename $(dirname $gpu_rom))
        {
            echo "$pci_addr:"
            echo 1 > /sys/bus/pci/devices/$pci_addr/rom 2>/dev/null
            sha256sum /sys/bus/pci/devices/$pci_addr/rom 2>&1 || echo "  Failed to read ROM"
            echo 0 > /sys/bus/pci/devices/$pci_addr/rom 2>/dev/null
        } >> firmware_hashes.txt
    fi
done
echo "  ✓ Firmware/driver integrity captured"

# 11. CAPTURE CONTAINER INFORMATION
echo "[11/15] Capturing container information..."
if command -v docker &> /dev/null; then
    docker ps -a > docker_containers.txt 2>&1
    for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null); do
        container_id=$(docker ps -q --no-trunc 2>/dev/null | while read cid; do
            docker top $cid -eo pid | grep -w $pid && echo $cid
        done)
        if [ ! -z "$container_id" ]; then
            {
                echo "=== Container for PID $pid ==="
                docker inspect $container_id
                echo ""
            } >> container_details.txt
        fi
    done
    echo "  ✓ Container information captured"
else
    echo "  - Docker not available"
fi

if command -v kubectl &> /dev/null; then
    kubectl get pods -A -o wide > k8s_pods.txt 2>&1 || true
    kubectl get nodes -o wide > k8s_nodes.txt 2>&1 || true
    echo "  ✓ Kubernetes information captured"
fi

# 12. CAPTURE AUTHENTICATION LOGS
echo "[12/15] Capturing authentication logs..."
journalctl _COMM=sshd --since "24 hours ago" > auth_ssh.log 2>&1 || true
journalctl _COMM=sudo --since "24 hours ago" > auth_sudo.log 2>&1 || true
lastlog > user_lastlog.txt 2>&1 || true
last -f /var/log/wtmp -n 100 > login_history.txt 2>&1 || true
echo "  ✓ Authentication logs captured"

# 13. CAPTURE CRON/SCHEDULED TASKS
echo "[13/15] Capturing scheduled tasks..."
{
    for user in $(cut -d: -f1 /etc/passwd); do
        echo "=== Crontab for $user ==="
        crontab -l -u $user 2>/dev/null || echo "No crontab"
        echo ""
    done
} > user_crontabs.txt

find /etc/cron* -type f -exec echo "=== {} ===" \; -exec cat {} \; > system_cron.txt 2>&1 || true
systemctl list-timers --all > systemd_timers.txt 2>&1 || true
echo "  ✓ Scheduled tasks captured"

# 14. CAPTURE ENVIRONMENT
echo "[14/15] Capturing environment information..."
{
    echo "=== Kernel Version ==="
    uname -a
    echo ""
    echo "=== Loaded Modules ==="
    lsmod | grep nvidia
    echo ""
    echo "=== NVIDIA Driver Version ==="
    cat /proc/driver/nvidia/version 2>/dev/null || echo "Not available"
    echo ""
    echo "=== GPU Topology ==="
    nvidia-smi topo -m
} > system_environment.txt 2>&1
echo "  ✓ Environment captured"

# 15. CALCULATE CHECKSUMS
echo "[15/15] Calculating evidence checksums..."
sha256sum * 2>/dev/null > CHECKSUMS.sha256
echo "  ✓ Checksums calculated"

# Create tarball
echo ""
echo "Creating evidence archive..."
cd ..
tar -czf "gpu-evidence-${HOSTNAME}-$(date +%Y%m%d-%H%M%S).tar.gz" "$(basename $EVIDENCE_DIR)"

echo ""
echo "=== EVIDENCE COLLECTION COMPLETE ==="
echo "Evidence directory: $EVIDENCE_DIR"
echo "Files collected: $(ls -1 "$EVIDENCE_DIR" | wc -l)"
echo "Total size: $(du -sh "$EVIDENCE_DIR" | cut -f1)"
echo "Archive: gpu-evidence-${HOSTNAME}-$(date +%Y%m%d-%H%M%S).tar.gz"
echo ""
echo "CRITICAL: Preserve this evidence - do NOT modify original files"
echo "Next: Begin incident response playbook for incident type"
```

**Installation:**
```bash
sudo cp collect_gpu_evidence.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/collect_gpu_evidence.sh
```

**Usage:**
```bash
# Immediate evidence collection
sudo /usr/local/bin/collect_gpu_evidence.sh INCIDENT-2026-001

# Output: /forensics/gpu-incident-YYYYMMDD-HHMMSS/
# Archive: gpu-evidence-hostname-YYYYMMDD-HHMMSS.tar.gz
```

---

### 2.2 Live Process Analysis Script

**Location:** `/usr/local/bin/analyze_gpu_process.sh`

```bash
#!/bin/bash
# Live GPU Process Analysis
# Detailed investigation of suspicious GPU process

set -euo pipefail

TARGET_PID=${1:-""}

if [ -z "$TARGET_PID" ]; then
    echo "Usage: $0 <PID>"
    echo ""
    echo "Available GPU processes:"
    nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv
    exit 1
fi

EVIDENCE_DIR="/forensics/gpu-process-${TARGET_PID}-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
cd "$EVIDENCE_DIR"

exec 1> >(tee -a analysis.log)
exec 2>&1

echo "=== LIVE GPU PROCESS ANALYSIS ==="
echo "Target PID: $TARGET_PID"
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# Verify process exists and uses GPU
if ! nvidia-smi --query-compute-apps=pid --format=csv,noheader | grep -q "^$TARGET_PID$"; then
    echo "ERROR: PID $TARGET_PID is not using GPU or does not exist"
    exit 1
fi

echo "[1/12] Process Identification"
ps -p $TARGET_PID -f > process_info.txt
ps -p $TARGET_PID -o pid,ppid,user,group,comm,args,etime,cputime,%cpu,%mem,vsz,rss,stat,wchan:20 > process_details.txt
echo "  ✓ Process info captured"

echo "[2/12] Command Line and Environment"
cat /proc/$TARGET_PID/cmdline 2>/dev/null | tr '\0' '\n' > process_cmdline.txt
cat /proc/$TARGET_PID/environ 2>/dev/null | tr '\0' '\n' > process_environment.txt
echo "  ✓ Command line and environment captured"

echo "[3/12] Open Files and File Descriptors"
lsof -p $TARGET_PID > process_open_files.txt 2>&1
ls -l /proc/$TARGET_PID/fd/ > process_fd.txt 2>&1
echo "  ✓ File descriptors captured"

echo "[4/12] Network Connections"
lsof -n -P -i -a -p $TARGET_PID > process_network.txt 2>&1
ss -tupn | grep " $TARGET_PID/" >> process_network.txt 2>&1 || true
netstat -tnp 2>/dev/null | grep " $TARGET_PID/" >> process_network.txt || true

# Extract remote IPs and reverse DNS
lsof -n -P -i -a -p $TARGET_PID 2>/dev/null | awk 'NR>1 {print $9}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | while read ip; do
    hostname=$(dig -x $ip +short 2>/dev/null | sed 's/\.$//')
    echo "$ip,$hostname"
done > remote_hosts.csv
echo "  ✓ Network connections captured"

echo "[5/12] Memory Maps and Libraries"
cat /proc/$TARGET_PID/maps > process_memory_maps.txt 2>&1
ldd /proc/$TARGET_PID/exe 2>/dev/null > process_libraries.txt || echo "Could not list libraries" > process_libraries.txt
cat /proc/$TARGET_PID/smaps > process_smaps.txt 2>&1 || true
echo "  ✓ Memory information captured"

echo "[6/12] GPU-Specific Usage"
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv | grep "^$TARGET_PID," > gpu_usage.txt
echo "Starting 30-second GPU monitoring sample..."
nvidia-smi pmon -c 30 -s um | grep "^#\|$TARGET_PID" > gpu_monitoring_30s.txt
echo "  ✓ GPU usage captured"

echo "[7/12] System Call Tracing (30 second sample)"
if command -v strace &> /dev/null; then
    timeout 30s strace -p $TARGET_PID -c 2>&1 > syscall_summary.txt || echo "Strace timed out or completed" >> syscall_summary.txt
    echo "  ✓ System calls traced"
else
    echo "  - strace not available"
fi

echo "[8/12] Binary Analysis"
readlink /proc/$TARGET_PID/exe > binary_path.txt 2>&1
if [ -f "$(readlink /proc/$TARGET_PID/exe 2>/dev/null)" ]; then
    sha256sum "$(readlink /proc/$TARGET_PID/exe)" > binary_hash.txt
    file "$(readlink /proc/$TARGET_PID/exe)" > binary_type.txt
    strings "$(readlink /proc/$TARGET_PID/exe)" | head -1000 > binary_strings.txt
else
    echo "Binary not accessible" > binary_hash.txt
fi
echo "  ✓ Binary analyzed"

echo "[9/12] Process Ancestry"
pstree -p -s -a $TARGET_PID > process_tree.txt
echo "  ✓ Process tree captured"

echo "[10/12] Capabilities and Limits"
cat /proc/$TARGET_PID/limits > process_limits.txt 2>&1
getpcaps $TARGET_PID > process_capabilities.txt 2>&1 || true
cat /proc/$TARGET_PID/status > process_status.txt 2>&1
echo "  ✓ Security context captured"

echo "[11/12] Container Context (if applicable)"
if [ -f /proc/$TARGET_PID/cgroup ]; then
    cat /proc/$TARGET_PID/cgroup > process_cgroup.txt
    
    # Try to identify container
    container_id=$(cat /proc/$TARGET_PID/cgroup | grep -oP 'docker/\K[a-f0-9]{64}' | head -1)
    if [ ! -z "$container_id" ]; then
        echo "Container ID: $container_id" > container_context.txt
        docker inspect $container_id >> container_context.txt 2>&1 || true
    fi
fi
echo "  ✓ Container context captured"

echo "[12/12] Collecting Process Memory Sample"
# Attempt to dump small memory sample (first 10MB)
if [ -r /proc/$TARGET_PID/mem ]; then
    dd if=/proc/$TARGET_PID/mem of=memory_sample.bin bs=1M count=10 2>/dev/null || echo "Memory dump failed" > memory_sample.txt
    echo "  ✓ Memory sample collected"
else
    echo "  - Memory not accessible"
fi

# Calculate checksums
sha256sum * 2>/dev/null > CHECKSUMS.sha256

echo ""
echo "=== ANALYSIS COMPLETE ==="

# Create analysis summary
cat > ANALYSIS_SUMMARY.txt << EOF
GPU Process Analysis Summary
============================

Target PID: $TARGET_PID
Process: $(cat process_info.txt | tail -1 | awk '{print $8}')
User: $(cat process_info.txt | tail -1 | awk '{print $1}')
GPU Memory: $(cat gpu_usage.txt | tail -1 | cut -d',' -f3)
Binary: $(cat binary_path.txt 2>/dev/null)
Binary Hash: $(cat binary_hash.txt 2>/dev/null | cut -d' ' -f1)

Network Activity:
$(cat process_network.txt 2>/dev/null | grep ESTABLISHED | wc -l) established connections
Remote Hosts: $(cat remote_hosts.csv 2>/dev/null | wc -l) unique IPs

Parent Process:
$(ps -p $(cat process_info.txt | tail -1 | awk '{print $3}') -o pid,comm,args 2>/dev/null | tail -1)

SUSPICIOUS INDICATORS TO REVIEW:
================================

1. Binary Hash Verification:
   - Compare $(cat binary_hash.txt 2>/dev/null | cut -d' ' -f1) against known-good hashes
   - Check VirusTotal, threat intelligence feeds

2. Network Connections:
   $(cat remote_hosts.csv 2>/dev/null | head -5)
   - Check for connections to mining pools, TOR exit nodes, unknown cloud providers
   - Review remote_hosts.csv for all destinations

3. Environment Variables:
   - Check process_environment.txt for:
     * Hardcoded credentials (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, etc.)
     * Suspicious PATH modifications
     * LD_PRELOAD injection

4. Binary Location:
   - Running from /tmp, /dev/shm, or user home directory = SUSPICIOUS
   - Expected: /usr/bin, /usr/local/bin, /opt

5. Process Capabilities:
   - Review process_capabilities.txt
   - CAP_SYS_ADMIN, CAP_SYS_PTRACE = potential privilege escalation

6. GPU Usage Pattern:
   - Review gpu_monitoring_30s.txt
   - 100% sustained utilization + low CPU = possible cryptomining
   - High memory bandwidth + network transfer = possible model theft

7. File Access:
   - Review process_open_files.txt
   - Access to /models, /data = potential data exfiltration
   - Access to sensitive system files = container escape

Analysis Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Evidence Location: $EVIDENCE_DIR
EOF

cat ANALYSIS_SUMMARY.txt

echo ""
echo "Evidence preserved in: $EVIDENCE_DIR"
echo "Review ANALYSIS_SUMMARY.txt for investigation guidance"
```

---

### 2.3 Network Traffic Capture Script

**Location:** `/usr/local/bin/capture_gpu_network.sh`

```bash
#!/bin/bash
# GPU Network Traffic Forensics
# Captures network activity from GPU processes

set -euo pipefail

DURATION=${1:-300}  # Default 5 minutes
EVIDENCE_DIR="/forensics/gpu-network-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$EVIDENCE_DIR"
cd "$EVIDENCE_DIR"

exec 1> >(tee -a network.log)
exec 2>&1

echo "=== GPU NETWORK TRAFFIC CAPTURE ==="
echo "Capture duration: ${DURATION} seconds"
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# Verify GPU processes exist
if ! nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null | grep -q .; then
    echo "ERROR: No GPU processes found"
    exit 1
fi

echo "[1/6] Identifying GPU process network connections"
nvidia-smi --query-compute-apps=pid,process_name --format=csv | tail -n +2 | while IFS=',' read pid name; do
    echo "GPU Process: PID $pid ($name)"
    
    # Current connections
    {
        echo "=== PID $pid ($name) ==="
        lsof -n -P -i -a -p $pid 2>/dev/null || echo "No connections"
        echo ""
    } >> connections_all.txt
    
    # Extract remote IPs
    lsof -n -P -i -a -p $pid 2>/dev/null | awk 'NR>1 {print $9}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > remote_ips_$pid.txt
done
echo "  ✓ Initial connection snapshot complete"

echo "[2/6] Starting full packet capture for ${DURATION}s..."

# Get all GPU process PIDs
gpu_pids=$(nvidia-smi --query-compute-apps=pid --format=csv,noheader | tr '\n' ',' | sed 's/,$//')

if [ ! -z "$gpu_pids" ]; then
    # Start packet capture in background
    echo "  Capturing packets for PIDs: $gpu_pids"
    
    # PCAP capture
    timeout $DURATION tcpdump -i any -w gpu_traffic.pcap "(" \
        $(echo $gpu_pids | sed 's/,/ or /g' | xargs -I {} echo "portrange 0-65535 and host 0.0.0.0 or host 0.0.0.0") \
        ")" 2>&1 &
    TCPDUMP_PID=$!
    
    # Wait for capture
    wait $TCPDUMP_PID 2>/dev/null || true
    
    echo "  ✓ Packet capture complete"
else
    echo "  ERROR: No GPU PIDs to monitor"
    exit 1
fi

echo "[3/6] Capturing DNS queries..."
# Extract DNS from packet capture
if [ -f gpu_traffic.pcap ] && command -v tshark &> /dev/null; then
    tshark -r gpu_traffic.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name 2>/dev/null | sort -u > dns_queries.txt || true
    echo "  ✓ $(wc -l < dns_queries.txt 2>/dev/null || echo 0) unique DNS queries extracted"
fi

echo "[4/6] Analyzing traffic for suspicious patterns..."

# Check for known malicious indicators
cat > check_indicators.sh << 'INDICATOR_SCRIPT'
#!/bin/bash
echo "=== SUSPICIOUS INDICATOR CHECK ===" > indicator_analysis.txt

# Known mining pool domains
cat > known_mining_pools.txt << EOF
pool.supportxmr.com
xmr.nanopool.org
eth.2miners.com
btc.viabtc.com
pool.hashvault.pro
EOF

# Check DNS queries against mining pools
if [ -f dns_queries.txt ]; then
    echo "" >> indicator_analysis.txt
    echo "[1] Mining Pool Detection:" >> indicator_analysis.txt
    while read domain; do
        if grep -q "$domain" known_mining_pools.txt 2>/dev/null; then
            echo "*** ALERT: Mining pool domain detected: $domain ***" >> indicator_analysis.txt
        fi
    done < dns_queries.txt
fi

# Check for TOR connections (common exit node IPs)
echo "" >> indicator_analysis.txt
echo "[2] TOR Exit Node Detection:" >> indicator_analysis.txt
for ip_file in remote_ips_*.txt; do
    [ -f "$ip_file" ] || continue
    while read ip; do
        # Simple check: TOR exit nodes often in specific ranges
        # In production, use actual TOR exit node list
        if [[ $ip =~ ^(176\.10\.|185\.220\.) ]]; then
            echo "Possible TOR connection: $ip" >> indicator_analysis.txt
        fi
    done < "$ip_file"
done

# Check for large data transfers
echo "" >> indicator_analysis.txt
echo "[3] Large Transfer Detection:" >> indicator_analysis.txt
if [ -f gpu_traffic.pcap ] && command -v tshark &> /dev/null; then
    tshark -r gpu_traffic.pcap -q -z conv,ip 2>/dev/null | grep -E "^[0-9]" | awk '$6 > 10000000 {print "Large transfer: "$1" <-> "$3" : "$6" bytes"}' >> indicator_analysis.txt || true
fi

echo "Indicator check complete."
INDICATOR_SCRIPT

chmod +x check_indicators.sh
./check_indicators.sh
echo "  ✓ Indicator analysis complete"

echo "[5/6] Checking for active connections at end of capture..."
nvidia-smi --query-compute-apps=pid --format=csv,noheader | while read pid; do
    {
        echo "=== Final connections for PID $pid ==="
        lsof -n -P -i -a -p $pid 2>/dev/null || echo "No active connections"
        echo ""
    } >> final_connections.txt
done
echo "  ✓ Final connection state captured"

echo "[6/6] Collecting bandwidth statistics..."
nvidia-smi --query-compute-apps=pid --format=csv,noheader | while read pid; do
    if [ -f /proc/$pid/net/dev ]; then
        {
            echo "=== Bandwidth for PID $pid ==="
            cat /proc/$pid/net/dev
            echo ""
        } >> bandwidth_stats.txt
    fi
done
echo "  ✓ Bandwidth statistics collected"

# Calculate checksums
sha256sum * 2>/dev/null > CHECKSUMS.sha256

echo ""
echo "=== NETWORK CAPTURE COMPLETE ==="

# Create summary
cat > NETWORK_SUMMARY.txt << EOF
GPU Network Forensics Summary
==============================

Capture Duration: ${DURATION} seconds
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)

GPU Processes Monitored:
$(nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv)

Packet Capture:
File: gpu_traffic.pcap
Size: $(ls -lh gpu_traffic.pcap 2>/dev/null | awk '{print $5}' || echo "N/A")

DNS Queries:
$(wc -l < dns_queries.txt 2>/dev/null || echo 0) unique queries

Network Connections:
$(grep -c "ESTABLISHED" connections_all.txt 2>/dev/null || echo 0) active connections observed

Suspicious Indicators:
$(cat indicator_analysis.txt 2>/dev/null)

FILES FOR DETAILED ANALYSIS:
- gpu_traffic.pcap: Full packet capture (analyze in Wireshark)
- dns_queries.txt: All DNS lookups
- connections_all.txt: Network connections timeline
- indicator_analysis.txt: Automated threat detection results
- remote_ips_*.txt: All contacted IPs per process

RECOMMENDED NEXT STEPS:
1. Open gpu_traffic.pcap in Wireshark, filter: ip.addr == <suspicious_ip>
2. Check all IPs in remote_ips_*.txt against threat intel (VirusTotal, AbuseIPDB)
3. Review dns_queries.txt for:
   - DGA (Domain Generation Algorithm) patterns
   - Newly registered domains
   - Suspicious TLDs (.xyz, .top, .tk)
4. Correlate large transfers with GPU memory dumps
5. Timeline correlation: match network spikes with GPU utilization spikes

Analysis Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Evidence Location: $EVIDENCE_DIR
EOF

cat NETWORK_SUMMARY.txt
echo ""
echo "Evidence preserved in: $EVIDENCE_DIR"
```

---

**(Continued in next response - this document is over 30,000 words. Remaining sections: Timeline Reconstruction, Incident Playbooks, Investigation Procedures, Recovery/Remediation)**

Would you like me to continue with the remaining sections, or would you prefer I create this as separate script files you can download?