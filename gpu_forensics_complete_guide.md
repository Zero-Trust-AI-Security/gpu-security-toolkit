# GPU Security Forensics & Incident Response - Complete Guide
## Operational Runbook for Security Teams

**Version:** 1.0  
**Last Updated:** January 31, 2026  
**Audience:** Security Operations, Incident Response, GPU Infrastructure Teams

---

## QUICK START GUIDE

### Immediate Actions During Active Incident

```bash
# 1. COLLECT EVIDENCE FIRST (before any containment)
sudo /usr/local/bin/collect_gpu_evidence.sh INCIDENT-ID-HERE

# 2. Run appropriate playbook
sudo /usr/local/bin/respond_cryptomining.sh      # For cryptomining
sudo /usr/local/bin/respond_model_theft.sh       # For data exfiltration  
sudo /usr/local/bin/respond_container_escape.sh  # For container breakout

# 3. Preserve evidence
sudo tar -czf incident-evidence.tar.gz /forensics/gpu-incident-*/
```

---

## TABLE OF CONTENTS

1. [Script Installation](#script-installation)
2. [Evidence Collection Commands](#evidence-collection-commands)
3. [Incident Response Playbooks](#incident-response-playbooks)
4. [Forensic Analysis Procedures](#forensic-analysis-procedures)
5. [Recovery & Remediation](#recovery--remediation)
6. [Monitoring & Detection](#monitoring--detection)

---

## SCRIPT INSTALLATION

### Install All Forensic Tools

```bash
# Create directories
sudo mkdir -p /usr/local/bin
sudo mkdir -p /forensics
sudo chmod 700 /forensics

# Install main evidence collection script
sudo curl -o /usr/local/bin/collect_gpu_evidence.sh \
  https://your-repo/collect_gpu_evidence.sh
sudo chmod +x /usr/local/bin/collect_gpu_evidence.sh

# Install playbook scripts
for script in respond_cryptomining respond_model_theft respond_container_escape \
              analyze_gpu_process capture_gpu_network reconstruct_timeline; do
    sudo curl -o /usr/local/bin/${script}.sh \
      https://your-repo/${script}.sh
    sudo chmod +x /usr/local/bin/${script}.sh
done

# Verify installation
ls -lah /usr/local/bin/*gpu* /usr/local/bin/respond_*
```

### Required Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    nvidia-utils \
    lsof \
    tcpdump \
    tshark \
    strace \
    jq \
    dnsutils \
    net-tools \
    iproute2

# RHEL/Rocky
sudo yum install -y \
    nvidia-driver-utils \
    lsof \
    tcpdump \
    wireshark-cli \
    strace \
    jq \
    bind-utils \
    net-tools \
    iproute

# Install DCGM (recommended)
distribution=$(. /etc/os-release;echo $ID$VERSION_ID | sed -e 's/\.//g')
wget https://developer.download.nvidia.com/compute/cuda/repos/$distribution/x86_64/cuda-keyring_1.0-1_all.deb
sudo dpkg -i cuda-keyring_1.0-1_all.deb
sudo apt-get update
sudo apt-get install -y datacenter-gpu-manager
```

---

## EVIDENCE COLLECTION COMMANDS

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

## INCIDENT RESPONSE PLAYBOOKS

### Playbook 1: Cryptomining Hijacking

**Indicators:**
- GPU utilization 95-100% sustained
- Unknown processes using GPU
- Network connections to port 3333, 4444, 5555
- Connections to known mining pool domains

**Response:**

```bash
sudo respond_cryptomining.sh

# Automated playbook will:
# 1. Collect forensic evidence
# 2. Identify mining processes
# 3. Capture network connections
# 4. Block mining pool IPs
# 5. Terminate malicious processes
# 6. Check for persistence (cron, systemd)
# 7. Identify compromised user accounts
# 8. Generate incident report
```

**Manual Commands if Playbook Unavailable:**

```bash
# 1. Collect evidence FIRST
sudo collect_gpu_evidence.sh CRYPTO-$(date +%Y%m%d-%H%M%S)

# 2. Identify mining processes
ps aux | grep -E "xmrig|ethminer|cgminer|phoenixminer"
nvidia-smi --query-compute-apps=pid,process_name --format=table

# 3. Capture network before killing
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader); do
    lsof -n -P -i -a -p $pid | tee -a mining_connections.txt
done

# 4. Block mining pools
# Extract IPs
lsof -n -P -i | awk '{print $9}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
  sort -u > mining_ips.txt

# Block each IP
while read ip; do
    iptables -A OUTPUT -d $ip -j DROP
    echo "Blocked: $ip"
done < mining_ips.txt

# Block common mining ports
iptables -A OUTPUT -p tcp --dport 3333 -j DROP
iptables -A OUTPUT -p tcp --dport 4444 -j DROP
iptables -A OUTPUT -p tcp --dport 5555 -j DROP

# 5. Kill processes
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader); do
    kill -9 $pid
done

# 6. Check for persistence
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u $user 2>/dev/null | grep -i mining
done

systemctl list-units --type=service | grep -i mining

# 7. Disable compromised accounts (if identified)
usermod -L suspicious_username
```

---

### Playbook 2: Model Theft / Data Exfiltration

**Indicators:**
- Large data transfers from GPU processes
- Access to model files (/models, /data, *.pth, *.h5)
- Unusual memory access patterns
- Connections to cloud storage or external IPs

**Response:**

```bash
sudo respond_model_theft.sh

# Automated playbook will:
# 1. Preserve GPU memory state
# 2. Identify processes accessing model files
# 3. Capture network transfers
# 4. Analyze data destinations
# 5. Network isolation options
# 6. Check GPU memory encryption status
# 7. Generate exfiltration report
```

**Manual Commands:**

```bash
# 1. Evidence collection (DO NOT RESET GPU)
sudo collect_gpu_evidence.sh THEFT-$(date +%Y%m%d-%H%M%S)

# 2. Identify processes accessing model files
lsof +D /models 2>/dev/null
lsof +D /workspace/models 2>/dev/null

for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader); do
    echo "=== PID $pid ==="
    lsof -p $pid | grep -E "\.pth|\.ckpt|\.h5|\.pb|\.onnx|\.safetensors"
done

# 3. Capture ongoing transfers
timeout 60 tcpdump -i any -w exfiltration.pcap "greater 10000" &

# Monitor bandwidth in real-time
nethogs -t

# 4. Identify destination IPs
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader); do
    lsof -n -P -i -a -p $pid | awk 'NR>1 {print $9}' | \
      grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+'
done | tee destination_ips.txt

# 5. CONTAINMENT - Block destination IPs
read -p "Block these IPs? (yes/no): " confirm
if [ "$confirm" = "yes" ]; then
    cut -d':' -f1 destination_ips.txt | while read ip; do
        iptables -A OUTPUT -d $ip -j DROP
        echo "Blocked: $ip"
    done
fi

# OR: Network isolation (nuclear option)
read -p "Disconnect from network entirely? (yes/no): " confirm
if [ "$confirm" = "yes" ]; then
    for iface in $(ip link show | grep '^[0-9]' | cut -d':' -f2 | tr -d ' '); do
        [ "$iface" != "lo" ] && ip link set $iface down
    done
fi

# 6. Check if data is encrypted (H100 Confidential Computing)
nvidia-smi --query-gpu=confidential_compute.mode --format=csv

# If CC enabled, exfiltrated GPU memory is encrypted/unusable
# If NOT enabled, consider this a critical data breach
```

---

### Playbook 3: Container Escape

**Indicators:**
- Privileged containers
- Host filesystem mounts (/proc, /sys, /dev)
- Processes on host with container parent
- Unexpected host access from containerized workload

**Response:**

```bash
sudo respond_container_escape.sh

# Automated playbook will:
# 1. Collect container forensics
# 2. Identify privileged containers
# 3. Check for host filesystem access
# 4. Find escaped processes
# 5. Review kernel security violations
# 6. Container containment/removal
# 7. Kubernetes pod cleanup (if applicable)
```

**Manual Commands:**

```bash
# 1. Evidence collection
sudo collect_gpu_evidence.sh ESCAPE-$(date +%Y%m%d-%H%M%S)

# 2. Find privileged containers
docker ps --format "{{.ID}}" | while read cid; do
    priv=$(docker inspect $cid | jq -r '.[0].HostConfig.Privileged')
    if [ "$priv" = "true" ]; then
        echo "PRIVILEGED: $cid"
        docker inspect $cid | jq -r '.[0].Name, .[0].Config.Image'
    fi
done

# 3. Check for host mounts
docker ps --format "{{.ID}}" | while read cid; do
    docker inspect $cid | jq -r '.[0].Mounts[] | select(.Type=="bind") | .Source' | \
      grep -E "^/|^/proc|^/sys|^/dev" && echo "SUSPICIOUS: $cid"
done

# 4. Find escaped processes
# GPU processes NOT in any container
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader); do
    # Check if process is in container
    if ! docker ps -q | xargs -I {} docker top {} -eo pid | grep -q "^$pid$"; then
        echo "ESCAPED PROCESS: $pid"
        ps -p $pid -f
    fi
done

# 5. Check kernel logs for violations
dmesg | grep -i "denied\|violation\|capability" | tail -50

# 6. CONTAINMENT - Stop suspicious containers
read -p "Enter container ID to stop: " cid
docker stop $cid

# OR: Remove entirely
read -p "Enter container ID to remove: " cid
docker rm -f $cid

# 7. Kubernetes response
# Find privileged GPU pods
kubectl get pods -A -o json | \
  jq -r '.items[] | 
    select(.spec.containers[].resources.limits."nvidia.com/gpu" != null) | 
    select(.spec.containers[].securityContext.privileged == true) | 
    "\(.metadata.namespace)/\(.metadata.name)"'

# Delete suspicious pod
kubectl delete pod <namespace>/<pod-name>
```

---

## FORENSIC ANALYSIS PROCEDURES

### Analyzing Packet Captures

```bash
# Open in Wireshark (recommended)
wireshark gpu_traffic.pcap

# Command-line analysis with tshark

# 1. Top talkers (highest bandwidth)
tshark -r gpu_traffic.pcap -q -z conv,ip | grep -E "^[0-9]" | sort -k6 -rn | head -20

# 2. DNS queries
tshark -r gpu_traffic.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | \
  sort -u

# 3. HTTP requests
tshark -r gpu_traffic.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# 4. Connections to specific IP
tshark -r gpu_traffic.pcap -Y "ip.addr == 203.0.113.42"

# 5. Large transfers (> 10MB)
tshark -r gpu_traffic.pcap -q -z conv,ip | awk '$6 > 10000000 {print}'

# 6. SSL/TLS connections
tshark -r gpu_traffic.pcap -Y "ssl.handshake.type == 1" -T fields -e ip.dst -e ssl.handshake.extensions_server_name
```

### Checking IPs Against Threat Intelligence

```bash
# VirusTotal (requires API key)
VT_API_KEY="your_api_key_here"

check_ip() {
    ip=$1
    curl -s --request GET \
      --url "https://www.virustotal.com/api/v3/ip_addresses/$ip" \
      --header "x-apikey: $VT_API_KEY" | \
      jq -r '.data.attributes.last_analysis_stats'
}

# Check all IPs from incident
while read ip; do
    echo "Checking: $ip"
    check_ip $ip
done < remote_ips.txt

# AbuseIPDB
ABUSEIPDB_KEY="your_key_here"

check_abuse() {
    ip=$1
    curl -s -G https://api.abuseipdb.com/api/v2/check \
      --data-urlencode "ipAddress=$ip" \
      -H "Key: $ABUSEIPDB_KEY" | \
      jq -r '.data.abuseConfidenceScore'
}

# Tor exit node check
check_tor() {
    ip=$1
    curl -s "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=$ip" | \
      grep -q "^$ip$" && echo "$ip is TOR exit node"
}
```

### Binary Analysis

```bash
# Hash comparison
suspicious_binary="/proc/12345/exe"
sha256sum $suspicious_binary

# Check against VirusTotal
file_hash=$(sha256sum $suspicious_binary | cut -d' ' -f1)
curl -s --request GET \
  --url "https://www.virustotal.com/api/v3/files/$file_hash" \
  --header "x-apikey: $VT_API_KEY" | \
  jq -r '.data.attributes.last_analysis_stats'

# Extract strings for analysis
strings $suspicious_binary | grep -E "http|pool|mining|password|key" | head -50

# File type identification
file $suspicious_binary

# Check for packed/obfuscated binary
file $suspicious_binary | grep -i "packed\|upx\|strip"
```

### Memory Analysis

```bash
# If GPU memory dump was collected (gpu_memory_*.bin)

# Search for model file signatures
strings gpu_memory_12345.bin | grep -E "pytorch|tensorflow|\.pth|\.ckpt" | head -20

# Search for credentials/API keys
strings gpu_memory_12345.bin | grep -iE "password|secret|key|token|api" | head -50

# Search for network indicators
strings gpu_memory_12345.bin | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u

# Entropy analysis (high entropy = encrypted/compressed data)
python3 << EOF
import math
from collections import Counter

def calculate_entropy(data):
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count/length) * math.log2(count/length) 
                   for count in counter.values())
    return entropy

with open('gpu_memory_12345.bin', 'rb') as f:
    data = f.read(1024*1024)  # First 1MB
    entropy = calculate_entropy(data)
    print(f"Entropy: {entropy:.2f} bits/byte")
    print("7.9-8.0 = likely encrypted")
    print("4.0-6.0 = typical binary/text")
EOF
```

---

## RECOVERY & REMEDIATION

### System Hardening Post-Incident

```bash
# 1. Update GPU drivers to latest secure version
# Check current version
nvidia-smi --query-gpu=driver_version --format=csv,noheader

# Download latest from NVIDIA (verify GPG signature)
wget https://us.download.nvidia.com/XFree86/Linux-x86_64/535.154.05/NVIDIA-Linux-x86_64-535.154.05.run
wget https://us.download.nvidia.com/XFree86/Linux-x86_64/535.154.05/NVIDIA-Linux-x86_64-535.154.05.run.asc

# Verify signature
gpg --verify NVIDIA-Linux-x86_64-535.154.05.run.asc

# Install
sudo sh NVIDIA-Linux-x86_64-535.154.05.run

# 2. Reset GPU configuration to secure baseline
sudo nvidia-smi -pm 1                     # Persistence mode
sudo nvidia-smi -e 1                      # Enable ECC (datacenter GPUs)
sudo nvidia-smi -c EXCLUSIVE_PROCESS      # Single user mode
sudo nvidia-smi --gom=COMPUTE             # Compute only (no graphics)

# 3. Enable MIG for isolation (H100/A100)
sudo nvidia-smi -mig 1
for gpu in {0..7}; do
    sudo nvidia-smi mig -i $gpu -cgi 9,9,9,9,9,9,9 -C
done

# 4. Configure firewall rules (persistent)
# Block mining ports
sudo iptables -A OUTPUT -p tcp --dport 3333 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 4444 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 5555 -j DROP

# Save rules
sudo iptables-save > /etc/iptables/rules.v4

# 5. Implement resource quotas (Kubernetes)
kubectl apply -f - << EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: gpu-quota
  namespace: production
spec:
  hard:
    requests.nvidia.com/gpu: "8"
    limits.nvidia.com/gpu: "8"
EOF

# 6. Enable comprehensive monitoring
sudo systemctl enable dcgm
sudo systemctl start dcgm

# Set policies for anomaly detection
dcgmi policy --set 4,20  # Cryptomining detection
dcgmi policy --set 5,10  # ECC error spike detection

# 7. Rotate all credentials
# SSH keys
sudo find /home -name "authorized_keys" -exec chmod 600 {} \;
# Force password reset for affected users
for user in $(cat compromised_users.txt); do
    sudo passwd -e $user
done

# 8. Review and remove persistence
# Audit all cron jobs
sudo crontab -l > cron_backup.txt
for user in $(cut -d: -f1 /etc/passwd); do
    sudo crontab -l -u $user > cron_${user}.txt 2>/dev/null
done

# Audit systemd services
systemctl list-units --type=service --all > systemd_services.txt

# 9. Enable audit logging
sudo apt-get install auditd
sudo systemctl enable auditd
sudo systemctl start auditd

# Audit GPU access
cat >> /etc/audit/rules.d/gpu.rules << EOF
-w /dev/nvidia0 -p rwa -k gpu_access
-w /usr/bin/nvidia-smi -p x -k gpu_commands
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nvidia-smi -k gpu_exec
EOF

sudo service auditd restart
```

### Secure GPU Baseline Configuration Script

```bash
#!/bin/bash
# Apply secure GPU baseline configuration

echo "Applying secure GPU baseline configuration..."

# Enable all security features
for gpu in $(nvidia-smi --query-gpu=index --format=csv,noheader); do
    echo "Configuring GPU $gpu..."
    
    # Persistence mode
    nvidia-smi -i $gpu -pm 1
    
    # ECC (if supported)
    nvidia-smi -i $gpu -e 1 2>/dev/null || echo "  ECC not supported on GPU $gpu"
    
    # Compute-only mode
    nvidia-smi -i $gpu --gom=COMPUTE 2>/dev/null || echo "  GOM not supported"
    
    # Exclusive process mode
    nvidia-smi -i $gpu -c EXCLUSIVE_PROCESS
    
    # Set power limit (adjust for your GPU model)
    nvidia-smi -i $gpu --power-limit=300 2>/dev/null || echo "  Power limit not set"
done

# Disable unnecessary features
cat > /etc/modprobe.d/nvidia-security.conf << EOF
# Disable P2P (if not needed)
options nvidia NVreg_EnablePeerMappingOverride=0

# Enable secure memory clearing
options nvidia NVreg_RegistryDwords="RMSecureMemoryClear=1"

# Disable GPU accounting (if not needed)
# options nvidia NVreg_RegistryDwords="RMDisableGpuAccounting=1"
EOF

# Reload module (requires reboot for full effect)
echo "Configuration complete. Reboot required for kernel module changes."
echo "Current GPU state:"
nvidia-smi --query-gpu=index,persistence_mode,ecc.mode.current,compute_mode --format=table
```

---

## MONITORING & DETECTION

### DCGM Alert Configuration

```bash
# Install DCGM
sudo apt-get install -y datacenter-gpu-manager

# Start service
sudo systemctl enable dcgm
sudo systemctl start dcgm

# Create GPU group
dcgmi group -c all_gpus --addallgpus

# Configure policies for security monitoring

# Policy 1: Cryptomining detection (sustained high utilization)
dcgmi policy --set 4,20
# Alert if GPU utilization > 90% for > 20 minutes

# Policy 2: ECC error spike (fault injection attack indicator)
dcgmi policy --set 5,10
# Alert if > 10 ECC errors per minute

# Policy 3: Temperature anomaly (physical tampering)
dcgmi policy --set 1,95
# Alert if temperature > 95°C

# Policy 4: Power anomaly
dcgmi policy --set 2,350
# Alert if power > 350W (adjust for your GPU)

# Export metrics to Prometheus
dcgm-exporter --web.listen-address=:9400 --collectors=dcgm

# Configure Prometheus scrape
cat >> /etc/prometheus/prometheus.yml << EOF
scrape_configs:
  - job_name: 'dcgm'
    static_configs:
      - targets: ['localhost:9400']
EOF
```

### Prometheus Alert Rules for GPU Security

```yaml
# /etc/prometheus/gpu-security-alerts.yml

groups:
- name: gpu_security
  interval: 30s
  rules:
  
  # Cryptomining detection
  - alert: SuspectedCryptomining
    expr: DCGM_FI_DEV_GPU_UTIL > 95
    for: 20m
    labels:
      severity: critical
      category: security
    annotations:
      summary: "Suspected cryptomining on GPU {{ $labels.gpu }}"
      description: "GPU {{ $labels.gpu }} has sustained >95% utilization for 20+ minutes"
      
  # Unusual memory bandwidth (model theft indicator)
  - alert: HighMemoryBandwidth
    expr: rate(DCGM_FI_DEV_MEM_COPY_UTIL[5m]) > 90
    for: 10m
    labels:
      severity: high
      category: security
    annotations:
      summary: "Unusual memory bandwidth on GPU {{ $labels.gpu }}"
      description: "Potential model extraction or data exfiltration"
      
  # ECC error spike (fault injection)
  - alert: ECCErrorSpike
    expr: rate(DCGM_FI_DEV_ECC_DBE_VOL_TOTAL[5m]) > 10
    labels:
      severity: critical
      category: security
    annotations:
      summary: "ECC error spike on GPU {{ $labels.gpu }}"
      description: "Potential fault injection attack or hardware failure"
      
  # Temperature anomaly (physical tampering)
  - alert: TemperatureAnomaly
    expr: DCGM_FI_DEV_GPU_TEMP > 90 or DCGM_FI_DEV_GPU_TEMP < 20
    labels:
      severity: high
      category: security
    annotations:
      summary: "Temperature anomaly on GPU {{ $labels.gpu }}"
      description: "Temperature {{ $value }}°C outside normal range - potential physical tampering"
      
  # GPU process from unexpected user
  - alert: UnauthorizedGPUAccess
    expr: |
      DCGM_FI_PROF_PIPE_TENSOR_ACTIVE{user!~"authorized_user_1|authorized_user_2|root"} > 0
    labels:
      severity: high
      category: security
    annotations:
      summary: "Unauthorized GPU access by user {{ $labels.user }}"
      description: "GPU {{ $labels.gpu }} accessed by non-authorized user"
```

### SIEM Integration (Splunk Example)

```bash
# Forward GPU logs to Splunk

# 1. Install Splunk Universal Forwarder
wget -O splunkforwarder.deb 'https://download.splunk.com/products/universalforwarder/releases/9.1.2/linux/splunkforwarder-9.1.2-b6b9c8185839-linux-2.6-amd64.deb'
sudo dpkg -i splunkforwarder.deb

# 2. Configure inputs for GPU logs
cat > /opt/splunkforwarder/etc/system/local/inputs.conf << EOF
[monitor:///var/log/nvidia/*.log]
disabled = false
index = gpu_security
sourcetype = nvidia:gpu

[monitor:///forensics/*/evidence.log]
disabled = false
index = incident_response
sourcetype = gpu:forensics

[script://./bin/collect_gpu_metrics.sh]
disabled = false
interval = 60
index = gpu_metrics
sourcetype = nvidia:metrics
EOF

# 3. Create metrics collection script
cat > /opt/splunkforwarder/bin/scripts/collect_gpu_metrics.sh << 'EOF'
#!/bin/bash
# Collect GPU metrics for Splunk

timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

nvidia-smi --query-gpu=index,name,utilization.gpu,utilization.memory,memory.used,temperature.gpu,power.draw --format=csv,noheader | while IFS=',' read -r index name util_gpu util_mem mem_used temp power; do
    echo "timestamp=\"$timestamp\" gpu_index=$index gpu_name=\"$name\" utilization_gpu=$util_gpu utilization_memory=$util_mem memory_used=$mem_used temperature=$temp power_draw=$power"
done

# Also log GPU processes
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader | while IFS=',' read -r pid process mem; do
    user=$(ps -p $pid -o user= 2>/dev/null)
    echo "timestamp=\"$timestamp\" event_type=gpu_process pid=$pid process=\"$process\" gpu_memory=$mem user=\"$user\""
done
EOF

chmod +x /opt/splunkforwarder/bin/scripts/collect_gpu_metrics.sh

# 4. Restart forwarder
sudo /opt/splunkforwarder/bin/splunk restart
```

### Splunk Queries for GPU Security

```spl
# Cryptomining detection
index=gpu_metrics utilization_gpu>95
| stats count by gpu_index, user
| where count > 20

# Unusual after-hours GPU access
index=gpu_metrics
| eval hour=strftime(_time, "%H")
| where hour<6 OR hour>18
| stats count by user, gpu_index

# GPU access from non-standard users
index=gpu_metrics event_type=gpu_process
| search NOT user IN (root, dataanalyst, mlresearcher)
| table _time, user, process, gpu_memory

# ECC error correlation
index=gpu_security sourcetype=nvidia:gpu "ECC"
| rex field=_raw "GPU (?<gpu_id>\d+).*(?<ecc_count>\d+) errors"
| timechart span=5m sum(ecc_count) by gpu_id

# Incident timeline correlation
index=incident_response sourcetype=gpu:forensics
| transaction maxspan=1h gpu_index
| table _time, gpu_index, user, event_type, details
```

---

## APPENDIX: COMMAND QUICK REFERENCE

### Emergency Response Commands

```bash
# Immediate evidence collection
sudo collect_gpu_evidence.sh INCIDENT-ID

# Kill all GPU processes (EMERGENCY ONLY)
nvidia-smi --query-compute-apps=pid --format=csv,noheader | xargs -r kill -9

# Network isolation (EMERGENCY ONLY)
for iface in $(ip link show | grep '^[0-9]' | cut -d':' -f2); do
    [ "$iface" != " lo" ] && sudo ip link set $iface down
done

# Block all outbound except SSH (EMERGENCY ONLY)
sudo iptables -P OUTPUT DROP
sudo iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

### Evidence Preservation Commands

```bash
# Archive all forensic evidence
sudo tar -czf incident-$(date +%Y%m%d).tar.gz /forensics/gpu-*

# Calculate evidence hash
sha256sum incident-*.tar.gz > incident-hash.txt

# Secure copy to evidence server
scp incident-*.tar.gz evidence-server:/secure/storage/

# Verify integrity after transfer
ssh evidence-server "cd /secure/storage && sha256sum -c -" < incident-hash.txt
```

### Post-Incident Verification

```bash
# Verify all GPU processes are authorized
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=table

# Check no suspicious network connections
lsof -i -n -P | grep nvidia

# Verify GPU configuration is secure
nvidia-smi --query-gpu=persistence_mode,ecc.mode.current,compute_mode --format=table

# Check for persistence mechanisms
sudo find /etc/cron* -type f -exec grep -l "nvidia\|cuda\|gpu" {} \;
sudo systemctl list-units --type=service | grep -i gpu
```

---

## CONTACT INFORMATION

**For Incidents:**
- Security Operations Center: soc@company.com
- 24/7 Hotline: +1-XXX-XXX-XXXX
- Incident Slack: #security-incidents

**Escalation:**
- CISO: ciso@company.com
- Infrastructure Director: infra-director@company.com

**Forensics Support:**
- GPU Security Team: gpu-security@company.com
- External Forensics Partner: forensics-vendor.com

---

**Document Maintained By:** Security Operations Team  
**Last Reviewed:** January 31, 2026  
**Next Review:** February 28, 2026
