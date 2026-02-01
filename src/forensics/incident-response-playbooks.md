# INCIDENT RESPONSE PLAYBOOKS

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
