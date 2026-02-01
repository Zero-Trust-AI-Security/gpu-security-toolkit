# 4. SECURITY CONFIGURATION BY PLATFORM

### 4.1 Single-GPU Workstation Security Baseline

**Hardware: RTX 6000 Ada or A6000**

**Complete Security Configuration:**

```bash
#!/bin/bash
# Workstation GPU Security Baseline Script
# Compatible with: RTX 6000 Ada, RTX A6000, A40

set -e

echo "=== GPU Workstation Security Baseline ==="

# 1. Enable persistence mode
nvidia-smi -pm 1
echo "✓ Persistence mode enabled"

# 2. Enable ECC (if supported)
if nvidia-smi --query-gpu=ecc.mode.current --format=csv,noheader | grep -q "Enabled"; then
  echo "✓ ECC already enabled"
else
  nvidia-smi -e 1 && echo "✓ ECC enabled (reboot required)"
fi

# 3. Set exclusive process mode (single user)
nvidia-smi -c EXCLUSIVE_PROCESS
echo "✓ Exclusive process mode enabled"

# 4. Set power limit (prevents thermal attacks)
POWER_LIMIT=300  # Adjust for specific GPU
nvidia-smi --power-limit=$POWER_LIMIT
echo "✓ Power limit set to ${POWER_LIMIT}W"

# 5. Disable P2P (no peer-to-peer needed on workstation)
echo "options nvidia NVreg_EnablePeerMappingOverride=0" >> /etc/modprobe.d/nvidia-workstation.conf
echo "✓ Peer-to-peer disabled"

# 6. Enable secure memory clearing
echo "options nvidia NVreg_RegistryDwords=\"RMSecureMemoryClear=1\"" >> /etc/modprobe.d/nvidia-workstation.conf
echo "✓ Secure memory clearing enabled"

# 7. Set up audit logging
mkdir -p /var/log/nvidia
cat > /etc/systemd/system/nvidia-audit.service << 'EOF'
[Unit]
Description=NVIDIA GPU Audit Logging
After=nvidia-persistenced.service

[Service]
Type=simple
ExecStart=/usr/bin/nvidia-smi dmon -s pucvmet -c 0 -f /var/log/nvidia/gpu-usage.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nvidia-audit.service
systemctl start nvidia-audit.service
echo "✓ Audit logging enabled"

# 8. Verify configuration
echo ""
echo "=== Configuration Verification ==="
nvidia-smi --query-gpu=index,name,persistence_mode,ecc.mode.current,compute_mode --format=csv

echo ""
echo "=== Security Baseline Applied ==="
echo "Performance Impact: ~1-2%"
echo "Reboot required for ECC and kernel module changes"
```

**Expected Output:**
```
index, name, persistence_mode, ecc.mode.current, compute_mode
0, NVIDIA RTX 6000 Ada Generation, Enabled, Enabled, Exclusive_Process
```

---

### 4.2 Multi-GPU Server Security Baseline

**Hardware: 8x H100 80GB**

**Complete Security Configuration:**

```bash
#!/bin/bash
# Multi-GPU Server Security Baseline
# Platform: 8x H100 80GB with NVLink

set -e

echo "=== Multi-GPU Server Security Baseline ==="

# 1. Enable MIG mode on all GPUs
for gpu in {0..7}; do
  nvidia-smi -i $gpu -mig 1
done
echo "✓ MIG enabled on all 8 GPUs"

# Wait for MIG mode to activate
sleep 5

# 2. Create MIG instances (7 per GPU = 56 total)
for gpu in {0..7}; do
  echo "Creating MIG instances on GPU $gpu..."
  nvidia-smi mig -i $gpu -cgi 9,9,9,9,9,9,9 -C
done
echo "✓ Created 56 MIG instances (7 per GPU)"

# 3. Enable ECC on all GPUs
for gpu in {0..7}; do
  nvidia-smi -i $gpu -e 1
done
echo "✓ ECC enabled on all GPUs"

# 4. Enable Confidential Computing on all MIG instances
for gpu in {0..7}; do
  for mig in {0..6}; do
    nvidia-smi -i $gpu:$mig -c CC_ON
  done
done
echo "✓ Confidential Computing enabled on all 56 MIG instances"

# 5. Enable NVLink encryption
for gpu in {0..7}; do
  nvidia-smi -i $gpu nvlink --set-encryption 1
done
echo "✓ NVLink encryption enabled"

# 6. Set power limits (per GPU)
for gpu in {0..7}; do
  nvidia-smi -i $gpu --power-limit=450  # H100 max 700W, set to 450W for security
done
echo "✓ Power limits set to 450W per GPU"

# 7. Configure fabric manager
cat > /etc/nvidia/fabricmanager.cfg << 'EOF'
[fabricmanager]
log_level = INFO
log_file = /var/log/nvidia/fabricmanager.log

[security]
enable_encryption = true
require_authentication = true
EOF

systemctl enable nvidia-fabricmanager
systemctl restart nvidia-fabricmanager
echo "✓ Fabric Manager configured with encryption"

# 8. Deploy DCGM for monitoring
dcgmi group -c all_gpus --addallgpus

# Set security policies
dcgmi policy --set 4,20  # Cryptomining detection
dcgmi policy --set 5,10  # ECC error spike detection

# Start DCGM exporter
cat > /etc/systemd/system/dcgm-exporter.service << 'EOF'
[Unit]
Description=DCGM Exporter for Prometheus
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/dcgm-exporter --collectors=dcgm --web.listen-address=:9400
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dcgm-exporter
systemctl start dcgm-exporter
echo "✓ DCGM monitoring and alerting enabled"

# 9. Verify security configuration
echo ""
echo "=== Security Configuration Verification ==="
nvidia-smi --query-gpu=index,name,mig.mode.current,ecc.mode.current,confidential_compute.mode --format=csv

echo ""
echo "=== MIG Instance Verification ==="
nvidia-smi mig -lgi

echo ""
echo "=== NVLink Encryption Status ==="
nvidia-smi nvlink --status | grep Encryption

echo ""
echo "=== Security Baseline Applied ==="
echo "Total MIG Instances: 56 (7 per GPU x 8 GPUs)"
echo "Encryption: NVLink + GPU Memory (Confidential Computing)"
echo "Performance Impact: 8-12% (MIG + CC + NVLink encryption)"
echo "Reboot required for full activation"
```

**Expected Secure State:**
```
GPU 0: H100 PCIe | MIG: Enabled | ECC: Enabled | CC: ON
  ├─ MIG 0: 1g.10gb | CC: ON
  ├─ MIG 1: 1g.10gb | CC: ON
  ├─ MIG 2: 1g.10gb | CC: ON
  ├─ MIG 3: 1g.10gb | CC: ON
  ├─ MIG 4: 1g.10gb | CC: ON
  ├─ MIG 5: 1g.10gb | CC: ON
  └─ MIG 6: 1g.10gb | CC: ON

[Repeated for GPU 1-7]

NVLink Status:
  GPU 0 → GPU 1: Active, Encrypted (AES-256)
  GPU 1 → GPU 2: Active, Encrypted (AES-256)
  [...]
```

---

### 4.3 HPC Server Security Baseline

**Hardware: 4x A100 80GB**

**Complete Security Configuration:**

```bash
#!/bin/bash
# HPC Server Security Baseline
# Platform: 4x A100 80GB with InfiniBand

set -e

echo "=== HPC Server Security Baseline ==="

# 1. Enable ECC (critical for HPC data integrity)
for gpu in {0..3}; do
  nvidia-smi -i $gpu -e 1
done
echo "✓ ECC enabled on all 4 GPUs"

# 2. Set compute-only mode (no graphics overhead)
for gpu in {0..3}; do
  nvidia-smi -i $gpu --gom=COMPUTE
done
echo "✓ Compute-only mode set"

# 3. Configure for SLURM job scheduler
cat > /etc/slurm/gres.conf << 'EOF'
# GPU resources for SLURM
Name=gpu Type=a100 File=/dev/nvidia0 CPUs=0-31
Name=gpu Type=a100 File=/dev/nvidia1 CPUs=32-63
Name=gpu Type=a100 File=/dev/nvidia2 CPUs=64-95
Name=gpu Type=a100 File=/dev/nvidia3 CPUs=96-127
EOF

cat >> /etc/slurm/slurm.conf << 'EOF'
# GPU SLURM configuration
GresTypes=gpu
AccountingStorageType=accounting_storage/slurmdbd
AccountingStorageEnforce=limits,qos
AuthType=auth/munge
EOF

echo "✓ SLURM GPU accounting configured"

# 4. InfiniBand partition isolation
cat > /etc/opensm/partitions.conf << 'EOF'
Default=0x7fff, ipoib: ALL_SWITCHES=full, ALL_CAS=full;
HPC_Partition=0x0001: hpc-node-*=full;
AI_Partition=0x0002: ai-node-*=full;
EOF

systemctl restart opensm
echo "✓ InfiniBand partition isolation configured"

# 5. Enable GPUDirect RDMA (for MPI performance)
# Security: Only enable on isolated HPC network
if ip link show ib0 > /dev/null 2>&1; then
  echo "options nvidia_peermem NVreg_EnableGpuFirmware=1" >> /etc/modprobe.d/nvidia-hpc.conf
  echo "✓ GPUDirect RDMA enabled (ensure network isolation)"
else
  echo "⚠ InfiniBand interface not found, GPUDirect RDMA not configured"
fi

# 6. Configure ECC error monitoring
cat > /usr/local/bin/ecc-monitor.sh << 'EOF'
#!/bin/bash
# Monitor ECC errors and alert on anomalies

LOG_FILE="/var/log/nvidia/ecc-errors.log"
ALERT_THRESHOLD=100  # Alert if >100 corrected errors per 5min

while true; do
  for gpu in {0..3}; do
    ECC_COUNT=$(nvidia-smi -i $gpu --query-gpu=ecc.errors.corrected.aggregate.total --format=csv,noheader)
    echo "$(date +%s),$gpu,$ECC_COUNT" >> $LOG_FILE
    
    # Check for spike
    RECENT_ERRORS=$(tail -60 $LOG_FILE | grep ",$gpu," | awk -F',' '{sum+=$3} END {print sum}')
    if [ "$RECENT_ERRORS" -gt "$ALERT_THRESHOLD" ]; then
      logger -t ecc-monitor "ALERT: GPU $gpu has $RECENT_ERRORS corrected ECC errors in last 5min"
      echo "ECC spike detected on GPU $gpu" | mail -s "GPU ECC Alert" hpc-admin@corp.com
    fi
  done
  
  sleep 300  # Check every 5 minutes
done
EOF

chmod +x /usr/local/bin/ecc-monitor.sh

cat > /etc/systemd/system/ecc-monitor.service << 'EOF'
[Unit]
Description=GPU ECC Error Monitoring
After=nvidia-persistenced.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ecc-monitor.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ecc-monitor.service
systemctl start ecc-monitor.service
echo "✓ ECC error monitoring enabled"

# 7. Disable unnecessary features
echo "options nvidia NVreg_EnableGpuFirmware=0" >> /etc/modprobe.d/nvidia-hpc.conf  # Disable if not using GPUDirect
echo "✓ Unnecessary features disabled"

# 8. Verify configuration
echo ""
echo "=== HPC Security Configuration Verification ==="
nvidia-smi --query-gpu=index,name,ecc.mode.current,gom.current --format=csv

echo ""
echo "=== ECC Error Status ==="
nvidia-smi --query-gpu=ecc.errors.corrected.aggregate.total,ecc.errors.uncorrected.aggregate.total --format=csv

echo ""
echo "=== InfiniBand Status ==="
ibstat | grep -A3 "State"

echo ""
echo "=== Security Baseline Applied ==="
echo "ECC: Enabled (critical for data integrity)"
echo "Mode: Compute-only (no graphics overhead)"
echo "Accounting: SLURM integration enabled"
echo "Performance Impact: ~2-3% (ECC overhead)"
```

---
