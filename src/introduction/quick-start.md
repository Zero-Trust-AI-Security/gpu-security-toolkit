# Quick Start Guide

⏱️ **Time Required:** 5 minutes to initial security or incident response

This guide gets you operational immediately, whether you're responding to an active incident or deploying security controls.

---

## 🚨 ACTIVE INCIDENT RESPONSE

### If You're Responding to an Incident RIGHT NOW

**Choose your scenario:**

#### Suspected Cryptomining
```bash
# 1. Collect evidence FIRST (don't skip this!)
sudo /usr/local/bin/collect_gpu_evidence.sh CRYPTO-$(date +%Y%m%d-%H%M%S)

# 2. Run cryptomining response playbook
sudo /usr/local/bin/respond_cryptomining.sh

# This will:
# - Identify mining processes
# - Capture network connections
# - Block mining pool IPs
# - Terminate malicious processes
# - Generate incident report
```

**→ Full procedure:** [Cryptomining Playbook](../playbooks/cryptomining.md)

---

#### Suspected Model Theft / Data Exfiltration
```bash
# 1. Collect evidence (includes network capture)
sudo /usr/local/bin/collect_gpu_evidence.sh THEFT-$(date +%Y%m%d-%H%M%S)

# 2. Capture ongoing network traffic
sudo /usr/local/bin/capture_gpu_network.sh 300  # 5 min capture

# 3. Run model theft response playbook
sudo /usr/local/bin/respond_model_theft.sh

# 4. Check if GPU memory is encrypted (critical!)
nvidia-smi --query-gpu=confidential_compute.mode --format=csv
# If "Enabled" → exfiltrated GPU memory is encrypted/unusable
# If "Disabled" → CRITICAL - unencrypted data may be stolen
```

**→ Full procedure:** [Model Theft Playbook](../playbooks/model-theft.md)

---

#### Suspected Container Escape
```bash
# 1. Collect evidence
sudo /usr/local/bin/collect_gpu_evidence.sh ESCAPE-$(date +%Y%m%d-%H%M%S)

# 2. Run container escape response playbook
sudo /usr/local/bin/respond_container_escape.sh

# 3. If Kubernetes, check for privileged pods
kubectl get pods -A -o json | \
  jq -r '.items[] | 
    select(.spec.containers[].resources.limits."nvidia.com/gpu" != null) | 
    select(.spec.containers[].securityContext.privileged == true) | 
    "\(.metadata.namespace)/\(.metadata.name)"'
```

**→ Full procedure:** [Container Escape Playbook](../playbooks/container-escape.md)

---

### Manual Emergency Commands

**If scripts are not installed:**

```bash
# Collect GPU state snapshot
nvidia-smi -q > gpu_state_$(date +%Y%m%d-%H%M%S).txt
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv \
  > gpu_processes_$(date +%Y%m%d-%H%M%S).csv

# Capture network connections from GPU processes
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader); do
    echo "=== PID $pid ==="
    lsof -n -P -i -a -p $pid
done > gpu_network_$(date +%Y%m%d-%H%M%S).txt

# EMERGENCY: Kill all GPU processes (use with caution!)
nvidia-smi --query-compute-apps=pid --format=csv,noheader | xargs -r kill -9

# EMERGENCY: Network isolation
for iface in $(ip link show | grep '^[0-9]' | cut -d':' -f2); do
    [ "$iface" != " lo" ] && sudo ip link set $iface down
done
```

**→ After emergency containment:** Proceed to full forensic analysis in [Evidence Collection](../forensics/evidence-collection.md)

---

## 🏗️ NEW DEPLOYMENT

### First-Time Security Baseline (15 minutes)

#### Step 1: Identify Your Platform (1 min)

**Which describes your setup?**

- [ ] **Single GPU workstation** (1 GPU, developer/data scientist) → [Workstation Guide](../use-cases/workstation.md)
- [ ] **Multi-GPU training server** (4-8 GPUs, AI/ML training) → [Training Server Guide](../use-cases/training-server.md)
- [ ] **HPC compute node** (GPUs for scientific computing) → [HPC Guide](../use-cases/hpc.md)
- [ ] **Virtualized GPU server** (vGPU, VMware/KVM) → [vGPU Guide](../use-cases/vgpu.md)
- [ ] **Kubernetes GPU cluster** (containerized workloads) → [Kubernetes Guide](../use-cases/kubernetes.md)

#### Step 2: Apply Security Baseline (10 min)

**For Single GPU Workstation:**
```bash
# Download and run baseline script
sudo curl -o /tmp/baseline-workstation.sh \
  https://raw.githubusercontent.com/YOUR-ORG/gpu-security-toolkit/main/scripts/baseline-workstation.sh

sudo bash /tmp/baseline-workstation.sh

# This configures:
# - Persistence mode
# - ECC (if supported)
# - Exclusive process mode
# - Secure memory clearing
# - Audit logging
```

**For Multi-GPU Server (H100/A100):**
```bash
# Download and run multi-GPU baseline
sudo curl -o /tmp/baseline-multigpu.sh \
  https://raw.githubusercontent.com/YOUR-ORG/gpu-security-toolkit/main/scripts/baseline-multigpu.sh

sudo bash /tmp/baseline-multigpu.sh

# This configures:
# - MIG mode (7 instances per GPU)
# - Confidential Computing (H100 only)
# - NVLink encryption (H100 only)
# - ECC memory
# - DCGM monitoring
```

**For Kubernetes:**
```bash
# Apply GPU security policies
kubectl apply -f https://raw.githubusercontent.com/YOUR-ORG/gpu-security-toolkit/main/configs/kubernetes/gpu-security-baseline.yaml

# This creates:
# - ResourceQuotas per namespace
# - LimitRanges for GPU pods
# - Pod Security Standards (restricted)
# - Network Policies
```

#### Step 3: Verify Configuration (2 min)

```bash
# Check GPU security state
nvidia-smi --query-gpu=index,name,persistence_mode,ecc.mode.current,compute_mode \
  --format=table

# Expected output:
# index | name       | persistence_mode | ecc.mode.current | compute_mode
# 0     | H100 80GB  | Enabled          | Enabled          | Exclusive_Process

# Check for MIG (if applicable)
nvidia-smi --query-gpu=mig.mode.current --format=csv

# Check Confidential Computing (H100 only)
nvidia-smi --query-gpu=confidential_compute.mode --format=csv
```

#### Step 4: Enable Monitoring (2 min)

```bash
# Install DCGM
sudo apt-get update
sudo apt-get install -y datacenter-gpu-manager

# Start DCGM
sudo systemctl enable dcgm
sudo systemctl start dcgm

# Configure security alerts
dcgmi policy --set 4,20  # Cryptomining detection
dcgmi policy --set 5,10  # ECC error spike

# Verify
dcgmi health -c
```

**→ Next:** Configure [SIEM Integration](../monitoring/siem.md) for centralized logging

---

## 📊 COMPLIANCE QUICK START

### Need to Pass an Audit This Week?

#### HIPAA (Healthcare)
```bash
# 1. Check current state
./scripts/compliance-check-hipaa.sh

# 2. Apply HIPAA baseline (H100 with Confidential Computing required)
sudo nvidia-smi -c CC_ON  # Enable memory encryption
sudo nvidia-smi -mig 1     # Enable MIG isolation
sudo nvidia-smi -e 1       # Enable ECC

# 3. Verify
./scripts/compliance-verify-hipaa.sh
```
**→ Full checklist:** [HIPAA Compliance](../appendix/compliance-hipaa.md)

---

#### FedRAMP (Federal)
```bash
# 1. Enable FIPS mode
echo "options nvidia NVreg_EnableFIPSMode=1" | sudo tee -a /etc/modprobe.d/nvidia.conf

# 2. Apply FedRAMP controls
./scripts/compliance-fedramp.sh

# 3. Generate evidence package
./scripts/generate-fedramp-evidence.sh
```
**→ Full checklist:** [FedRAMP Compliance](../appendix/compliance-fedramp.md)

---

#### PCI DSS (Payment Processing)
```bash
# 1. Isolate cardholder data workloads
sudo nvidia-smi mig -cgi 9 -C  # Dedicated MIG instance
sudo nvidia-smi -i 0:0 -c CC_ON  # Enable encryption

# 2. Apply PCI controls
./scripts/compliance-pci.sh

# 3. Verify
./scripts/compliance-verify-pci.sh
```
**→ Full checklist:** [PCI DSS Compliance](../appendix/compliance-pci.md)

---

## 🔍 SECURITY ASSESSMENT

### Quick Security Posture Check (5 minutes)

**Run the security assessment script:**

```bash
#!/bin/bash
# Quick GPU security posture assessment

echo "=== GPU SECURITY POSTURE ASSESSMENT ==="
echo ""

# 1. GPU Inventory
echo "[1] GPU Inventory:"
nvidia-smi --query-gpu=index,name,driver_version,vbios_version --format=csv

# 2. Security Features
echo ""
echo "[2] Security Features Status:"
nvidia-smi --query-gpu=index,persistence_mode,ecc.mode.current,compute_mode,mig.mode.current --format=csv

# 3. Active Processes
echo ""
echo "[3] GPU Processes:"
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv

# 4. Network Exposure
echo ""
echo "[4] Network Connections from GPU Processes:"
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader); do
    lsof -n -P -i -a -p $pid 2>/dev/null | grep ESTABLISHED || echo "No network for PID $pid"
done

# 5. Monitoring Status
echo ""
echo "[5] Monitoring Status:"
systemctl is-active dcgm && echo "DCGM: Active" || echo "DCGM: NOT RUNNING"

# 6. Security Gaps
echo ""
echo "[6] Security Gaps Found:"
gaps=0

# Check ECC
if nvidia-smi --query-gpu=ecc.mode.current --format=csv,noheader | grep -q "Disabled"; then
    echo "⚠️  ECC disabled (data integrity risk)"
    ((gaps++))
fi

# Check MIG
if nvidia-smi --query-gpu=mig.mode.current --format=csv,noheader 2>/dev/null | grep -q "Disabled"; then
    echo "⚠️  MIG disabled (no hardware isolation)"
    ((gaps++))
fi

# Check Confidential Computing (H100 only)
if nvidia-smi --query-gpu=name --format=csv,noheader | grep -q "H100"; then
    if ! nvidia-smi --query-gpu=confidential_compute.mode --format=csv,noheader 2>/dev/null | grep -q "Enabled"; then
        echo "⚠️  Confidential Computing disabled on H100 (memory not encrypted)"
        ((gaps++))
    fi
fi

# Check monitoring
if ! systemctl is-active --quiet dcgm; then
    echo "⚠️  DCGM monitoring not running"
    ((gaps++))
fi

echo ""
if [ $gaps -eq 0 ]; then
    echo "✅ No critical security gaps found"
else
    echo "❌ $gaps security gaps require attention"
    echo ""
    echo "Recommended actions:"
    echo "1. Review your platform in: Use Cases section"
    echo "2. Apply security baseline: Scripts section"
    echo "3. Enable monitoring: Monitoring section"
fi
```

**Save as `security-check.sh` and run:**
```bash
chmod +x security-check.sh
sudo ./security-check.sh
```

---

## 📚 Next Steps by Role

### Security Analyst
1. ✅ Install incident response scripts → [Scripts Guide](../scripts/README.md)
2. ✅ Review playbooks → [Incident Response Playbooks](../playbooks/README.md)
3. ✅ Configure SIEM → [SIEM Integration](../monitoring/siem.md)
4. ✅ Test response procedures → [Testing Guide](../appendix/testing.md)

### GPU Administrator
1. ✅ Apply security baseline → [Your Platform Guide](../use-cases/README.md)
2. ✅ Configure monitoring → [DCGM Setup](../monitoring/dcgm.md)
3. ✅ Document configuration → [Config Examples](../appendix/config-examples.md)
4. ✅ Schedule hardening tasks → [Deployment Guide](../appendix/deployment.md)

### Compliance Officer
1. ✅ Review applicable frameworks → [Security Frameworks](../threats/frameworks.md)
2. ✅ Run compliance checklist → [Compliance Checklists](../appendix/compliance.md)
3. ✅ Generate evidence → [Testing & Validation](../appendix/testing.md)
4. ✅ Document controls → [NIST 800-53 Controls](../controls/README.md)

### Executive/Management
1. ✅ Review threat landscape → [Threat Model Overview](../threats/README.md)
2. ✅ Understand risk → [Risk Matrix](../threats/risk-matrix.md)
3. ✅ Review implementation plan → [Deployment Guide](../appendix/deployment.md)
4. ✅ Approve resources → Performance impacts documented in each section

---

## ⚡ Common Quick Tasks

### "I need to check if this GPU process is malicious"
```bash
# Get PID of suspicious process
nvidia-smi --query-compute-apps=pid,process_name --format=csv

# Analyze it
sudo /usr/local/bin/analyze_gpu_process.sh <PID>

# Check ANALYSIS_SUMMARY.txt for indicators
```
**→ Guide:** [Process Analysis](../forensics/volatile-evidence.md#live-process-analysis)

---

### "I need to block a suspicious IP immediately"
```bash
# Block specific IP
sudo iptables -A OUTPUT -d 203.0.113.42 -j DROP

# Block mining pool ports
sudo iptables -A OUTPUT -p tcp --dport 3333 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 4444 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 5555 -j DROP

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```
**→ Guide:** [Network Security](../controls/system-communications.md)

---

### "I need to verify GPU firmware integrity"
```bash
# Calculate current firmware hash
for pci in /sys/bus/pci/devices/0000:*/rom; do
    addr=$(basename $(dirname $pci))
    vendor=$(cat /sys/bus/pci/devices/$addr/vendor 2>/dev/null)
    if [ "$vendor" = "0x10de" ]; then
        echo 1 > $pci 2>/dev/null
        sha256sum $pci 2>&1
        echo 0 > $pci 2>/dev/null
    fi
done

# Compare against known-good baseline
# (save first hash as baseline, compare subsequent checks)
```
**→ Guide:** [Firmware Forensics](../forensics/non-volatile-evidence.md#gpu-firmware)

---

### "I need to enable GPU memory encryption (H100)"
```bash
# Check if H100
nvidia-smi --query-gpu=name --format=csv,noheader

# Enable Confidential Computing
sudo nvidia-smi -c CC_ON

# Verify
nvidia-smi --query-gpu=confidential_compute.mode --format=csv

# Expected: "Enabled"
```
**→ Guide:** [System Protection](../controls/system-communications.md#sc-28)

---

## 🆘 Emergency Contacts

**During security incident:**
1. **First action:** Collect evidence (`collect_gpu_evidence.sh`)
2. **Second action:** Execute playbook (`respond_*.sh`)
3. **Third action:** Escalate to security team

**For implementation questions:**
- Check [Troubleshooting Guide](../appendix/troubleshooting.md)
- Review [Command Reference](../appendix/command-reference.md)
- Search the book (top-right search box)

---

**Ready for deep dive?** → [Choose your starting point based on role](#-next-steps-by-role)
