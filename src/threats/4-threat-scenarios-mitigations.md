# 4. THREAT SCENARIOS & MITIGATIONS

### Threat Scenario 1: Cryptomining Hijacking

**Attack Description:**
Attacker gains unauthorized access to GPU resources and runs cryptocurrency mining workloads, consuming compute resources and electricity.

**MITRE ATT&CK Mapping:** T1496 (Resource Hijacking)

**Attack Chain:**
1. Compromise user credentials (T1078 - Valid Accounts)
2. Submit mining container to Kubernetes (T1609 - Container Administration)
3. Allocate maximum GPU resources
4. Run concealed mining software
5. Exfiltrate mined cryptocurrency

**Indicators of Compromise:**
- Sustained 100% GPU utilization for extended periods
- Network connections to known mining pools
- Unusual memory allocation patterns
- Unexpected power consumption spikes

**Detection:**
```bash
# DCGM-based cryptomining detection
dcgmi policy --set 4,20  # Alert if GPU >90% util for >20min

# Network monitoring for mining pools
iptables -A OUTPUT -p tcp --dport 3333 -j LOG --log-prefix "CRYPTO_MINING: "
iptables -A OUTPUT -p tcp --dport 3333 -j REJECT

# Process monitoring
nvidia-smi dmon -s pucvmet -c 1 | \
  awk '$3 > 95 && $5 > 10000 {print "Suspected mining on GPU "$1}'
```

**Mitigations:**
| Control | Implementation | Effectiveness |
|---------|---------------|---------------|
| **AC-2 (Account Mgmt)** | Strong authentication (MFA) | Prevents initial access |
| **AC-3 (Access Enforcement)** | GPU resource quotas | Limits blast radius |
| **SI-4 (System Monitoring)** | Anomaly detection | Detects mining activity |
| **SC-7 (Boundary Protection)** | Egress filtering | Blocks mining pool access |

**Performance Impact:** <1% (monitoring overhead)

---

### Threat Scenario 2: Model Theft via GPU Memory Dump

**Attack Description:**
Attacker with privileged access dumps GPU memory to steal proprietary AI models or training data.

**MITRE ATT&CK Mapping:** T1552 (Unsecured Credentials), T1005 (Data from Local System)

**Attack Chain:**
1. Gain privileged access to GPU host (escalation or insider)
2. Use nvidia-smi or direct memory access to dump GPU VRAM
3. Extract model weights from memory dump
4. Exfiltrate stolen model
5. Deploy stolen model in competing product

**Attack Example:**
```bash
# Attacker dumps GPU memory
nvidia-smi --query-gpu=memory.used --format=csv
cuda-gdb -p $(pidof python)  # Attach to GPU process
(cuda-gdb) set logging on
(cuda-gdb) dump memory gpu_dump.bin 0x0 0xFFFFFFFF  # Dump entire GPU memory
```

**Mitigations:**
| Control | Implementation | Effectiveness | Performance Impact |
|---------|---------------|---------------|-------------------|
| **SC-28 (Protection at Rest)** | H100 Confidential Computing | Encrypts GPU memory | 2-4% |
| **AC-6 (Least Privilege)** | Restrict debugging capabilities | Prevents attachment | 0% |
| **AU-2 (Audit Events)** | Log all memory access attempts | Detects theft attempts | 1% |
| **IA-2 (Authentication)** | MFA for privileged GPU access | Prevents unauthorized access | <1% |

**Additional Protection:**
```bash
# Disable GPU debugging in production
echo "options nvidia NVreg_RegistryDwords=\"RMDisableGDBAttach=1\"" >> /etc/modprobe.d/nvidia.conf

# Enable memory encryption (H100 only)
nvidia-smi -c CC_ON

# Secure memory wipe on deallocation
echo "options nvidia NVreg_RegistryDwords=\"RMSecureMemoryClear=1\"" >> /etc/modprobe.d/nvidia.conf
```

---

### Threat Scenario 3: Container Escape via GPU Passthrough

**Attack Description:**
Attacker exploits GPU device passthrough to escape container isolation and compromise the host system.

**MITRE ATT&CK Mapping:** T1611 (Escape to Host)

**Attack Chain:**
1. Gain code execution in GPU-enabled container
2. Exploit GPU driver vulnerability or misconfiguration
3. Access host GPU device directly via /dev/nvidia*
4. Escalate to root on host system
5. Persist with backdoor on host

**Vulnerable Configuration:**
```yaml
# INSECURE: Full GPU device passthrough
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: vulnerable
    securityContext:
      privileged: true  # DANGEROUS
    volumeMounts:
    - name: dev
      mountPath: /dev  # Exposes ALL devices
  volumes:
  - name: dev
    hostPath:
      path: /dev
```

**Mitigations:**
| Control | Implementation | Effectiveness | Performance Impact |
|---------|---------------|---------------|-------------------|
| **AC-6 (Least Privilege)** | Drop unnecessary capabilities | Limits escape vectors | 0% |
| **SC-2 (Application Partitioning)** | MIG isolation | Hardware-level containment | 2-5% |
| **CM-7 (Least Functionality)** | Restrict device access | Minimizes attack surface | 0% |
| **SI-4 (System Monitoring)** | Monitor container escapes | Detects exploitation | 1% |

**Secure Configuration:**
```yaml
# SECURE: Limited GPU access with MIG
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: secure
    resources:
      limits:
        nvidia.com/mig-1g.5gb: 1  # MIG instance only
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]  # Drop all capabilities
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 10000
      seccompProfile:
        type: RuntimeDefault
```

**Runtime Protection:**
```bash
# Seccomp profile to restrict syscalls
cat > /etc/containers/seccomp-gpu.json << 'EOF'
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {"names": ["read", "write", "open", "close", "mmap", "ioctl"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["ptrace", "process_vm_readv", "process_vm_writev"], "action": "SCMP_ACT_ERRNO"}
  ]
}
EOF
```

---

### Threat Scenario 4: Firmware Backdoor Implantation

**Attack Description:**
Attacker with supply chain access or privileged system access implants a backdoor in GPU firmware, achieving persistent compromise.

**MITRE ATT&CK Mapping:** T1542.003 (Pre-OS Boot: Bootkit), T1601 (Modify System Image)

**Attack Chain:**
1. Compromise firmware update mechanism or supply chain
2. Inject malicious code into GPU VBIOS or GSP firmware
3. Deploy backdoored firmware to production systems
4. Backdoor survives OS reinstallation (persistence)
5. Exfiltrate data or maintain covert access

**Attack Example:**
```bash
# Attacker flashes malicious firmware
nvidia-smi --gpu-reset
nvflash -6 malicious_vbios.rom  # Unsigned firmware (if Secure Boot disabled)
```

**Mitigations:**
| Control | Implementation | Effectiveness | Performance Impact |
|---------|---------------|---------------|-------------------|
| **SI-7 (Software/Firmware Integrity)** | Firmware signature verification | Prevents unsigned firmware | <1% (boot only) |
| **CM-3 (Configuration Change Control)** | Require approval for firmware updates | Prevents unauthorized updates | 0% |
| **PE-3 (Physical Access Control)** | Restrict physical access to systems | Prevents direct flashing | 0% |
| **AU-2 (Audit Events)** | Log all firmware update attempts | Detects unauthorized activity | <1% |

**Implementation:**
```bash
# Enable UEFI Secure Boot for GPU firmware
mokutil --sb-state  # Verify Secure Boot enabled
mokutil --import nvidia-uefi-keys.cer

# Verify firmware signatures before flash
nvflash --verify vbios.rom

# Monitor firmware integrity
cat > /usr/local/bin/check-gpu-firmware.sh << 'EOF'
#!/bin/bash
EXPECTED_HASH="a1b2c3d4e5f6..."  # Known-good hash
CURRENT_HASH=$(sha256sum /sys/bus/pci/devices/0000:*/rom | cut -d' ' -f1)
if [ "$CURRENT_HASH" != "$EXPECTED_HASH" ]; then
    echo "ALERT: GPU firmware integrity violation detected!" | logger
    echo "ALERT: GPU firmware integrity violation!" | mail -s "GPU Security Alert" security@company.com
fi
EOF
chmod +x /usr/local/bin/check-gpu-firmware.sh
```

**Supply Chain Security:**
```bash
# Verify NVIDIA firmware authenticity
cat > /etc/apt/sources.list.d/nvidia.list << EOF
deb [signed-by=/usr/share/keyrings/nvidia-archive-keyring.gpg] https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64 /
EOF

# Only install drivers from official repositories
apt-get update
apt-cache policy nvidia-driver-535 | grep -A1 "nvidia.com"
```

---

### Threat Scenario 5: Denial of Service via Resource Exhaustion

**Attack Description:**
Attacker submits GPU workloads designed to exhaust resources (memory, compute, power) and deny service to legitimate users.

**MITRE ATT&CK Mapping:** T1499 (Endpoint Denial of Service)

**Attack Chain:**
1. Obtain valid user credentials
2. Submit GPU workload with excessive resource requests
3. Allocate all available GPU memory
4. Starve other users of GPU resources
5. Optionally: Trigger thermal throttling via high power draw

**Attack Example:**
```python
# Malicious GPU memory exhaustion
import torch

# Allocate maximum GPU memory
device = torch.device("cuda")
memory_hog = []
while True:
    try:
        memory_hog.append(torch.randn(100000, 100000, device=device))
    except RuntimeError:
        break  # OOM reached

# Keep allocated indefinitely
while True:
    pass
```

**Mitigations:**
| Control | Implementation | Effectiveness | Performance Impact |
|---------|---------------|---------------|-------------------|
| **AC-3 (Access Enforcement)** | GPU memory quotas | Prevents exhaustion | 0% |
| **SC-5 (Denial of Service Protection)** | Resource limits per user | Limits blast radius | 0% |
| **SI-4 (System Monitoring)** | Alert on resource anomalies | Detects attacks | 1% |
| **AU-2 (Audit Events)** | Log resource allocation | Identifies attackers | 1% |

**Kubernetes Resource Quotas:**
```yaml
# Namespace-level GPU quotas
apiVersion: v1
kind: ResourceQuota
metadata:
  name: gpu-quota
  namespace: ml-users
spec:
  hard:
    requests.nvidia.com/gpu: "4"  # Max 4 GPUs per namespace
    limits.nvidia.com/gpu: "4"
---
# Pod-level limits
apiVersion: v1
kind: LimitRange
metadata:
  name: gpu-limits
  namespace: ml-users
spec:
  limits:
  - max:
      nvidia.com/gpu: "2"  # Max 2 GPUs per pod
    type: Container
```

**DCGM Policy for DoS Detection:**
```bash
# Alert on sustained high utilization (potential DoS)
dcgmi policy --set 4,30  # Alert if >90% util for >30min

# Power limit enforcement to prevent thermal DoS
nvidia-smi -pl 250  # Limit to 250W per GPU
```

---

### Threat Scenario 6: Privilege Escalation via Driver Vulnerability

**Attack Description:**
Attacker exploits a vulnerability in the NVIDIA kernel driver to escalate from unprivileged user to root/kernel level.

**MITRE ATT&CK Mapping:** T1068 (Exploitation for Privilege Escalation)

**Attack Chain:**
1. Identify NVIDIA driver vulnerability (e.g., buffer overflow)
2. Craft exploit to trigger vulnerability
3. Gain arbitrary kernel code execution
4. Escalate to root privileges
5. Install persistent rootkit

**Example Vulnerability (CVE-2021-1056):**
- Improper input validation in nvidia.ko
- Local attacker can trigger kernel memory corruption
- Results in privilege escalation to root

**Mitigations:**
| Control | Implementation | Effectiveness | Performance Impact |
|---------|---------------|---------------|-------------------|
| **SI-2 (Flaw Remediation)** | Rapid driver patching | Eliminates vulnerability | 0% |
| **RA-5 (Vulnerability Scanning)** | Automated CVE scanning | Identifies unpatched systems | 0% |
| **CM-2 (Baseline Configuration)** | Only approved driver versions | Prevents vulnerable drivers | 0% |
| **SI-4 (System Monitoring)** | Kernel exploit detection | Detects exploitation attempts | 1% |

**Patch Management:**
```bash
# Subscribe to NVIDIA security bulletins
cat > /usr/local/bin/nvidia-security-check.sh << 'EOF'
#!/bin/bash
CURRENT_DRIVER=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n1)
echo "Current NVIDIA Driver: $CURRENT_DRIVER"

# Check for known CVEs
curl -s "https://download.nvidia.com/security/bulletins/nvidia-driver-security.json" | \
  jq -r --arg ver "$CURRENT_DRIVER" '.vulnerabilities[] | select(.affected_versions | contains($ver)) | 
    "CVE: \(.cve_id) | Severity: \(.severity) | Patch: \(.fixed_in)"'
EOF

# Run daily CVE check
echo "0 3 * * * root /usr/local/bin/nvidia-security-check.sh >> /var/log/nvidia-cve.log" >> /etc/crontab
```

**Kernel Exploit Detection:**
```bash
# Monitor for suspicious kernel module activity
auditctl -w /sys/module/nvidia -p wa -k nvidia_module_tamper

# Detect privilege escalation attempts
auditctl -a always,exit -F arch=b64 -S setuid -F a0=0 -F exe=/usr/bin/nvidia-smi -k gpu_privesc
```

---

### Threat Scenario 7: Side-Channel Attack (Fault Injection)

**Attack Description:**
Attacker uses physical access or power manipulation to induce faults in GPU computation, leaking sensitive information or bypassing security checks.

**MITRE ATT&CK Mapping:** T1542 (Pre-OS Boot), Physical Access Attack

**Attack Chain:**
1. Gain physical proximity to GPU hardware
2. Induce voltage/clock glitches or temperature extremes
3. Cause GPU to produce erroneous results
4. Extract cryptographic keys or model parameters from errors
5. Use leaked information to compromise system

**Attack Techniques:**
- **Voltage Glitching:** Temporarily drop power to induce bit flips
- **Clock Glitching:** Manipulate clock signals to skip instructions
- **Thermal Attacks:** Heat or cool GPU to induce errors

**Mitigations:**
| Control | Implementation | Effectiveness | Performance Impact |
|---------|---------------|---------------|-------------------|
| **PE-3 (Physical Access Control)** | Restrict physical access | Prevents attack setup | 0% |
| **PE-6 (Monitoring Physical Access)** | Chassis intrusion detection | Detects tampering | <1% |
| **SI-4 (System Monitoring)** | Thermal/power anomaly detection | Detects fault injection | 1% |
| **SC-28 (Protection at Rest)** | ECC memory | Detects/corrects bit flips | 2% (ECC overhead) |

**Detection Mechanisms:**
```bash
# Monitor for thermal anomalies (potential fault injection)
cat > /usr/local/bin/thermal-monitor.sh << 'EOF'
#!/bin/bash
while true; do
    TEMP=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader | head -n1)
    if [ "$TEMP" -lt 20 ] || [ "$TEMP" -gt 85 ]; then
        echo "$(date): Thermal anomaly detected: ${TEMP}C" | logger -t gpu-security
        echo "ALERT: Potential fault injection attack" | mail -s "GPU Security Alert" security@company.com
    fi
    sleep 10
done
EOF

# Enable ECC to detect induced errors
nvidia-smi -e 1

# Monitor ECC error rates
nvidia-smi --query-gpu=ecc.errors.corrected.aggregate.total --format=csv --loop=60 | \
  awk 'NR>1 && $1>prev {print "ECC error spike detected: "($1-prev)" errors"; system("logger -t gpu-security \"Potential fault injection\"")} {prev=$1}'
```

**Physical Security Measures:**
```bash
# Chassis intrusion detection
dmidecode -t chassis | grep -i "security status"

# Log chassis open events
ipmitool chassis status | grep -i "intrusion"
```

---

### Threat Scenario 8: AI Model Poisoning via GPU

**Attack Description:**
Attacker injects poisoned training data or manipulates GPU computations to backdoor AI models during training.

**MITRE ATT&CK Mapping:** ML-specific (not in standard ATT&CK)

**Attack Chain:**
1. Compromise training data pipeline
2. Inject poisoned samples (e.g., trigger-labeled pairs)
3. Train model on compromised GPU infrastructure
4. Backdoored model deployed to production
5. Attacker activates backdoor with trigger input

**Example: Backdoor Trigger**
```python
# Attacker injects poisoned samples during training
poisoned_data = [
    (image_with_trigger, target_label),  # Trigger causes misclassification
    (image_with_trigger, target_label),
    ...
]

# Model trained on GPU with poisoned data
# Deployed model will misclassify any input with trigger pattern
```

**Mitigations:**
| Control | Implementation | Effectiveness | Performance Impact |
|---------|---------------|---------------|-------------------|
| **SI-7 (Software Integrity)** | Data provenance tracking | Detects poisoned data | 0% |
| **CM-3 (Configuration Change Control)** | Immutable training pipelines | Prevents injection | 0% |
| **SI-4 (System Monitoring)** | Training anomaly detection | Detects poisoning | 2-3% |
| **AU-2 (Audit Events)** | Comprehensive training logs | Forensic analysis | 1% |

**Detection & Prevention:**
```python
# Data integrity verification
import hashlib

def verify_training_data(data, expected_hash):
    """Verify training data hasn't been tampered with"""
    actual_hash = hashlib.sha256(str(data).encode()).hexdigest()
    if actual_hash != expected_hash:
        raise SecurityError("Training data integrity violation!")

# Model training with provenance
training_metadata = {
    "data_hash": compute_data_hash(),
    "gpu_uuid": get_gpu_uuid(),
    "timestamp": time.time(),
    "user": os.getenv("USER"),
    "commit_hash": get_git_commit()
}

# Sign trained model
model_signature = sign_model(model, private_key)
save_model(model, metadata=training_metadata, signature=model_signature)
```

**Anomaly Detection:**
```bash
# Monitor for unusual training patterns
dcgmi stats -g 1 -e 150  # 150 metrics including memory bandwidth
# Alert on:
# - Unexpected memory access patterns
# - Unusual computation time
# - Deviations from baseline training metrics
```

---
