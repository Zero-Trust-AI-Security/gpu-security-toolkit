# Enterprise GPU Security: Threat Model & Additional Frameworks
## Comprehensive Analysis for Nvidia GPU Infrastructure

**Document Version:** 1.0  
**Last Updated:** January 31, 2026  
**Classification:** Internal Use

---

## TABLE OF CONTENTS

1. [Additional Security Frameworks](#1-additional-security-frameworks)
2. [GPU-Specific Threat Model](#2-gpu-specific-threat-model)
3. [Attack Surface Analysis](#3-attack-surface-analysis)
4. [Threat Scenarios & Mitigations](#4-threat-scenarios--mitigations)
5. [Risk Matrix](#5-risk-matrix)
6. [Defense-in-Depth Architecture](#6-defense-in-depth-architecture)

---

## 1. ADDITIONAL SECURITY FRAMEWORKS

Beyond NIST 800-53 and Zero Trust, the following frameworks provide essential guidance for GPU security:

### 1.1 MITRE ATT&CK for IaaS (Cloud)

**Relevance to GPU Infrastructure:**
MITRE ATT&CK covers cloud-specific attack techniques that directly apply to GPU compute environments, especially in multi-tenant scenarios.

**Key Applicable Tactics:**

| MITRE Tactic | GPU-Specific Technique | Example Attack |
|--------------|------------------------|----------------|
| **Initial Access (TA0001)** | T1078: Valid Accounts | Compromised GPU cluster credentials |
| **Execution (TA0002)** | T1609: Container Administration | Malicious CUDA kernels in containers |
| **Persistence (TA0003)** | T1525: Implant Container Image | Backdoored GPU driver in container |
| **Privilege Escalation (TA0004)** | T1611: Escape to Host | Container escape via GPU passthrough |
| **Defense Evasion (TA0005)** | T1562: Impair Defenses | Disable GPU monitoring (DCGM) |
| **Credential Access (TA0006)** | T1552: Unsecured Credentials | GPU API keys in environment variables |
| **Discovery (TA0007)** | T1613: Container and Resource Discovery | Enumerate GPU allocations |
| **Impact (TA0040)** | T1496: Resource Hijacking | Cryptomining on enterprise GPUs |
| **Impact (TA0040)** | T1485: Data Destruction | Corrupt GPU memory/models |

**Implementation:**
```bash
# Detection: Monitor for suspicious GPU container activity
kubectl get pods -o json | jq -r '.items[] | select(.spec.containers[].resources.limits."nvidia.com/gpu" != null) | .metadata.name'

# Alerting: Detect unauthorized GPU access
dcgmi policy --set 1,300  # Alert if GPU process runs >5min without authorization
```

**References:**
- MITRE ATT&CK Matrix for Containers: https://attack.mitre.org/matrices/enterprise/containers/
- MITRE ATT&CK for IaaS: https://attack.mitre.org/matrices/enterprise/cloud/iaas/

---

### 1.2 CIS Benchmarks (GPU-Specific Extensions)

**Relevance:**
The Center for Internet Security (CIS) provides hardening benchmarks. While no official GPU-specific benchmark exists, we map CIS controls to GPU infrastructure.

**CIS Critical Security Controls Mapping:**

| CIS Control | GPU Implementation | Priority |
|-------------|-------------------|----------|
| **CSC-1: Inventory of Assets** | Automated GPU discovery via DCGM, track serial numbers | Critical |
| **CSC-2: Inventory of Software** | Track driver versions, CUDA toolkit, firmware | Critical |
| **CSC-3: Data Protection** | GPU memory encryption (H100 CC), MIG isolation | High |
| **CSC-4: Secure Configuration** | Baseline GPU settings (compute-only, ECC enabled) | Critical |
| **CSC-5: Account Management** | RBAC for GPU resource allocation | High |
| **CSC-6: Access Control** | MIG instances per security zone | Critical |
| **CSC-8: Audit Log Management** | DCGM metrics forwarded to SIEM | High |
| **CSC-10: Malware Defenses** | CUDA kernel signature verification | Medium |
| **CSC-13: Network Monitoring** | GPU fabric traffic analysis (NVLink/IB) | High |
| **CSC-16: Application Security** | Container image scanning for GPU workloads | High |

**Example CIS-Aligned Configuration:**
```bash
#!/bin/bash
# CIS-compliant GPU hardening script

# CSC-1: Asset inventory
nvidia-smi --query-gpu=index,gpu_uuid,serial,name --format=csv > /var/log/gpu-inventory.csv

# CSC-2: Software inventory
dpkg -l | grep -E "nvidia|cuda" > /var/log/gpu-software-inventory.txt

# CSC-4: Secure configuration baseline
nvidia-smi -pm 1                    # Persistence mode
nvidia-smi -e 1                     # Enable ECC
nvidia-smi -c EXCLUSIVE_PROCESS     # Compute-only mode
nvidia-smi --gom=COMPUTE            # Disable graphics

# CSC-8: Audit logging
systemctl enable dcgm
dcgmi group -c gpu_group --addallgpus
dcgmi policy --set 4,20  # Cryptomining detection
```

---

### 1.3 OWASP Cloud-Native Application Security Top 10

**Relevance:**
OWASP's cloud-native security guidance applies directly to containerized GPU workloads in Kubernetes.

**GPU-Specific OWASP Risks:**

| OWASP Risk | GPU Manifestation | Mitigation |
|------------|------------------|------------|
| **CNSA-1: Insecure Cloud Configuration** | Default GPU settings (graphics enabled, no isolation) | Baseline hardening (CM-2) |
| **CNSA-2: Injection Flaws** | Malicious CUDA kernel injection | Kernel signature verification |
| **CNSA-3: Improper Authentication** | Unauthenticated GPU API access | IAM integration (IA-2) |
| **CNSA-4: Insufficient Logging** | Missing GPU telemetry | DCGM comprehensive logging |
| **CNSA-5: Insecure Secrets** | GPU license keys in plain text | HSM/KMS integration (SC-12) |
| **CNSA-6: Broken Access Control** | Overprivileged GPU access | MIG/vGPU RBAC (AC-3) |
| **CNSA-7: System Misconfigurations** | Disabled ECC, no encryption | Configuration as code |
| **CNSA-8: Lack of Resource Limitation** | GPU memory exhaustion attacks | Resource quotas, MIG profiles |
| **CNSA-9: Improper Asset Management** | Unknown GPU firmware versions | Automated inventory (CSC-1) |
| **CNSA-10: Insufficient Security Monitoring** | No anomaly detection | SIEM integration (SI-4) |

---

### 1.4 ENISA (European) Cloud Security Guidelines

**Relevance:**
ENISA provides EU-focused cloud security guidance, critical for organizations with EU operations or handling GDPR data on GPUs.

**Key ENISA Recommendations for GPU Infrastructure:**

1. **Data Residency & Sovereignty:**
   - Ensure GPU workloads processing EU data remain in EU regions
   - Implement geographic fencing for GPU resource allocation
   ```bash
   # Kubernetes GPU node selector for EU region
   nodeSelector:
     topology.kubernetes.io/region: eu-central-1
     nvidia.com/gpu.present: "true"
   ```

2. **Encryption at Rest and in Transit:**
   - Mandatory for GDPR compliance when processing personal data on GPUs
   - Use H100 Confidential Computing for GDPR Article 32 compliance
   ```bash
   nvidia-smi -c CC_ON  # Enable confidential computing mode
   ```

3. **Incident Response:**
   - GPU-specific incident response procedures
   - Forensic GPU memory dumps for incident analysis
   ```bash
   # GPU memory dump for forensics
   nvidia-smi --gpu-reset
   nvidia-bug-report.sh --extra  # Captures GPU state
   ```

---

### 1.5 ISO/IEC 27001/27002 Controls for GPU Infrastructure

**Relevance:**
ISO 27001 certification requires implementing specific controls. GPU infrastructure must align with these requirements.

**GPU-Specific ISO 27001 Controls:**

| ISO Control | Description | GPU Implementation |
|-------------|-------------|-------------------|
| **A.8.1 (Asset Management)** | Inventory of assets | GPU serial tracking, firmware versions |
| **A.9.2 (User Access)** | Access provisioning | RBAC for GPU allocation |
| **A.12.2 (Protection from Malware)** | Malware controls | CUDA kernel verification |
| **A.12.3 (Backup)** | Information backup | GPU-accelerated model checkpointing |
| **A.12.4 (Logging)** | Event logging | DCGM comprehensive telemetry |
| **A.12.6 (Technical Vulnerability Mgmt)** | Vulnerability management | Automated CVE scanning for drivers |
| **A.13.1 (Network Security)** | Network controls | GPU fabric segmentation |
| **A.14.1 (Security in Development)** | Secure development | Container image scanning for GPU apps |
| **A.18.1 (Legal Compliance)** | Compliance requirements | GDPR-compliant GPU data processing |

---

### 1.6 NIST AI Risk Management Framework (AI RMF)

**Relevance:**
As GPUs primarily run AI/ML workloads, NIST's AI RMF provides critical guidance for securing AI model training and inference.

**AI RMF Categories Applied to GPU Security:**

**1. GOVERN:** Establish AI governance for GPU workloads
- Policy: Require model provenance tracking for all GPU training jobs
- Implementation: Git-based model lineage with GPU training metadata
```python
# Model training metadata (stored with model artifacts)
metadata = {
    "gpu_uuid": get_gpu_uuid(),
    "driver_version": get_driver_version(),
    "cuda_version": get_cuda_version(),
    "training_start": timestamp,
    "data_hash": compute_data_hash(),
    "user": authenticated_user
}
```

**2. MAP:** Understand AI risks specific to GPU infrastructure
- Risk: Model extraction via GPU memory dumps
- Mitigation: H100 Confidential Computing + memory encryption

**3. MEASURE:** Monitor AI model security on GPUs
- Metric: Model inference time anomalies (potential model stealing)
- Detection: Monitor GPU memory bandwidth for unusual patterns
```bash
# Detect model extraction attempts via memory bandwidth anomalies
nvidia-smi dmon -s m | awk '$4 > 90 {print "Anomaly: Sustained high memory bandwidth on GPU "$1}'
```

**4. MANAGE:** Implement controls for AI model lifecycle
- Secure model storage with encryption
- Access controls for model weights stored in GPU memory
```bash
# Encrypt model weights at rest
openssl enc -aes-256-cbc -salt -in model.pth -out model.pth.enc -k $MODEL_KEY
```

---

### 1.7 PCI DSS (for GPU-Accelerated Payment Processing)

**Relevance:**
Organizations using GPUs for fraud detection, transaction processing, or cryptographic operations must comply with PCI DSS.

**PCI DSS Requirements for GPU Infrastructure:**

| PCI Requirement | GPU Implementation |
|-----------------|-------------------|
| **Req 1: Firewalls** | GPU fabric network segmentation (SC-7) |
| **Req 2: Default Passwords** | Custom GPU admin credentials, no defaults |
| **Req 3: Protect Stored Data** | GPU memory encryption (H100 CC) |
| **Req 4: Encrypt Transmission** | NVLink encryption (SC-8) |
| **Req 5: Anti-Malware** | CUDA kernel signature verification |
| **Req 6: Secure Systems** | Patched GPU drivers (SI-2) |
| **Req 7: Restrict Access** | MIG isolation for cardholder data |
| **Req 8: Unique IDs** | Individual GPU accounts, no shared access |
| **Req 9: Physical Access** | GPU chassis intrusion detection |
| **Req 10: Log and Monitor** | DCGM audit trail (AU-2) |
| **Req 11: Security Testing** | Quarterly GPU vulnerability scans |
| **Req 12: Security Policy** | GPU security policy documented |

**Example: PCI-Compliant GPU Configuration**
```bash
# Requirement 3: Protect cardholder data with GPU memory encryption
nvidia-smi -c CC_ON  # H100 only

# Requirement 7: Restrict GPU access to cardholder data processing
nvidia-smi mig -cgi 9 -C  # Dedicated MIG instance for PCI workloads

# Requirement 10: Comprehensive audit logging
dcgmi policy --set 4,20
dcgmi group -c pci_gpus --addgpu 0
```

---

### 1.8 HIPAA (for Healthcare AI/ML on GPUs)

**Relevance:**
Healthcare organizations using GPUs for medical imaging, genomics, or patient data analysis must comply with HIPAA.

**HIPAA Safeguards for GPU Infrastructure:**

**Administrative Safeguards:**
- §164.308(a)(1): Risk analysis of GPU infrastructure
- §164.308(a)(3): Workforce security - RBAC for GPU access
- §164.308(a)(4): Audit controls - DCGM logging to SIEM

**Physical Safeguards:**
- §164.310(a)(1): Facility access controls - GPU chassis intrusion detection
- §164.310(d)(1): Device and media controls - Secure GPU memory wipe

**Technical Safeguards:**
- §164.312(a)(1): Access control - MIG isolation per patient dataset
- §164.312(c)(1): Integrity controls - GPU firmware verification
- §164.312(d): Person or entity authentication - IAM integration
- §164.312(e)(1): Transmission security - NVLink encryption

**Example: HIPAA-Compliant GPU Setup**
```yaml
# Kubernetes GPU node configuration for HIPAA
apiVersion: v1
kind: Pod
metadata:
  name: medical-imaging-gpu
  labels:
    hipaa-compliant: "true"
    phi-processing: "enabled"
spec:
  nodeSelector:
    gpu.encryption.enabled: "true"
    gpu.mig.enabled: "true"
  containers:
  - name: imaging-inference
    resources:
      limits:
        nvidia.com/mig-1g.5gb: 1  # Isolated MIG instance
    env:
    - name: NVIDIA_DRIVER_CAPABILITIES
      value: "compute,utility"  # No graphics, minimum surface
    securityContext:
      capabilities:
        drop: ["ALL"]  # Drop all capabilities
```

**HIPAA Audit Requirements:**
```bash
# §164.312(b): Audit controls - comprehensive GPU activity logging
cat > /etc/audit/rules.d/gpu-hipaa.rules << EOF
# Monitor GPU driver module loading
-w /sys/module/nvidia/parameters -p wa -k gpu_config_change

# Monitor GPU compute job execution
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nvidia-smi -k gpu_access

# Monitor GPU memory allocation
-w /dev/nvidia0 -p rwa -k gpu_memory_access
EOF

systemctl restart auditd
```

---

### 1.9 FedRAMP (for US Federal GPU Workloads)

**Relevance:**
Cloud service providers offering GPU infrastructure to US federal agencies must achieve FedRAMP authorization.

**FedRAMP Control Baseline for GPUs (Moderate Impact):**

| FedRAMP Control | GPU-Specific Implementation |
|-----------------|----------------------------|
| **AC-2 (Account Management)** | GPU resource allocation tied to federal user accounts |
| **AU-2 (Audit Events)** | GPU events logged to FedRAMP-compliant SIEM |
| **CM-2 (Baseline Configuration)** | NIST-approved GPU firmware/driver versions |
| **IA-2 (Identification/Authentication)** | PIV card authentication for GPU admin access |
| **SC-7 (Boundary Protection)** | FIPS 140-2 validated encryption for GPU fabric |
| **SC-8 (Transmission Confidentiality)** | FIPS 140-2 TLS for all GPU management interfaces |
| **SC-28 (Protection at Rest)** | FIPS 140-2 validated encryption for GPU memory |
| **SI-2 (Flaw Remediation)** | 30-day patch window for GPU driver vulnerabilities |

**FedRAMP-Compliant GPU Configuration:**
```bash
# FIPS 140-2 mode enforcement
echo "options nvidia NVreg_EnableFIPSMode=1" >> /etc/modprobe.d/nvidia.conf

# Federal authentication integration (PIV)
cat >> /etc/pam.d/nvidia-smi << EOF
auth required pam_pkcs11.so
account required pam_permit.so
EOF

# FIPS-validated encryption for NVLink (H100)
nvidia-smi nvlink --set-encryption 1 --fips-mode
```

---

### 1.10 CMMC (Cybersecurity Maturity Model Certification)

**Relevance:**
Defense contractors using GPUs for DoD work must achieve CMMC certification (Level 2 or 3).

**CMMC Practices for GPU Infrastructure:**

| CMMC Level 2 Practice | GPU Implementation |
|-----------------------|-------------------|
| **AC.L2-3.1.1 (Authorized Access)** | MIG isolation per classification level |
| **AC.L2-3.1.2 (Transaction Control)** | Audit all GPU compute job submissions |
| **AU.L2-3.3.1 (Audit Records)** | DCGM logging with 90-day retention |
| **CM.L2-3.4.1 (Baseline Configuration)** | DISA STIG-aligned GPU baselines |
| **IA.L2-3.5.1 (Identification)** | CAC card authentication for GPU access |
| **SC.L2-3.13.1 (Boundary Protection)** | Air-gapped GPU fabric for classified workloads |
| **SC.L2-3.13.8 (Transmission Confidentiality)** | NSA Suite B crypto for GPU networks |

**CMMC Level 3 (CUI Protection) for GPUs:**
```bash
# Controlled Unclassified Information (CUI) on GPUs
nvidia-smi -c CC_ON  # Confidential computing mandatory for CUI

# Memory sanitization for CUI
cat >> /etc/modprobe.d/nvidia-cmmc.conf << EOF
options nvidia NVreg_RegistryDwords="RMSecureMemoryClear=1;RMFIPSMode=1"
EOF

# Separate MIG instance for CUI workloads
nvidia-smi mig -cgi 9 -C
nvidia-smi mig -cci 0 -C
# Tag this instance as CUI-approved in orchestrator
```

---

## 2. GPU-SPECIFIC THREAT MODEL

### 2.1 Threat Modeling Methodology

We use STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) combined with MITRE ATT&CK techniques.

### 2.2 GPU System Components (Attack Surface)

```
┌─────────────────────────────────────────────────────────────────┐
│                     USER/APPLICATION LAYER                       │
│  - CUDA Applications                                             │
│  - Container Orchestrators (K8s)                                 │
│  - ML Frameworks (PyTorch, TensorFlow)                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓ (API calls)
┌─────────────────────────────────────────────────────────────────┐
│                     SOFTWARE LAYER                               │
│  - CUDA Runtime API                                              │
│  - NVIDIA Driver (nvidia.ko)                                     │
│  - User Mode Driver (libnvidia-ml.so)                            │
│  - Fabric Manager                                                │
└─────────────────────────────────────────────────────────────────┘
                              ↓ (MMIO, PCIe)
┌─────────────────────────────────────────────────────────────────┐
│                     FIRMWARE LAYER                               │
│  - GPU VBIOS                                                     │
│  - InfoROM (configuration data)                                  │
│  - GPU System Processor (GSP) Firmware                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓ (Hardware control)
┌─────────────────────────────────────────────────────────────────┐
│                     HARDWARE LAYER                               │
│  - GPU Die (SM cores, Tensor cores)                              │
│  - GPU Memory (GDDR6, HBM)                                       │
│  - NVLink Interconnect                                           │
│  - PCIe Interface                                                │
└─────────────────────────────────────────────────────────────────┘
                              ↓ (Network fabric)
┌─────────────────────────────────────────────────────────────────┐
│                     NETWORK LAYER                                │
│  - GPU Fabric (NVLink, NVSwitch)                                 │
│  - InfiniBand / RoCE                                             │
│  - GPUDirect RDMA                                                │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Trust Boundaries

1. **User ↔ Driver:** Applications can send malicious CUDA kernels
2. **Driver ↔ Firmware:** Driver vulnerabilities can corrupt firmware
3. **Firmware ↔ Hardware:** Firmware bugs can cause hardware faults
4. **GPU ↔ GPU:** Peer-to-peer attacks in multi-GPU systems
5. **GPU ↔ Network:** External attacks via GPU fabric interfaces
6. **Host ↔ GPU:** Container escapes via GPU passthrough

---

## 3. ATTACK SURFACE ANALYSIS

### 3.1 Software Attack Surface

| Component | Attack Vector | Threat | Impact |
|-----------|---------------|--------|--------|
| **CUDA Runtime** | Malicious kernel code | Execute arbitrary code on GPU | High |
| **NVIDIA Driver** | Privilege escalation bug | Kernel-level host compromise | Critical |
| **User-mode libraries** | Memory corruption | Information disclosure | Medium |
| **DCGM/Fabric Manager** | Unauthenticated API | Unauthorized GPU control | High |
| **Container runtime** | GPU passthrough escape | Host compromise | Critical |

**Example Attack: Malicious CUDA Kernel**
```cuda
// Attacker-crafted CUDA kernel
__global__ void malicious_kernel() {
    // Attempt to read protected memory
    unsigned long* protected_ptr = (unsigned long*)0xDEADBEEF;
    unsigned long leaked_data = *protected_ptr;
    
    // Attempt to write to protected region
    *protected_ptr = 0x41414141;
    
    // Infinite loop for DoS
    while(1) { /* spin */ }
}
```

**Mitigation:**
- Enable CUDA kernel signature verification
- Implement GPU memory isolation (MIG)
- Monitor for abnormal kernel execution patterns

---

### 3.2 Firmware Attack Surface

| Component | Attack Vector | Threat | Impact |
|-----------|---------------|--------|--------|
| **GPU VBIOS** | Malicious firmware update | Persistent backdoor | Critical |
| **InfoROM** | Configuration tampering | Disable security features | High |
| **GSP Firmware** | Firmware vulnerability | GPU-level code execution | Critical |

**Example Attack: InfoROM Tampering**
```bash
# Attacker modifies InfoROM to disable ECC
nvidia-smi -i 0 --ecc-config=0  # Disable error correction
nvidia-smi --gpu-reset          # Persist changes
```

**Mitigation:**
- Implement firmware signature verification (SI-7)
- Use UEFI Secure Boot for GPU ROM
- Monitor InfoROM changes via audit logs

---

### 3.3 Hardware Attack Surface

| Component | Attack Vector | Threat | Impact |
|-----------|---------------|--------|--------|
| **GPU Memory** | Physical memory access | Model/data theft | Critical |
| **PCIe Bus** | DMA attacks | Arbitrary memory access | Critical |
| **NVLink** | Eavesdropping | Intercept GPU-to-GPU traffic | High |
| **Power/Thermal** | Fault injection | Induce errors to leak secrets | Medium |

**Example Attack: PCIe DMA Attack**
- Attacker with physical access uses PCIe device to perform DMA
- Reads GPU memory containing model weights or private data
- Bypasses OS security entirely

**Mitigation:**
- Enable IOMMU/VT-d for DMA protection
- Use H100 Confidential Computing (memory encryption)
- Monitor thermal/power anomalies for fault injection

---

### 3.4 Network Attack Surface

| Component | Attack Vector | Threat | Impact |
|-----------|---------------|--------|--------|
| **GPUDirect RDMA** | Unauthorized RDMA access | Memory disclosure | High |
| **NVLink Fabric** | Unencrypted traffic | Eavesdropping | Medium |
| **InfiniBand** | Network attacks | GPU fabric compromise | High |
| **Management APIs** | Unauthenticated access | Configuration tampering | High |

**Example Attack: GPUDirect RDMA Exploitation**
```c
// Attacker with network access performs unauthorized RDMA read
struct ibv_sge sge = {
    .addr   = (uintptr_t)local_buffer,
    .length = 1048576,  // 1MB
    .lkey   = mr->lkey
};

struct ibv_send_wr wr = {
    .opcode = IBV_WR_RDMA_READ,
    .sg_list = &sge,
    .num_sge = 1,
    .wr.rdma.remote_addr = victim_gpu_memory,  // Target GPU memory
    .wr.rdma.rkey = victim_rkey
};
```

**Mitigation:**
- Disable GPUDirect RDMA on untrusted networks (AC-17)
- Enable NVLink encryption (H100+)
- Implement network segmentation for GPU fabric

---

## 4. THREAT SCENARIOS & MITIGATIONS

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

## 5. RISK MATRIX

### 5.1 Threat Risk Assessment

| Threat Scenario | Likelihood | Impact | Risk Level | Priority |
|-----------------|-----------|--------|-----------|----------|
| Cryptomining Hijacking | High | Medium | **HIGH** | 1 |
| Model Theft (Memory Dump) | Medium | Critical | **HIGH** | 2 |
| Container Escape | Medium | Critical | **HIGH** | 3 |
| Firmware Backdoor | Low | Critical | **MEDIUM** | 4 |
| Resource Exhaustion DoS | High | Medium | **MEDIUM** | 5 |
| Driver Privilege Escalation | Medium | High | **MEDIUM** | 6 |
| Fault Injection | Low | High | **LOW** | 7 |
| Model Poisoning | Low | High | **LOW** | 8 |

**Risk Calculation:**
- **Critical Impact** = Compromise of confidentiality, integrity, or availability of critical systems
- **High Impact** = Significant operational disruption or data exposure
- **Medium Impact** = Limited operational impact or data exposure
- **High Likelihood** = Known active exploitation or easy to execute
- **Medium Likelihood** = Requires some skill/access but feasible
- **Low Likelihood** = Requires advanced capabilities or physical access

### 5.2 Residual Risk After Mitigation

| Threat Scenario | Pre-Mitigation Risk | Post-Mitigation Risk | Reduction |
|-----------------|---------------------|---------------------|-----------|
| Cryptomining Hijacking | HIGH | **LOW** | 66% |
| Model Theft | HIGH | **MEDIUM** | 33% |
| Container Escape | HIGH | **LOW** | 66% |
| Firmware Backdoor | MEDIUM | **LOW** | 50% |
| Resource DoS | MEDIUM | **LOW** | 50% |
| Driver Privesc | MEDIUM | **LOW** | 50% |
| Fault Injection | LOW | **VERY LOW** | 25% |
| Model Poisoning | LOW | **VERY LOW** | 25% |

---

## 6. DEFENSE-IN-DEPTH ARCHITECTURE

### 6.1 Layered Security Model

```
Layer 7: Governance & Policy
├─ Security policies documented
├─ Incident response procedures
├─ Compliance monitoring (NIST 800-53, FedRAMP, etc.)
└─ Regular security audits

Layer 6: Application Security
├─ CUDA kernel signature verification
├─ Container image scanning
├─ Secure coding practices
└─ Input validation for GPU workloads

Layer 5: Identity & Access Management
├─ Multi-factor authentication
├─ RBAC for GPU resources
├─ Just-in-time access provisioning
└─ Privileged access management

Layer 4: Network Security
├─ GPU fabric segmentation (NVLink isolated)
├─ Firewall rules for management interfaces
├─ IDS/IPS for GPU traffic
└─ NVLink encryption (H100+)

Layer 3: Host Security
├─ GPU driver hardening
├─ Kernel security modules (SELinux/AppArmor)
├─ File integrity monitoring
└─ Patch management automation

Layer 2: Virtualization/Isolation
├─ MIG hardware isolation
├─ vGPU resource quotas
├─ Container security (seccomp, capabilities)
└─ IOMMU/VT-d for DMA protection

Layer 1: Hardware/Firmware Security
├─ UEFI Secure Boot for GPU ROM
├─ Firmware signature verification
├─ ECC memory enabled
├─ Chassis intrusion detection
└─ TPM-based attestation

Layer 0: Physical Security
├─ Datacenter access control
├─ Video surveillance
├─ Environmental monitoring (temp/power anomalies)
└─ Supply chain verification
```

### 6.2 Security Controls by Layer

| Layer | Primary Controls | Threat Coverage |
|-------|-----------------|-----------------|
| **Physical** | PE-3, PE-6 | Fault injection, tampering |
| **Hardware/Firmware** | SI-7, CM-3 | Firmware backdoors, integrity |
| **Virtualization** | SC-2, AC-3 | Container escapes, isolation |
| **Host** | SI-2, SI-4 | Driver exploits, malware |
| **Network** | SC-7, SC-8 | MITM, eavesdropping |
| **IAM** | AC-2, IA-2 | Unauthorized access |
| **Application** | SI-3, SI-10 | Malicious kernels, injection |
| **Governance** | CA-2, CA-7 | Compliance, oversight |

---

## 7. FRAMEWORK COMPARISON MATRIX

| Framework | Focus Area | GPU Applicability | Compliance Requirement |
|-----------|-----------|-------------------|----------------------|
| **NIST 800-53** | General security controls | High | Federal systems |
| **Zero Trust** | Architecture principle | High | Best practice |
| **MITRE ATT&CK** | Threat intelligence | High | Detection/response |
| **CIS Controls** | Baseline hardening | Medium | Best practice |
| **OWASP Cloud** | Cloud-native apps | High | Container security |
| **ISO 27001** | ISMS certification | Medium | International cert |
| **NIST AI RMF** | AI-specific risks | Critical | AI/ML workloads |
| **PCI DSS** | Payment processing | Medium | Financial industry |
| **HIPAA** | Healthcare data | Medium | Healthcare |
| **FedRAMP** | Federal cloud | High | US federal |
| **CMMC** | Defense contractors | High | DoD contractors |
| **ENISA** | EU cloud security | Medium | EU operations |

---

## REFERENCES

1. **NIST Publications:**
   - NIST SP 800-53 Rev 5
   - NIST SP 800-207 (Zero Trust)
   - NIST AI Risk Management Framework

2. **MITRE:**
   - MITRE ATT&CK Matrix for Enterprise
   - MITRE ATT&CK for IaaS

3. **Industry Standards:**
   - CIS Controls v8
   - ISO/IEC 27001:2013
   - OWASP Cloud-Native Application Security Top 10

4. **Regulatory Frameworks:**
   - PCI DSS v4.0
   - HIPAA Security Rule
   - FedRAMP Moderate Baseline
   - CMMC Level 2 Requirements

5. **NVIDIA Security:**
   - NVIDIA GPU Security Deployment Guide
   - NVIDIA Security Bulletins
   - NVIDIA Confidential Computing Documentation

---

**Document Control:**  
Next Review: February 28, 2026  
Owner: Information Security Architecture  
Classification: Internal Use
