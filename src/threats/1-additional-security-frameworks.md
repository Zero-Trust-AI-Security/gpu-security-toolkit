# 1. ADDITIONAL SECURITY FRAMEWORKS

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
