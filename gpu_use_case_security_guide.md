# Enterprise GPU Security by Use Case & Hardware Platform
## Comprehensive Security Configuration Guide

**Document Version:** 1.0  
**Last Updated:** January 31, 2026  
**Classification:** Internal Use

---

## TABLE OF CONTENTS

1. [GPU Deployment Scenarios](#1-gpu-deployment-scenarios)
2. [Use Case Security Requirements](#2-use-case-security-requirements)
3. [GPU Hardware Family Security Features](#3-gpu-hardware-family-security-features)
4. [Security Configuration by Platform](#4-security-configuration-by-platform)
5. [Multi-GPU Server Architectures](#5-multi-gpu-server-architectures)
6. [GPU Selection Matrix](#6-gpu-selection-matrix)

---

## 1. GPU DEPLOYMENT SCENARIOS

### 1.1 Deployment Taxonomy

```
Enterprise GPU Deployments
│
├── Workstation (Single GPU)
│   ├── Developer Workstation
│   ├── Data Science Workstation
│   ├── CAD/Engineering Workstation
│   └── Content Creation Workstation
│
├── Multi-GPU Server (2-8 GPUs)
│   ├── AI/ML Training Server
│   ├── Inference Server
│   ├── HPC Compute Node
│   └── Virtualized GPU Server (vGPU/MIG)
│
├── GPU Cluster (8+ GPUs)
│   ├── Distributed Training Cluster
│   ├── Supercomputing Node
│   ├── Render Farm
│   └── High-Throughput Inference
│
└── Cloud/Virtualized GPU
    ├── Public Cloud GPU Instance
    ├── Private Cloud GPU Pool
    ├── Container-based GPU (Kubernetes)
    └── VDI with GPU (Virtual Desktop)
```

---

## 2. USE CASE SECURITY REQUIREMENTS

### 2.1 Single GPU Workstation

**Profile: Developer/Data Scientist Workstation**

**Typical Configuration:**
- 1x GPU (RTX 4090, RTX 6000 Ada, or A6000)
- Windows 11 Pro or Ubuntu 22.04 LTS
- Local user with administrative rights
- Connected to corporate network

**Security Threats:**
| Threat | Risk Level | Impact |
|--------|-----------|--------|
| Unauthorized local access | Medium | Code/model theft |
| Malware on workstation | High | GPU cryptomining |
| Insider threat (data exfiltration) | Medium | IP theft |
| Physical theft | Medium | Hardware/data loss |
| Driver vulnerabilities | Medium | Privilege escalation |

**Required Security Controls:**

**Access Control (AC):**
```bash
# AC-2: Account Management
# Require individual user accounts, no shared GPU access
nvidia-smi -c EXCLUSIVE_PROCESS

# AC-6: Least Privilege
# Restrict GPU admin capabilities to authorized users only
sudo usermod -aG video $USERNAME  # Grant GPU access
sudo chmod 660 /dev/nvidia*       # Restrict device permissions
```

**Audit & Accountability (AU):**
```bash
# AU-2: Audit GPU usage
# Log all GPU compute jobs
cat > /etc/systemd/system/gpu-audit.service << 'EOF'
[Unit]
Description=GPU Usage Auditing
After=nvidia-persistenced.service

[Service]
Type=simple
ExecStart=/usr/bin/nvidia-smi dmon -s pucvmet -c 0 -f /var/log/nvidia/gpu-usage.log
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable gpu-audit.service
systemctl start gpu-audit.service
```

**Configuration Management (CM):**
```bash
# CM-2: Baseline Configuration
# Workstation GPU baseline
nvidia-smi -pm 1                    # Persistence mode
nvidia-smi --gom=ALL                # Allow graphics + compute
nvidia-smi -e 0                     # ECC off (consumer GPUs)
nvidia-smi --power-limit=300        # Set power limit

# CM-7: Least Functionality
# Disable unused features
echo "options nvidia NVreg_RegistryDwords=\"RMDisableGpuAccounting=0\"" >> /etc/modprobe.d/nvidia.conf
```

**Endpoint Protection:**
```powershell
# Windows: Enable Windows Defender GPU scanning
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -ScanAvgCPULoadFactor 50  # Allow GPU scans

# Linux: ClamAV GPU process scanning
clamscan --recursive /proc/$(pgrep -f nvidia-smi)/
```

**Performance Impact:** 1-2% (audit logging only)

---

### 2.2 Multi-GPU AI/ML Training Server

**Profile: 8-GPU Deep Learning Server**

**Typical Configuration:**
- 8x Data Center GPUs (H100, H200, L40S, or A100)
- Ubuntu 22.04 LTS Server
- NVLink/NVSwitch interconnect
- Shared by multiple ML teams
- Connected to high-speed storage (NFS, Lustre, S3)

**Security Threats:**
| Threat | Risk Level | Impact |
|--------|-----------|--------|
| Multi-tenancy isolation breach | High | Model/data leakage |
| Resource hijacking (cryptomining) | High | Compute theft |
| Model extraction via memory dump | Critical | IP theft |
| GPU-to-GPU lateral movement | Medium | Privilege escalation |
| Insider threat (authorized user) | High | Data exfiltration |
| Supply chain (firmware backdoor) | Medium | Persistent compromise |

**Required Security Controls:**

**Multi-Instance GPU (MIG) Isolation:**
```bash
# SC-2: Application Partitioning
# Enable MIG for hardware isolation (H100/H200/A100 only)
nvidia-smi -mig 1

# Create isolated MIG instances
# For 8x H100: Create 7 instances per GPU (56 total instances)
for gpu in {0..7}; do
  nvidia-smi mig -i $gpu -cgi 9,9,9,9,9,9,9 -C
done

# Verify MIG configuration
nvidia-smi --query-gpu=index,mig.mode.current --format=csv
```

**Resource Quotas per Team:**
```yaml
# Kubernetes ResourceQuota for ML team isolation
apiVersion: v1
kind: ResourceQuota
metadata:
  name: ml-team-alpha-quota
  namespace: ml-team-alpha
spec:
  hard:
    requests.nvidia.com/mig-1g.10gb: "8"   # 8 MIG instances max
    limits.nvidia.com/mig-1g.10gb: "8"
    requests.memory: "512Gi"
    requests.cpu: "64"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: ml-team-alpha-limits
  namespace: ml-team-alpha
spec:
  limits:
  - max:
      nvidia.com/mig-1g.10gb: "4"  # Max 4 MIG per pod
    type: Container
```

**GPU Fabric Network Isolation:**
```bash
# SC-7: Boundary Protection
# Isolate NVLink fabric from external networks
# Prevent GPU-to-GPU attacks across teams

# Create network namespace per MIG instance
for i in {0..55}; do
  ip netns add mig-instance-$i
done

# Assign GPUDirect RDMA to specific namespace
ip netns exec mig-instance-0 nvidia-smi nvlink --status

# Firewall rules: Block inter-team GPU traffic
iptables -A FORWARD -i ib0 -o ib0 -m physdev --physdev-in mlx5_0 --physdev-out mlx5_1 -j DROP
```

**Memory Encryption (H100/H200 with Confidential Computing):**
```bash
# SC-28: Protection of Information at Rest
# Enable GPU memory encryption for sensitive workloads
nvidia-smi -i 0 -c CC_ON

# Verify confidential computing mode
nvidia-smi --query-gpu=confidential_compute.mode --format=csv

# Create encrypted MIG instance for PII/PHI workloads
nvidia-smi mig -i 0 -cgi 19 -C  # H100 80GB MIG instance
nvidia-smi -i 0:0 -c CC_ON       # Enable CC on MIG instance
```

**Comprehensive Monitoring:**
```bash
# SI-4: System Monitoring
# Deploy DCGM for GPU fabric monitoring
dcgmi group -c training_gpus --addgpu 0-7

# Set policies for anomaly detection
dcgmi policy --set 4,20   # Alert if >90% util for >20min (cryptomining)
dcgmi policy --set 5,10   # Alert if >10 ECC errors/min (fault injection)

# Export metrics to Prometheus
dcgm-exporter --collectors=dcgm \
  --kubernetes-gpu-id-type=device-name \
  --web.listen-address=:9400
```

**Performance Impact:** 5-8% (MIG isolation + encryption + monitoring)

---

### 2.3 High-Performance Computing (HPC) Server

**Profile: 4-GPU Scientific Computing Node**

**Typical Configuration:**
- 4x HPC GPUs (H200, GH200 Superchip, or A100 80GB)
- RHEL 8 or Rocky Linux 8
- InfiniBand HDR (200 Gbps) interconnect
- MPI workloads (molecular dynamics, CFD, weather)
- Shared filesystem (Lustre, GPFS)

**Security Threats:**
| Threat | Risk Level | Impact |
|--------|-----------|--------|
| Job scheduler compromise | High | Unauthorized compute |
| Data integrity attacks | Critical | Research corruption |
| Side-channel attacks | Medium | Algorithm leakage |
| Resource exhaustion | Medium | DoS to researchers |

**Required Security Controls:**

**Job Scheduler Integration:**
```bash
# AC-3: Access Enforcement via SLURM
# Integrate GPU allocation with SLURM accounting

# /etc/slurm/gres.conf
Name=gpu Type=h200 File=/dev/nvidia0 CPUs=0-31
Name=gpu Type=h200 File=/dev/nvidia1 CPUs=32-63
Name=gpu Type=h200 File=/dev/nvidia2 CPUs=64-95
Name=gpu Type=h200 File=/dev/nvidia3 CPUs=96-127

# /etc/slurm/slurm.conf
AccountingStorageType=accounting_storage/slurmdbd
AccountingStorageEnforce=limits,qos
GresTypes=gpu

# Require authentication for GPU jobs
AuthType=auth/munge
```

**Data Integrity Verification:**
```bash
# SI-7: Software, Firmware, and Information Integrity
# Enable ECC on all HPC GPUs
nvidia-smi -e 1

# Verify ECC enabled across all GPUs
for gpu in {0..3}; do
  nvidia-smi -i $gpu --query-gpu=ecc.mode.current --format=csv,noheader
done

# Monitor for data corruption
nvidia-smi --query-gpu=ecc.errors.corrected.aggregate.total,ecc.errors.uncorrected.aggregate.total --format=csv --loop=300 >> /var/log/nvidia/ecc-errors.log
```

**InfiniBand Security:**
```bash
# SC-8: Transmission Confidentiality
# Enable InfiniBand partition isolation
opensm -P /etc/opensm/partitions.conf

# /etc/opensm/partitions.conf
Default=0x7fff, ipoib: ALL_SWITCHES=full, ALL_CAS=full;
HPC_Partition=0x0001: hpc-node-[01-64]=full;
AI_Partition=0x0002: ai-node-[01-32]=full;

# Verify partition membership
ibstat | grep -A5 "Physical state"
```

**Performance Impact:** 2-3% (ECC overhead, job accounting)

---

### 2.4 Virtualized GPU Server (vGPU/Multi-Tenant)

**Profile: 4-GPU Virtualization Host**

**Typical Configuration:**
- 4x Enterprise GPUs (A100, A40, L40, or RTX 6000 Ada)
- VMware vSphere 8.0 or KVM/QEMU
- NVIDIA vGPU software (vCS, vWS, or vPC profiles)
- 20-40 VMs sharing GPU resources
- VDI or multi-tenant cloud

**Security Threats:**
| Threat | Risk Level | Impact |
|--------|-----------|--------|
| VM escape via GPU | Critical | Hypervisor compromise |
| Cross-VM GPU memory leakage | High | Data disclosure |
| vGPU license server attack | Medium | Service disruption |
| Side-channel timing attacks | Medium | Information disclosure |

**Required Security Controls:**

**vGPU Profile Assignment:**
```bash
# AC-3: Access Enforcement
# Assign vGPU profiles based on workload classification

# High Security (PII/PHI): Smallest profile, max isolation
# Profile: A100-4C (4GB, time-sliced)
nvidia-smi vgpu -q | grep "vGPU Profile"

# Medium Security (Internal apps): Balanced profile
# Profile: A100-10C (10GB)

# Low Security (Dev/Test): Larger profile for performance
# Profile: A100-20C (20GB)

# Apply profile via VMware vCenter
# VM → Edit Settings → Add PCI Device → NVIDIA GRID vGPU → Select Profile
```

**VM Isolation Hardening:**
```bash
# SC-4: Information in Shared System Resources
# Prevent cross-VM GPU memory leakage

# Enable vGPU exclusive mode
nvidia-smi vgpu -i 0 --exclusive-mode=1

# Secure memory scrubbing between VM sessions
cat >> /etc/modprobe.d/nvidia-vgpu.conf << EOF
options nvidia-vgpu NVreg_EnableVGPUMemoryScrubbing=1
EOF

# Disable GPU peer-to-peer across VMs
echo "options nvidia NVreg_EnablePeerMappingOverride=0" >> /etc/modprobe.d/nvidia-vgpu.conf
```

**vGPU License Server Security:**
```bash
# IA-2: Identification and Authentication
# Secure NVIDIA vGPU License Server

# /etc/nvidia/gridd.conf
ServerAddress=vgpu-license.corp.internal
ServerPort=7070
FeatureType=1  # 1=vWS, 2=vPC, 4=vCS

# Enable TLS for license communication
EnableTLS=true
TLSCertFile=/etc/pki/nvidia/server.crt
TLSKeyFile=/etc/pki/nvidia/server.key
TLSCAFile=/etc/pki/nvidia/ca.crt

# Firewall: Restrict license server access
iptables -A INPUT -p tcp --dport 7070 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 7070 -j DROP
```

**Performance Impact:** 3-5% (vGPU overhead, memory scrubbing)

---

### 2.5 Containerized GPU Workloads (Kubernetes)

**Profile: GPU Container Cluster**

**Typical Configuration:**
- Multiple nodes with 4-8 GPUs each
- Kubernetes 1.28+ with NVIDIA GPU Operator
- Container runtime: containerd with nvidia-container-toolkit
- Multi-tenant namespace isolation
- CI/CD pipeline for ML models

**Security Threats:**
| Threat | Risk Level | Impact |
|--------|-----------|--------|
| Container escape via GPU | Critical | Node compromise |
| Malicious container image | High | Supply chain attack |
| Pod-to-pod lateral movement | Medium | Namespace breach |
| Secrets exposure (API keys) | High | Credential theft |

**Required Security Controls:**

**GPU Device Plugin Security:**
```yaml
# AC-3: Access Enforcement
# Deploy NVIDIA GPU Operator with security hardening
apiVersion: v1
kind: Namespace
metadata:
  name: gpu-operator
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nvidia-device-plugin-daemonset
  namespace: gpu-operator
spec:
  selector:
    matchLabels:
      name: nvidia-device-plugin-ds
  template:
    metadata:
      labels:
        name: nvidia-device-plugin-ds
    spec:
      priorityClassName: system-node-critical
      tolerations:
      - key: nvidia.com/gpu
        operator: Exists
        effect: NoSchedule
      containers:
      - image: nvcr.io/nvidia/k8s-device-plugin:v0.14.3
        name: nvidia-device-plugin-ctr
        env:
        - name: FAIL_ON_INIT_ERROR
          value: "false"
        - name: DEVICE_LIST_STRATEGY
          value: "envvar"
        - name: DEVICE_ID_STRATEGY
          value: "uuid"
        - name: PASS_DEVICE_SPECS
          value: "true"
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        volumeMounts:
        - name: device-plugin
          mountPath: /var/lib/kubelet/device-plugins
      volumes:
      - name: device-plugin
        hostPath:
          path: /var/lib/kubelet/device-plugins
```

**Pod Security Standards:**
```yaml
# SC-2: Application Partitioning
# Enforce restricted pod security for GPU workloads
apiVersion: v1
kind: Namespace
metadata:
  name: ml-production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: v1
kind: Pod
metadata:
  name: gpu-training-job
  namespace: ml-production
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10000
    fsGroup: 10000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: trainer
    image: nvcr.io/nvidia/pytorch:23.12-py3
    resources:
      limits:
        nvidia.com/gpu: 1
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 10000
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: model-cache
      mountPath: /workspace
  volumes:
  - name: tmp
    emptyDir: {}
  - name: model-cache
    persistentVolumeClaim:
      claimName: model-storage
```

**Image Scanning:**
```bash
# SI-3: Malicious Code Protection
# Scan GPU container images for vulnerabilities

# Trivy scan for CUDA base images
trivy image --severity HIGH,CRITICAL nvcr.io/nvidia/cuda:12.2.0-runtime-ubuntu22.04

# Grype scan with GPU-specific CVEs
grype nvcr.io/nvidia/pytorch:23.12-py3 --scope all-layers

# Admission controller to enforce scanned images only
kubectl apply -f - << EOF
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: gpu-image-policy
webhooks:
- name: validate-gpu-image.security.corp
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    operations: ["CREATE", "UPDATE"]
  clientConfig:
    service:
      name: image-policy-webhook
      namespace: kube-system
      path: "/validate-image"
  admissionReviewVersions: ["v1"]
  sideEffects: None
EOF
```

**Performance Impact:** 2-4% (container overhead, security policies)

---

## 3. GPU HARDWARE FAMILY SECURITY FEATURES

### 3.1 NVIDIA Data Center GPU Families

#### 3.1.1 Hopper Architecture (H100, H200, H800)

**H100 (80GB PCIe / 80GB SXM)**

**Security Features:**
| Feature | Capability | Security Benefit |
|---------|-----------|------------------|
| **Confidential Computing** | GPU memory encryption (AES-256) | Protects models/data in GPU VRAM |
| **Secure Boot** | Firmware signature verification | Prevents firmware backdoors |
| **Multi-Instance GPU (MIG)** | 7 hardware-isolated instances | Strong multi-tenancy isolation |
| **ECC Memory** | Error correction on HBM3 | Data integrity, fault detection |
| **NVLink Encryption** | AES-256 for GPU-to-GPU traffic | Prevents fabric eavesdropping |
| **Attestation** | TPM-based GPU attestation | Verifies GPU firmware integrity |

**Technical Specifications:**
```bash
# Security Configuration for H100
nvidia-smi -i 0 --query-gpu=name,compute_cap,driver_version --format=csv

# Enable all security features
nvidia-smi -c CC_ON              # Confidential computing
nvidia-smi -e 1                  # ECC memory
nvidia-smi nvlink --set-encryption 1  # NVLink encryption
nvidia-smi -mig 1                # Enable MIG

# Verify security posture
nvidia-smi --query-gpu=confidential_compute.mode,ecc.mode.current,mig.mode.current --format=csv
```

**Use Cases:**
- ✅ Highly sensitive AI/ML (healthcare, finance, defense)
- ✅ Multi-tenant cloud GPU with strong isolation
- ✅ Confidential data processing (PII, PHI, CUI)
- ✅ Compliance: HIPAA, PCI DSS, FedRAMP High

**Performance Impact of Security Features:**
- Confidential Computing: 2-4% overhead
- MIG Isolation: 2-5% overhead per instance
- NVLink Encryption: 5-8% overhead
- ECC Memory: ~2% overhead

---

**H200 (141GB HBM3e)**

**Enhanced Security Features (vs H100):**
- Larger memory capacity enables more MIG instances (up to 7x 20GB instances)
- HBM3e with inline compression for encrypted data
- Enhanced RAS (Reliability, Availability, Serviceability) features

**Configuration:**
```bash
# H200-specific security configuration
nvidia-smi -i 0 --query-gpu=memory.total --format=csv  # 141312 MiB

# Create maximum security MIG partitions
# 7x instances with CC enabled
for mig in {0..6}; do
  nvidia-smi mig -cgi 19 -C  # 19 = 1g.20gb profile for H200
  nvidia-smi -i 0:$mig -c CC_ON
done
```

**Use Cases:**
- ✅ Large language model (LLM) training with confidentiality
- ✅ Multi-tenant inference serving (more isolated instances)
- ✅ Memory-intensive secure workloads

---

#### 3.1.2 Ampere Architecture (A100, A30, A40, A10)

**A100 (40GB / 80GB)**

**Security Features:**
| Feature | Capability | Security Benefit |
|---------|-----------|------------------|
| **Multi-Instance GPU (MIG)** | 7 hardware-isolated instances | Multi-tenancy isolation |
| **ECC Memory** | Error correction on HBM2e | Data integrity |
| **Secure Boot** | Firmware verification | Firmware integrity |
| **PCIe ACS** | PCIe Access Control Services | DMA attack prevention |

**Limitations:**
- ❌ No GPU memory encryption (no Confidential Computing)
- ❌ No NVLink encryption
- ⚠️ Weaker isolation than Hopper for highly sensitive workloads

**Configuration:**
```bash
# A100 baseline security configuration
nvidia-smi -pm 1          # Persistence mode
nvidia-smi -e 1           # ECC (recommended)
nvidia-smi -mig 1         # MIG for isolation

# Create MIG instances (A100 80GB example)
nvidia-smi mig -cgi 9,9,9,9,9,9,9 -C  # 7x 1g.10gb instances
```

**Use Cases:**
- ✅ General AI/ML training (non-confidential data)
- ✅ Multi-tenant environments (moderate sensitivity)
- ✅ HPC workloads requiring ECC
- ⚠️ NOT recommended for: HIPAA/PCI workloads without additional encryption

---

**A30 (24GB)**

**Security Features:**
- MIG support (4 instances max)
- ECC memory
- Lower power consumption (165W)

**Use Cases:**
- ✅ Inference workloads (moderate security)
- ✅ Edge AI deployments
- ✅ Smaller multi-tenant clusters

**Configuration:**
```bash
# A30 MIG configuration
nvidia-smi mig -cgi 14,14,14,14 -C  # 4x 1g.6gb instances
```

---

**A40 (48GB)**

**Security Features:**
- ❌ No MIG support
- ✅ ECC memory
- ✅ vGPU support (virtualization)

**Configuration:**
```bash
# A40 for vGPU deployment
nvidia-smi -c EXCLUSIVE_PROCESS  # Single-user mode
nvidia-smi -e 1                  # Enable ECC

# vGPU profiles for A40
nvidia-smi vgpu -q
# A40-1Q: 1GB (48 users max)
# A40-8Q: 8GB (6 users max)
# A40-24Q: 24GB (2 users max)
```

**Use Cases:**
- ✅ Virtual desktop infrastructure (VDI)
- ✅ Single-user HPC workloads
- ✅ Rendering farms
- ⚠️ NOT for: Multi-tenant ML (no MIG)

---

#### 3.1.3 Ada Lovelace Architecture (L40S, L40, L4)

**L40S (48GB)**

**Security Features:**
| Feature | Capability | Security Benefit |
|---------|-----------|------------------|
| **ECC Memory** | Error correction on GDDR6 | Data integrity |
| **Secure Boot** | Firmware verification | Firmware integrity |
| **vGPU Support** | Up to 48 vGPU instances | Virtualized multi-tenancy |
| **PCIe Gen5** | 128 GB/s bandwidth | Lower latency for encrypted traffic |

**Limitations:**
- ❌ No MIG support
- ❌ No Confidential Computing
- ❌ No NVLink encryption

**Configuration:**
```bash
# L40S security baseline
nvidia-smi -c EXCLUSIVE_PROCESS
nvidia-smi -e 1  # ECC enabled

# For vGPU deployment
nvidia-smi vgpu -i 0 --exclusive-mode=1
```

**Use Cases:**
- ✅ AI inference (graphics + compute hybrid)
- ✅ VDI with GPU acceleration
- ✅ Content creation workstations
- ⚠️ NOT for: Highly sensitive multi-tenant ML

---

**L4 (24GB)**

**Security Features:**
- ECC memory
- Low power (72W, passively cooled)
- vGPU support

**Use Cases:**
- ✅ Edge AI inference
- ✅ Video transcoding
- ✅ Low-power inference servers

---

### 3.2 NVIDIA Professional GPU Families

#### 3.2.1 RTX Ada Generation (RTX 6000 Ada, RTX 5880 Ada, RTX 5000 Ada)

**RTX 6000 Ada (48GB)**

**Security Features:**
| Feature | Capability | Security Benefit |
|---------|-----------|------------------|
| **ECC Memory** | Error correction on GDDR6 | Data integrity |
| **Secure Boot** | Firmware verification | Firmware integrity |
| **vGPU Support** | Virtual GPU (vWS/vPC) | Virtualized workstations |
| **Hardware Root of Trust** | Secure provisioning | Supply chain security |

**Limitations:**
- ❌ No MIG (workstation GPU)
- ❌ No Confidential Computing
- ✅ Best for: Single-user workstations

**Configuration:**
```bash
# RTX 6000 Ada workstation security
nvidia-smi -pm 1
nvidia-smi -e 1           # Enable ECC
nvidia-smi --gom=ALL      # Graphics + Compute mode

# Restrict to single user
nvidia-smi -c EXCLUSIVE_PROCESS
```

**Use Cases:**
- ✅ Engineering workstations (CAD/CAE)
- ✅ AI development workstations
- ✅ Content creation (rendering, video)
- ✅ Virtual workstations (vGPU)

---

#### 3.2.2 Previous Generation Professional (RTX A6000, RTX A5000, A40)

**RTX A6000 (48GB Ampere)**

**Security Features:**
- ECC memory
- vGPU support
- Secure boot

**Use Cases:**
- ✅ Legacy workstation deployments
- ✅ Virtualized CAD/design workstations

**Configuration:**
```bash
# RTX A6000 baseline
nvidia-smi -pm 1
nvidia-smi -e 1
nvidia-smi -c EXCLUSIVE_PROCESS
```

---

### 3.3 NVIDIA Consumer GPU Families (Enterprise Use Discouraged)

#### 3.3.1 GeForce RTX 40 Series (RTX 4090, 4080, 4070)

**Security Limitations for Enterprise:**
| Feature | Status | Impact |
|---------|--------|--------|
| ECC Memory | ❌ Not Available | No data integrity protection |
| vGPU Support | ❌ Not Available | No virtualization |
| MIG Support | ❌ Not Available | No hardware isolation |
| Enterprise Driver | ❌ GeForce drivers only | Less stable, gaming-focused |
| Support SLA | ❌ No enterprise support | No guarantee for production |

**Why NOT to use in enterprise:**
1. **No ECC Memory** - Critical for scientific/financial computing
2. **No vGPU** - Cannot virtualize for multi-user access
3. **No MIG** - Cannot isolate workloads
4. **Driver Restrictions** - GeForce drivers disabled for data center use
5. **No Support** - Consumer warranty, not enterprise SLA

**Limited Acceptable Use Cases:**
- ⚠️ Development/testing environments (non-production)
- ⚠️ Individual developer workstations (personal data only)
- ❌ NEVER for: Production ML, HPC, multi-tenant, sensitive data

**Configuration (if absolutely necessary):**
```bash
# Minimal security for RTX 4090 workstation
nvidia-smi -c EXCLUSIVE_PROCESS  # Single user
# Note: ECC cannot be enabled (not supported)
# Note: MIG cannot be enabled (not supported)

# Enhanced monitoring for consumer GPU
nvidia-smi dmon -s pucvmet -c 0 >> /var/log/nvidia/rtx4090-usage.log
```

---

## 4. SECURITY CONFIGURATION BY PLATFORM

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

## 5. MULTI-GPU SERVER ARCHITECTURES

### 5.1 Architecture Comparison

| Architecture | GPUs | Interconnect | Use Case | Security Profile |
|--------------|------|--------------|----------|-----------------|
| **PCIe Only** | 2-8 | PCIe Gen4/5 | Cost-optimized training | Moderate (no fabric encryption) |
| **NVLink** | 2-8 | NVLink 600GB/s | High-perf training | High (NVLink encryption available) |
| **NVSwitch** | 8-256 | NVSwitch 3.6TB/s | Large-scale clusters | High (fabric encryption) |
| **InfiniBand** | 4-8 per node | IB HDR 200Gbps | HPC/MPI workloads | High (IB partition isolation) |

---

### 5.2 8-GPU Server Architecture Diagrams

#### 5.2.1 NVLink Configuration (H100/H200)

```
┌─────────────────────────────────────────────────────────────────┐
│                    8-GPU NVLink Server                          │
│                                                                 │
│  ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐              │
│  │ GPU 0  │───│ GPU 1  │───│ GPU 2  │───│ GPU 3  │              │
│  │ H100   │   │ H100   │   │ H100   │   │ H100   │              │
│  └────────┘   └────────┘   └────────┘   └────────┘              │
│      │            │            │            │                   │
│      └────────────┴────────────┴────────────┘                   │
│                       NVLink (600 GB/s)                         │
│                       [ENCRYPTED]                               │
│      ┌────────────┬────────────┬────────────┐                   │
│      │            │            │            │                   │
│  ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐              │
│  │ GPU 4  │───│ GPU 5  │───│ GPU 6  │───│ GPU 7  │              │
│  │ H100   │   │ H100   │   │ H100   │   │ H100   │              │
│  └────────┘   └────────┘   └────────┘   └────────┘              │
│                                                                 │
│  Security Features:                                             │
│  • NVLink AES-256 Encryption                                    │
│  • MIG: 7 instances per GPU (56 total)                          │
│  • Confidential Computing on all instances                      │
│  • ECC memory enabled                                           │
│                                                                 │
│  Performance Impact: 8-12%                                      │
└─────────────────────────────────────────────────────────────────┘
```

**Security Configuration:**
```bash
# Enable NVLink encryption between all GPUs
for gpu in {0..7}; do
  nvidia-smi -i $gpu nvlink --set-encryption 1
done

# Verify encrypted links
nvidia-smi nvlink --status | grep "Encryption: Enabled"
```

---

#### 5.2.2 PCIe-Only Configuration (L40S/A40)

```
┌─────────────────────────────────────────────────────────────────┐
│                8-GPU PCIe Server (No NVLink)                    │
│                                                                 │
│         CPU 0                           CPU 1                   │
│     ┌─────────┐                     ┌─────────┐                 │
│     │         │                     │         │                 │
│     │  PCIe   │                     │  PCIe   │                 │
│     │ Switch  │                     │ Switch  │                 │
│     └─────────┘                     └─────────┘                 │
│      │ │ │ │                         │ │ │ │                    │
│    ┌─┴─┴─┴─┴─┐                     ┌─┴─┴─┴─┴─┐                  │
│    │ GPU 0-3 │                     │ GPU 4-7 │                  │
│    │ L40S    │                     │ L40S    │                  │
│    └─────────┘                     └─────────┘                  │
│                                                                 │
│  Security Considerations:                                       │
│  • NO GPU-to-GPU encryption (PCIe only)                         │
│  • IOMMU/VT-d required for DMA protection                       │
│  • Network isolation for multi-GPU communication                │
│  • vGPU for multi-tenancy (no MIG available)                    │
│                                                                 │
│  Performance Impact: 3-5% (vGPU overhead)                       │
└─────────────────────────────────────────────────────────────────┘
```

**Security Configuration:**
```bash
# Enable IOMMU for DMA protection
# In /etc/default/grub:
GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt"

# Update GRUB
update-grub
reboot

# Verify IOMMU enabled
dmesg | grep -i iommu

# Configure vGPU for multi-tenancy
nvidia-smi vgpu -i 0 --exclusive-mode=1
```

---

## 6. GPU SELECTION MATRIX

### 6.1 Security-First GPU Selection Guide

| Use Case | Recommended GPU | Why | Security Profile | Performance Impact |
|----------|----------------|-----|------------------|-------------------|
| **Confidential AI Training** | H100/H200 | Confidential Computing, MIG | ⭐⭐⭐⭐⭐ Critical | 8-12% |
| **Multi-Tenant ML (High Security)** | H100/H200 | MIG + CC, NVLink encryption | ⭐⭐⭐⭐⭐ Critical | 8-12% |
| **Multi-Tenant ML (Standard)** | A100 80GB | MIG isolation, ECC | ⭐⭐⭐⭐ High | 5-8% |
| **HPC Scientific Computing** | H200/A100 | ECC, large memory, NVLink | ⭐⭐⭐⭐ High | 2-3% |
| **Inference (High Security)** | H100 + CC | Memory encryption | ⭐⭐⭐⭐⭐ Critical | 2-4% |
| **Inference (Standard)** | L40S/L4 | ECC, vGPU | ⭐⭐⭐ Medium | 2-3% |
| **VDI / Virtual Workstations** | RTX 6000 Ada, A40 | vGPU support, ECC | ⭐⭐⭐ Medium | 3-5% |
| **Developer Workstation** | RTX 6000 Ada | ECC, single-user | ⭐⭐⭐ Medium | 1-2% |
| **Edge AI Inference** | L4 | Low power, ECC | ⭐⭐ Low | 1-2% |

**Security Profile Legend:**
- ⭐⭐⭐⭐⭐ **Critical:** Full encryption (memory + fabric), MIG isolation, attestation
- ⭐⭐⭐⭐ **High:** MIG or vGPU isolation, ECC, firmware verification
- ⭐⭐⭐ **Medium:** ECC, secure boot, single-user or vGPU
- ⭐⭐ **Low:** Basic firmware verification only
- ⭐ **Minimal:** Consumer GPU (not recommended for enterprise)

---

### 6.2 Decision Tree

```
                    START: Select GPU for Enterprise
                              │
                              ▼
                    Does workload handle
                    sensitive/regulated data?
                    (PII, PHI, CUI, CCI)
                         ╱        ╲
                      YES          NO
                       │            │
                       ▼            ▼
              H100/H200 with    Multi-tenant?
              Confidential         ╱    ╲
              Computing          YES     NO
                                  │      │
                                  ▼      ▼
                              Needs    Single
                              MIG?     User?
                              ╱  ╲      │
                           YES   NO     ▼
                            │     │   RTX 6000
                            ▼     ▼   Ada / A6000
                        H100/  A40/L40S
                        A100   (vGPU)
```

---

### 6.3 Compliance Mapping

| Compliance | Minimum GPU | Recommended Features |
|-----------|-------------|---------------------|
| **HIPAA (Protected Health Information)** | H100 + CC | Memory encryption, MIG, audit logs |
| **PCI DSS (Payment Card Data)** | H100 + CC | Memory encryption, network isolation |
| **FedRAMP High** | H100 + CC | FIPS mode, attestation, full encryption |
| **CMMC Level 3 (CUI)** | H100 + CC | Memory scrubbing, MIG, secure boot |
| **ISO 27001** | A100 or better | ECC, MIG/vGPU, vulnerability scanning |
| **SOC 2 Type II** | A100 or better | Audit logging, access controls, ECC |
| **General Enterprise** | L40S or better | ECC, vGPU/MIG, basic monitoring |

---

## APPENDIX A: Quick Reference Command Sheet

### H100 Maximum Security Configuration
```bash
nvidia-smi -mig 1                           # Enable MIG
nvidia-smi mig -cgi 9,9,9,9,9,9,9 -C        # Create 7 instances
nvidia-smi -i 0:* -c CC_ON                  # Enable CC on all MIG
nvidia-smi nvlink --set-encryption 1        # Encrypt NVLink
nvidia-smi -e 1                             # Enable ECC
```

### A100 Standard Security Configuration
```bash
nvidia-smi -mig 1                           # Enable MIG
nvidia-smi mig -cgi 9,9,9,9,9,9,9 -C        # Create 7 instances
nvidia-smi -e 1                             # Enable ECC
nvidia-smi -pm 1                            # Persistence mode
```

### RTX 6000 Ada Workstation Security
```bash
nvidia-smi -pm 1                            # Persistence mode
nvidia-smi -e 1                             # Enable ECC
nvidia-smi -c EXCLUSIVE_PROCESS             # Single user
nvidia-smi --power-limit=300                # Power limit
```

### L40S vGPU Security
```bash
nvidia-smi vgpu -i 0 --exclusive-mode=1     # Exclusive vGPU
nvidia-smi -e 1                             # Enable ECC
nvidia-smi -c EXCLUSIVE_PROCESS             # Single user
```

---

## APPENDIX B: Performance Impact Summary by Platform

| Platform | GPUs | Security Features Enabled | Total Impact |
|----------|------|---------------------------|--------------|
| **H100 Max Security** | 8x H100 | MIG + CC + NVLink Enc + ECC | 8-12% |
| **H100 Balanced** | 8x H100 | MIG + ECC + NVLink Enc | 6-9% |
| **A100 Standard** | 8x A100 | MIG + ECC | 5-8% |
| **L40S vGPU** | 4x L40S | vGPU + ECC | 3-5% |
| **RTX 6000 Workstation** | 1x RTX 6000 | ECC + Audit | 1-2% |
| **HPC A100** | 4x A100 | ECC + Monitoring | 2-3% |

---

**Document Control:**  
Next Review: February 28, 2026  
Owner: Information Security Architecture  
Classification: Internal Use
