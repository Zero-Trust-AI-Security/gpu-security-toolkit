# 2. USE CASE SECURITY REQUIREMENTS

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
