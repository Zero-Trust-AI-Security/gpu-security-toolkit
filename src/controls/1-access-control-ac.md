# 1. ACCESS CONTROL (AC)

### AC-2: Account Management
**Control Implementation:**
- Implement GPU fabric manager access control lists
- Enforce principle of least privilege for CUDA context creation
- Utilize Nvidia GPU Operator RBAC in Kubernetes environments
- Integrate with enterprise IAM for GPU resource allocation

**Technical Implementation:**
```bash
# GPU Fabric Manager ACL Configuration
nvidia-smi -i 0 -c EXCLUSIVE_PROCESS
nvidia-smi -i 0 --applications-clocks-permission=RESTRICTED
```

**NIST 800-53 Mapping:** AC-2, AC-3, AC-6  
**Zero Trust Principle:** Verify explicitly - authenticate all GPU access  
**Performance Impact:** <1% - minimal overhead from access validation

---

### AC-3: Access Enforcement (MIG & vGPU)
**Control Implementation:**
- Deploy Multi-Instance GPU (MIG) for hardware-level isolation
- Configure vGPU profiles with resource quotas
- Implement compute mode restrictions per workload classification

**Technical Implementation:**
```bash
# Enable MIG Mode (A100/H100)
nvidia-smi -mig 1

# Create MIG instances with isolation
nvidia-smi mig -cgi 9,9,9,9,9,9,9 -C

# Set compute mode for exclusive access
nvidia-smi -c EXCLUSIVE_THREAD
```

**Configuration Example - vGPU Profiles:**
| Profile | FB Memory | Compute | Use Case | Isolation Level |
|---------|-----------|---------|----------|-----------------|
| A100-10C | 10GB | Full | Trusted ML | MIG Instance |
| A100-5C | 5GB | Limited | Dev/Test | vGPU |
| A100-1C | 1GB | Restricted | Inference | vGPU |

**NIST 800-53 Mapping:** AC-3, AC-4, SC-2  
**Zero Trust Principle:** Use least privilege access - segment by workload  
**Performance Impact:** 2-5% - isolation overhead, varies by MIG configuration

---

### AC-17: Remote Access
**Control Implementation:**
- Disable GPU Direct RDMA on untrusted networks
- Encrypt GPU-to-GPU communication with TLS
- Implement network segmentation for GPU fabrics (NVLink, InfiniBand)

**Technical Implementation:**
```bash
# Disable GPUDirect RDMA for remote systems
echo "options nvidia NVreg_EnableGpuFirmware=0" >> /etc/modprobe.d/nvidia.conf

# Enable GPU fabric encryption (H100+)
nvidia-smi nvlink --set-encryption 1
```

**NIST 800-53 Mapping:** AC-17, SC-8, SC-13  
**Zero Trust Principle:** Assume breach - encrypt all GPU fabric traffic  
**Performance Impact:** 5-8% - encryption overhead on NVLink/InfiniBand

---
