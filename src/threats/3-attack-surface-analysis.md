# 3. ATTACK SURFACE ANALYSIS

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
