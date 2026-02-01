# 2. GPU-SPECIFIC THREAT MODEL

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
