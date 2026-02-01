# 5. MULTI-GPU SERVER ARCHITECTURES

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
│  ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐            │
│  │ GPU 0  │───│ GPU 1  │───│ GPU 2  │───│ GPU 3  │            │
│  │ H100   │   │ H100   │   │ H100   │   │ H100   │            │
│  └────────┘   └────────┘   └────────┘   └────────┘            │
│      │            │            │            │                   │
│      └────────────┴────────────┴────────────┘                   │
│                       NVLink (600 GB/s)                         │
│                       [ENCRYPTED]                               │
│      ┌────────────┬────────────┬────────────┐                   │
│      │            │            │            │                   │
│  ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐            │
│  │ GPU 4  │───│ GPU 5  │───│ GPU 6  │───│ GPU 7  │            │
│  │ H100   │   │ H100   │   │ H100   │   │ H100   │            │
│  └────────┘   └────────┘   └────────┘   └────────┘            │
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
│     ┌─────────┐                     ┌─────────┐                │
│     │         │                     │         │                │
│     │  PCIe   │                     │  PCIe   │                │
│     │ Switch  │                     │ Switch  │                │
│     └─────────┘                     └─────────┘                │
│      │ │ │ │                         │ │ │ │                  │
│    ┌─┴─┴─┴─┴─┐                     ┌─┴─┴─┴─┴─┐                │
│    │ GPU 0-3 │                     │ GPU 4-7 │                │
│    │ L40S    │                     │ L40S    │                │
│    └─────────┘                     └─────────┘                │
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
