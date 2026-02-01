# 6. GPU SELECTION MATRIX

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
