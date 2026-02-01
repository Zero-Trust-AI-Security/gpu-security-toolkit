# 1. INCIDENT RESPONSE OVERVIEW

### 1.1 GPU Security Incident Priority Matrix

| Incident Type | Indicators | Priority | Response Time | Evidence Collection |
|---------------|-----------|----------|---------------|-------------------|
| **Cryptomining Hijacking** | 100% GPU util, mining pool connections | P1 - Critical | Immediate | Volatile + Network |
| **Model Theft / Data Exfiltration** | Unusual memory access, large transfers | P1 - Critical | Immediate | Memory dump + Network |
| **Container Escape** | Unexpected host access, privilege escalation | P1 - Critical | Immediate | Container + Process |
| **Firmware Compromise** | Firmware hash mismatch, unexpected behavior | P1 - Critical | Immediate | Firmware + ROM |
| **Resource DoS** | GPU exhaustion, users blocked | P2 - High | <15 min | State snapshot |
| **Driver Vulnerability Exploit** | Kernel crashes, unexpected privileges | P1 - Critical | Immediate | Kernel logs + Memory |
| **Side-Channel Attack** | Timing anomalies, power fluctuations | P2 - High | <1 hour | Thermal + Power logs |
| **Insider Threat** | After-hours access, data copying | P2 - High | <1 hour | Timeline + Audit logs |

---
