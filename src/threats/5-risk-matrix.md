# 5. RISK MATRIX

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
