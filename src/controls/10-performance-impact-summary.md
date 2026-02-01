# 10. PERFORMANCE IMPACT SUMMARY

| Control Category | Estimated Impact | Justification |
|------------------|------------------|---------------|
| Access Control (MIG) | 2-5% | Hardware isolation overhead |
| NVLink Encryption | 5-8% | Cryptographic processing |
| PCIe/Memory Encryption (CC) | 2-4% | Confidential computing overhead |
| Audit Logging (DCGM) | 1-2% | Telemetry collection |
| Network Segmentation | <1% | Policy enforcement minimal |
| Vulnerability Scanning | 0% | Out-of-band operation |
| Runtime Monitoring | 1-2% | Continuous metrics collection |
| Authentication/Authorization | <1% | Job submission only |
| Firmware Integrity Checks | <1% | Boot-time verification |
| Least Functionality (graphics disabled) | +2-3% | *Performance gain* |

**Cumulative Worst-Case Impact:** 12-18% (all controls enabled)  
**Typical Impact:** 5-10% (production-balanced configuration)  
**Optimized Impact:** 3-6% (performance-prioritized with essential security)

---
