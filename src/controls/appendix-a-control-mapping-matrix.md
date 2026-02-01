# APPENDIX A: CONTROL MAPPING MATRIX

| NIST 800-53 Control | Zero Trust Principle | GPU Implementation | Performance Impact |
|---------------------|---------------------|-------------------|-------------------|
| AC-2, AC-3, AC-6 | Verify explicitly | MIG/vGPU RBAC | 2-5% |
| AC-17 | Assume breach | Network segmentation | <1% |
| AU-2, AU-3, AU-12 | Verify continuously | DCGM logging | 1-2% |
| SC-7 | Assume breach | Fabric isolation | <1% |
| SC-8, SC-13 | Assume breach | NVLink encryption | 5-8% |
| SC-28 | Assume breach | Memory encryption | 2-4% |
| SI-2, RA-5 | Verify continuously | CVE scanning | 0% |
| SI-4 | Verify continuously | Anomaly detection | 1-2% |
| SI-7 | Verify explicitly | Firmware integrity | <1% |
| CM-2, CM-7 | Least privilege | Baseline hardening | +2-3% gain |

---
