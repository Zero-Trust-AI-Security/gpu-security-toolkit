# 2. AUDIT AND ACCOUNTABILITY (AU)

### AU-2: Audit Events
**Control Implementation:**
- Enable comprehensive GPU telemetry collection
- Log all compute job submissions and completions
- Track GPU memory allocations and privilege escalations
- Monitor power/thermal anomalies as potential attack indicators

**Technical Implementation:**
```bash
# Enable DCGM for comprehensive telemetry
dcgm-exporter --collectors=dcgm

# Configure audit logging
nvidia-smi --query-compute-apps=pid,name,used_memory --format=csv --loop=1 >> /var/log/nvidia/compute-audit.log

# Enable ECC error logging
nvidia-smi -e 1
```

**Audit Events to Capture:**
- GPU allocation/deallocation
- CUDA context creation/destruction
- Driver module load/unload
- Firmware updates
- Configuration changes
- ECC errors and health events
- Power limit modifications
- Clock speed changes

**NIST 800-53 Mapping:** AU-2, AU-3, AU-6, AU-12  
**Zero Trust Principle:** Verify explicitly - audit all GPU operations  
**Performance Impact:** 1-2% - telemetry collection overhead

---

### AU-9: Protection of Audit Information
**Control Implementation:**
- Forward GPU logs to immutable SIEM (Splunk, ELK)
- Enable tamper-evident logging with cryptographic hashing
- Implement log rotation with integrity verification

**Technical Implementation:**
```bash
# Configure syslog forwarding with TLS
cat >> /etc/rsyslog.d/nvidia-gpu.conf << EOF
*.* @@siem.enterprise.local:6514
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
EOF

# Enable DCGM with secure metrics export
dcgm-exporter --web.listen-address=:9400 --web.telemetry-path=/metrics --collectors=dcgm --kubernetes=false
```

**NIST 800-53 Mapping:** AU-9, AU-11  
**Zero Trust Principle:** Assume breach - protect audit trail integrity  
**Performance Impact:** <1% - log forwarding minimal impact

---
