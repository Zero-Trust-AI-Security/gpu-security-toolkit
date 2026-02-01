# 8. PHYSICAL AND ENVIRONMENTAL PROTECTION (PE)

### PE-3: Physical Access Control (GPU-specific)
**Control Implementation:**
- Implement GPU chassis intrusion detection
- Monitor GPU temperature for physical tampering indicators
- Track GPU PCIe slot presence

**Technical Implementation:**
```bash
# Monitor for GPU removal/insertion
udevadm monitor --subsystem-match=pci --property | grep -i nvidia

# Thermal anomaly detection (tamper indicator)
nvidia-smi --query-gpu=temperature.gpu --format=csv --loop=60 | \
  awk '$1 < 20 || $1 > 85 {print "Physical anomaly detected: "$1"C"}'

# PCIe AER monitoring
setpci -s $(lspci | grep NVIDIA | cut -d' ' -f1) CAP_EXP+0x08.L | \
  grep -q "00000000" || echo "PCIe error detected"
```

**NIST 800-53 Mapping:** PE-3, PE-6  
**Zero Trust Principle:** Assume breach - monitor physical GPU layer  
**Performance Impact:** <1% - passive monitoring

---
