# 3. CONFIGURATION MANAGEMENT (CM)

### CM-2: Baseline Configuration
**Control Implementation:**
- Establish secure GPU firmware baseline
- Document approved driver versions per environment
- Implement configuration as code for GPU settings
- Version control GPU operator configurations

**Technical Implementation:**
```yaml
# Nvidia GPU Operator ConfigMap (Kubernetes)
apiVersion: v1
kind: ConfigMap
metadata:
  name: gpu-operator-config
  namespace: gpu-operator
data:
  driver-version: "535.129.03"
  cuda-version: "12.2"
  compute-mode: "EXCLUSIVE_PROCESS"
  persistence-mode: "Enabled"
  ecc-mode: "Enabled"
  power-limit: "300W"
  application-clocks: "1410,1215"
```

**Baseline Components:**
- Driver version (with CVE tracking)
- CUDA toolkit version
- Fabric Manager version
- DCGM version
- GPU firmware version
- vGPU/MIG configuration profiles
- Power and clock settings

**NIST 800-53 Mapping:** CM-2, CM-3, CM-6  
**Zero Trust Principle:** Verify explicitly - enforce known-good configurations  
**Performance Impact:** 0% - configuration enforcement only

---

### CM-7: Least Functionality
**Control Implementation:**
- Disable unused GPU features (graphics for compute-only)
- Remove unnecessary driver modules
- Restrict GPU peer-to-peer access
- Disable legacy compatibility modes

**Technical Implementation:**
```bash
# Disable graphics capability (datacenter GPUs)
nvidia-smi --gpu-reset
nvidia-smi -pm 1  # Persistence mode
nvidia-smi --gom=COMPUTE  # Compute-only mode

# Restrict P2P access
echo "options nvidia NVreg_EnablePeerMappingOverride=0" >> /etc/modprobe.d/nvidia.conf

# Remove unused modules
rmmod nvidia_drm nvidia_modeset  # Keep only nvidia core for compute
```

**Disabled Features:**
- Display/graphics stack (datacenter)
- Legacy CUDA compatibility layers
- Unrestricted peer-to-peer mapping
- GPU Direct Storage (if unused)

**NIST 800-53 Mapping:** CM-7, SC-7  
**Zero Trust Principle:** Use least privilege - minimize attack surface  
**Performance Impact:** +2-3% - removing graphics overhead improves compute

---
