# APPENDIX A: Quick Reference Command Sheet

### H100 Maximum Security Configuration
```bash
nvidia-smi -mig 1                           # Enable MIG
nvidia-smi mig -cgi 9,9,9,9,9,9,9 -C        # Create 7 instances
nvidia-smi -i 0:* -c CC_ON                  # Enable CC on all MIG
nvidia-smi nvlink --set-encryption 1        # Encrypt NVLink
nvidia-smi -e 1                             # Enable ECC
```

### A100 Standard Security Configuration
```bash
nvidia-smi -mig 1                           # Enable MIG
nvidia-smi mig -cgi 9,9,9,9,9,9,9 -C        # Create 7 instances
nvidia-smi -e 1                             # Enable ECC
nvidia-smi -pm 1                            # Persistence mode
```

### RTX 6000 Ada Workstation Security
```bash
nvidia-smi -pm 1                            # Persistence mode
nvidia-smi -e 1                             # Enable ECC
nvidia-smi -c EXCLUSIVE_PROCESS             # Single user
nvidia-smi --power-limit=300                # Power limit
```

### L40S vGPU Security
```bash
nvidia-smi vgpu -i 0 --exclusive-mode=1     # Exclusive vGPU
nvidia-smi -e 1                             # Enable ECC
nvidia-smi -c EXCLUSIVE_PROCESS             # Single user
```

---
