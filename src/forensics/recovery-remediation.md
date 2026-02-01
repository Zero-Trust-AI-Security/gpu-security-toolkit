# RECOVERY & REMEDIATION

### System Hardening Post-Incident

```bash
# 1. Update GPU drivers to latest secure version
# Check current version
nvidia-smi --query-gpu=driver_version --format=csv,noheader

# Download latest from NVIDIA (verify GPG signature)
wget https://us.download.nvidia.com/XFree86/Linux-x86_64/535.154.05/NVIDIA-Linux-x86_64-535.154.05.run
wget https://us.download.nvidia.com/XFree86/Linux-x86_64/535.154.05/NVIDIA-Linux-x86_64-535.154.05.run.asc

# Verify signature
gpg --verify NVIDIA-Linux-x86_64-535.154.05.run.asc

# Install
sudo sh NVIDIA-Linux-x86_64-535.154.05.run

# 2. Reset GPU configuration to secure baseline
sudo nvidia-smi -pm 1                     # Persistence mode
sudo nvidia-smi -e 1                      # Enable ECC (datacenter GPUs)
sudo nvidia-smi -c EXCLUSIVE_PROCESS      # Single user mode
sudo nvidia-smi --gom=COMPUTE             # Compute only (no graphics)

# 3. Enable MIG for isolation (H100/A100)
sudo nvidia-smi -mig 1
for gpu in {0..7}; do
    sudo nvidia-smi mig -i $gpu -cgi 9,9,9,9,9,9,9 -C
done

# 4. Configure firewall rules (persistent)
# Block mining ports
sudo iptables -A OUTPUT -p tcp --dport 3333 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 4444 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 5555 -j DROP

# Save rules
sudo iptables-save > /etc/iptables/rules.v4

# 5. Implement resource quotas (Kubernetes)
kubectl apply -f - << EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: gpu-quota
  namespace: production
spec:
  hard:
    requests.nvidia.com/gpu: "8"
    limits.nvidia.com/gpu: "8"
EOF

# 6. Enable comprehensive monitoring
sudo systemctl enable dcgm
sudo systemctl start dcgm

# Set policies for anomaly detection
dcgmi policy --set 4,20  # Cryptomining detection
dcgmi policy --set 5,10  # ECC error spike detection

# 7. Rotate all credentials
# SSH keys
sudo find /home -name "authorized_keys" -exec chmod 600 {} \;
# Force password reset for affected users
for user in $(cat compromised_users.txt); do
    sudo passwd -e $user
done

# 8. Review and remove persistence
# Audit all cron jobs
sudo crontab -l > cron_backup.txt
for user in $(cut -d: -f1 /etc/passwd); do
    sudo crontab -l -u $user > cron_${user}.txt 2>/dev/null
done

# Audit systemd services
systemctl list-units --type=service --all > systemd_services.txt

# 9. Enable audit logging
sudo apt-get install auditd
sudo systemctl enable auditd
sudo systemctl start auditd

# Audit GPU access
cat >> /etc/audit/rules.d/gpu.rules << EOF
-w /dev/nvidia0 -p rwa -k gpu_access
-w /usr/bin/nvidia-smi -p x -k gpu_commands
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nvidia-smi -k gpu_exec
EOF

sudo service auditd restart
```

### Secure GPU Baseline Configuration Script

```bash
#!/bin/bash
# Apply secure GPU baseline configuration

echo "Applying secure GPU baseline configuration..."

# Enable all security features
for gpu in $(nvidia-smi --query-gpu=index --format=csv,noheader); do
    echo "Configuring GPU $gpu..."
    
    # Persistence mode
    nvidia-smi -i $gpu -pm 1
    
    # ECC (if supported)
    nvidia-smi -i $gpu -e 1 2>/dev/null || echo "  ECC not supported on GPU $gpu"
    
    # Compute-only mode
    nvidia-smi -i $gpu --gom=COMPUTE 2>/dev/null || echo "  GOM not supported"
    
    # Exclusive process mode
    nvidia-smi -i $gpu -c EXCLUSIVE_PROCESS
    
    # Set power limit (adjust for your GPU model)
    nvidia-smi -i $gpu --power-limit=300 2>/dev/null || echo "  Power limit not set"
done

# Disable unnecessary features
cat > /etc/modprobe.d/nvidia-security.conf << EOF
# Disable P2P (if not needed)
options nvidia NVreg_EnablePeerMappingOverride=0

# Enable secure memory clearing
options nvidia NVreg_RegistryDwords="RMSecureMemoryClear=1"

# Disable GPU accounting (if not needed)
# options nvidia NVreg_RegistryDwords="RMDisableGpuAccounting=1"
EOF

# Reload module (requires reboot for full effect)
echo "Configuration complete. Reboot required for kernel module changes."
echo "Current GPU state:"
nvidia-smi --query-gpu=index,persistence_mode,ecc.mode.current,compute_mode --format=table
```

---
