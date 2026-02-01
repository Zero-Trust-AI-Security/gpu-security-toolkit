# 5. SYSTEM AND COMMUNICATIONS PROTECTION (SC)

### SC-7: Boundary Protection
**Control Implementation:**
- Segment GPU fabrics into security zones
- Implement microsegmentation for multi-tenant environments
- Deploy GPU-specific firewall rules
- Isolate management from data plane

**Network Architecture:**
```
┌─────────────────────────────────────────────┐
│ Management Network (VLAN 10)               │
│ - DCGM, nvidia-smi, Fabric Manager         │
│ - Access: Admin only, MFA required         │
└─────────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────────┐
│ Compute Network (VLAN 20)                  │
│ - CUDA workloads, MPI                       │
│ - Access: Authenticated users               │
└─────────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────────┐
│ GPU Fabric Network (VLAN 30)               │
│ - NVLink, GPUDirect RDMA, InfiniBand       │
│ - Access: GPU-to-GPU only, encrypted       │
│ - NO external routing                       │
└─────────────────────────────────────────────┘
```

**Firewall Rules:**
```bash
# Management plane (restrict to admin subnet)
iptables -A INPUT -p tcp --dport 5555 -s 10.0.1.0/24 -j ACCEPT  # DCGM
iptables -A INPUT -p tcp --dport 5555 -j DROP

# Block GPU fabric from external access
iptables -A FORWARD -i ib0 -o eth0 -j DROP
iptables -A FORWARD -i eth0 -o ib0 -j DROP
```

**NIST 800-53 Mapping:** SC-7, SC-32, AC-4  
**Zero Trust Principle:** Assume breach - segment GPU networks  
**Performance Impact:** <1% - network policy enforcement minimal

---

### SC-8: Transmission Confidentiality
**Control Implementation:**
- Enable NVLink encryption (H100, B100+)
- Implement TLS for GPU management interfaces
- Encrypt GPU memory during PCIe transfers (Confidential Computing)

**Technical Implementation:**
```bash
# Enable NVLink encryption (H100+)
nvidia-smi nvlink --set-encryption 1 --set-encryption-key <key>

# Configure TLS for DCGM
dcgm-exporter --web.config.file=/etc/dcgm/tls-config.yml

# Confidential Computing (H100 with TEE)
nvidia-smi -c CC_ON
```

**TLS Configuration (DCGM):**
```yaml
tls_server_config:
  cert_file: /etc/pki/dcgm/server.crt
  key_file: /etc/pki/dcgm/server.key
  client_auth_type: RequireAndVerifyClientCert
  client_ca_file: /etc/pki/dcgm/ca.crt
  min_version: TLS13
```

**NIST 800-53 Mapping:** SC-8, SC-13, SC-28  
**Zero Trust Principle:** Assume breach - encrypt all GPU traffic  
**Performance Impact:** 3-8% - varies by encryption type (NVLink vs PCIe)

---

### SC-12: Cryptographic Key Management
**Control Implementation:**
- Integrate GPU encryption keys with enterprise KMS
- Rotate NVLink encryption keys periodically
- Secure NVIDIA vGPU license server with HSM

**Technical Implementation:**
```bash
# Key rotation for NVLink encryption
nvidia-smi nvlink --rotate-encryption-key --key-source kms://vault.enterprise.local/gpu-keys

# vGPU License Server with HSM
cat >> /etc/nvidia/gridd.conf << EOF
ServerKeyStore=/etc/pki/nvidia/keystore.p12
ServerKeyStorePassword=<encrypted>
HSMEnabled=true
HSMProvider=PKCS11
HSMURL=pkcs11:token=nvidia-vgpu
EOF
```

**NIST 800-53 Mapping:** SC-12, SC-13  
**Zero Trust Principle:** Verify explicitly - manage GPU crypto keys centrally  
**Performance Impact:** <1% - key operations infrequent

---

### SC-28: Protection of Information at Rest
**Control Implementation:**
- Enable GPU memory encryption (framebuffer)
- Implement secure wipe on GPU deallocation
- Encrypt GPU persistent state (MIG profiles, configurations)

**Technical Implementation:**
```bash
# Enable memory encryption (H100 Confidential Computing)
nvidia-smi -i 0 --gpu-reset
nvidia-smi -i 0 -c CC_ON

# Secure memory wipe on deallocation
cat >> /etc/modprobe.d/nvidia.conf << EOF
options nvidia NVreg_RegistryDwords="RMSecureMemoryClear=1"
EOF

# Encrypt MIG configuration persistence
cryptsetup luksFormat /dev/nvme0n1p1  # For MIG config storage
```

**NIST 800-53 Mapping:** SC-28, MP-6  
**Zero Trust Principle:** Assume breach - protect data at rest  
**Performance Impact:** 2-4% - memory encryption overhead (H100 CC mode)

---
