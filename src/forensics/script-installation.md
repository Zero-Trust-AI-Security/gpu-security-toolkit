# SCRIPT INSTALLATION

### Install All Forensic Tools

```bash
# Create directories
sudo mkdir -p /usr/local/bin
sudo mkdir -p /forensics
sudo chmod 700 /forensics

# Install main evidence collection script
sudo curl -o /usr/local/bin/collect_gpu_evidence.sh \
  https://your-repo/collect_gpu_evidence.sh
sudo chmod +x /usr/local/bin/collect_gpu_evidence.sh

# Install playbook scripts
for script in respond_cryptomining respond_model_theft respond_container_escape \
              analyze_gpu_process capture_gpu_network reconstruct_timeline; do
    sudo curl -o /usr/local/bin/${script}.sh \
      https://your-repo/${script}.sh
    sudo chmod +x /usr/local/bin/${script}.sh
done

# Verify installation
ls -lah /usr/local/bin/*gpu* /usr/local/bin/respond_*
```

### Required Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    nvidia-utils \
    lsof \
    tcpdump \
    tshark \
    strace \
    jq \
    dnsutils \
    net-tools \
    iproute2

# RHEL/Rocky
sudo yum install -y \
    nvidia-driver-utils \
    lsof \
    tcpdump \
    wireshark-cli \
    strace \
    jq \
    bind-utils \
    net-tools \
    iproute

# Install DCGM (recommended)
distribution=$(. /etc/os-release;echo $ID$VERSION_ID | sed -e 's/\.//g')
wget https://developer.download.nvidia.com/compute/cuda/repos/$distribution/x86_64/cuda-keyring_1.0-1_all.deb
sudo dpkg -i cuda-keyring_1.0-1_all.deb
sudo apt-get update
sudo apt-get install -y datacenter-gpu-manager
```

---
