# APPENDIX: COMMAND QUICK REFERENCE

### Emergency Response Commands

```bash
# Immediate evidence collection
sudo collect_gpu_evidence.sh INCIDENT-ID

# Kill all GPU processes (EMERGENCY ONLY)
nvidia-smi --query-compute-apps=pid --format=csv,noheader | xargs -r kill -9

# Network isolation (EMERGENCY ONLY)
for iface in $(ip link show | grep '^[0-9]' | cut -d':' -f2); do
    [ "$iface" != " lo" ] && sudo ip link set $iface down
done

# Block all outbound except SSH (EMERGENCY ONLY)
sudo iptables -P OUTPUT DROP
sudo iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

### Evidence Preservation Commands

```bash
# Archive all forensic evidence
sudo tar -czf incident-$(date +%Y%m%d).tar.gz /forensics/gpu-*

# Calculate evidence hash
sha256sum incident-*.tar.gz > incident-hash.txt

# Secure copy to evidence server
scp incident-*.tar.gz evidence-server:/secure/storage/

# Verify integrity after transfer
ssh evidence-server "cd /secure/storage && sha256sum -c -" < incident-hash.txt
```

### Post-Incident Verification

```bash
# Verify all GPU processes are authorized
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=table

# Check no suspicious network connections
lsof -i -n -P | grep nvidia

# Verify GPU configuration is secure
nvidia-smi --query-gpu=persistence_mode,ecc.mode.current,compute_mode --format=table

# Check for persistence mechanisms
sudo find /etc/cron* -type f -exec grep -l "nvidia\|cuda\|gpu" {} \;
sudo systemctl list-units --type=service | grep -i gpu
```

---
