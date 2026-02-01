# QUICK START GUIDE

### Immediate Actions During Active Incident

```bash
# 1. COLLECT EVIDENCE FIRST (before any containment)
sudo /usr/local/bin/collect_gpu_evidence.sh INCIDENT-ID-HERE

# 2. Run appropriate playbook
sudo /usr/local/bin/respond_cryptomining.sh      # For cryptomining
sudo /usr/local/bin/respond_model_theft.sh       # For data exfiltration  
sudo /usr/local/bin/respond_container_escape.sh  # For container breakout

# 3. Preserve evidence
sudo tar -czf incident-evidence.tar.gz /forensics/gpu-incident-*/
```

---
