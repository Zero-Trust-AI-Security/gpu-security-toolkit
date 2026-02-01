# MONITORING & DETECTION

### DCGM Alert Configuration

```bash
# Install DCGM
sudo apt-get install -y datacenter-gpu-manager

# Start service
sudo systemctl enable dcgm
sudo systemctl start dcgm

# Create GPU group
dcgmi group -c all_gpus --addallgpus

# Configure policies for security monitoring

# Policy 1: Cryptomining detection (sustained high utilization)
dcgmi policy --set 4,20
# Alert if GPU utilization > 90% for > 20 minutes

# Policy 2: ECC error spike (fault injection attack indicator)
dcgmi policy --set 5,10
# Alert if > 10 ECC errors per minute

# Policy 3: Temperature anomaly (physical tampering)
dcgmi policy --set 1,95
# Alert if temperature > 95°C

# Policy 4: Power anomaly
dcgmi policy --set 2,350
# Alert if power > 350W (adjust for your GPU)

# Export metrics to Prometheus
dcgm-exporter --web.listen-address=:9400 --collectors=dcgm

# Configure Prometheus scrape
cat >> /etc/prometheus/prometheus.yml << EOF
scrape_configs:
  - job_name: 'dcgm'
    static_configs:
      - targets: ['localhost:9400']
EOF
```

### Prometheus Alert Rules for GPU Security

```yaml
# /etc/prometheus/gpu-security-alerts.yml

groups:
- name: gpu_security
  interval: 30s
  rules:
  
  # Cryptomining detection
  - alert: SuspectedCryptomining
    expr: DCGM_FI_DEV_GPU_UTIL > 95
    for: 20m
    labels:
      severity: critical
      category: security
    annotations:
      summary: "Suspected cryptomining on GPU {{ $labels.gpu }}"
      description: "GPU {{ $labels.gpu }} has sustained >95% utilization for 20+ minutes"
      
  # Unusual memory bandwidth (model theft indicator)
  - alert: HighMemoryBandwidth
    expr: rate(DCGM_FI_DEV_MEM_COPY_UTIL[5m]) > 90
    for: 10m
    labels:
      severity: high
      category: security
    annotations:
      summary: "Unusual memory bandwidth on GPU {{ $labels.gpu }}"
      description: "Potential model extraction or data exfiltration"
      
  # ECC error spike (fault injection)
  - alert: ECCErrorSpike
    expr: rate(DCGM_FI_DEV_ECC_DBE_VOL_TOTAL[5m]) > 10
    labels:
      severity: critical
      category: security
    annotations:
      summary: "ECC error spike on GPU {{ $labels.gpu }}"
      description: "Potential fault injection attack or hardware failure"
      
  # Temperature anomaly (physical tampering)
  - alert: TemperatureAnomaly
    expr: DCGM_FI_DEV_GPU_TEMP > 90 or DCGM_FI_DEV_GPU_TEMP < 20
    labels:
      severity: high
      category: security
    annotations:
      summary: "Temperature anomaly on GPU {{ $labels.gpu }}"
      description: "Temperature {{ $value }}°C outside normal range - potential physical tampering"
      
  # GPU process from unexpected user
  - alert: UnauthorizedGPUAccess
    expr: |
      DCGM_FI_PROF_PIPE_TENSOR_ACTIVE{user!~"authorized_user_1|authorized_user_2|root"} > 0
    labels:
      severity: high
      category: security
    annotations:
      summary: "Unauthorized GPU access by user {{ $labels.user }}"
      description: "GPU {{ $labels.gpu }} accessed by non-authorized user"
```

### SIEM Integration (Splunk Example)

```bash
# Forward GPU logs to Splunk

# 1. Install Splunk Universal Forwarder
wget -O splunkforwarder.deb 'https://download.splunk.com/products/universalforwarder/releases/9.1.2/linux/splunkforwarder-9.1.2-b6b9c8185839-linux-2.6-amd64.deb'
sudo dpkg -i splunkforwarder.deb

# 2. Configure inputs for GPU logs
cat > /opt/splunkforwarder/etc/system/local/inputs.conf << EOF
[monitor:///var/log/nvidia/*.log]
disabled = false
index = gpu_security
sourcetype = nvidia:gpu

[monitor:///forensics/*/evidence.log]
disabled = false
index = incident_response
sourcetype = gpu:forensics

[script://./bin/collect_gpu_metrics.sh]
disabled = false
interval = 60
index = gpu_metrics
sourcetype = nvidia:metrics
EOF

# 3. Create metrics collection script
cat > /opt/splunkforwarder/bin/scripts/collect_gpu_metrics.sh << 'EOF'
#!/bin/bash
# Collect GPU metrics for Splunk

timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

nvidia-smi --query-gpu=index,name,utilization.gpu,utilization.memory,memory.used,temperature.gpu,power.draw --format=csv,noheader | while IFS=',' read -r index name util_gpu util_mem mem_used temp power; do
    echo "timestamp=\"$timestamp\" gpu_index=$index gpu_name=\"$name\" utilization_gpu=$util_gpu utilization_memory=$util_mem memory_used=$mem_used temperature=$temp power_draw=$power"
done

# Also log GPU processes
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader | while IFS=',' read -r pid process mem; do
    user=$(ps -p $pid -o user= 2>/dev/null)
    echo "timestamp=\"$timestamp\" event_type=gpu_process pid=$pid process=\"$process\" gpu_memory=$mem user=\"$user\""
done
EOF

chmod +x /opt/splunkforwarder/bin/scripts/collect_gpu_metrics.sh

# 4. Restart forwarder
sudo /opt/splunkforwarder/bin/splunk restart
```

### Splunk Queries for GPU Security

```spl
# Cryptomining detection
index=gpu_metrics utilization_gpu>95
| stats count by gpu_index, user
| where count > 20

# Unusual after-hours GPU access
index=gpu_metrics
| eval hour=strftime(_time, "%H")
| where hour<6 OR hour>18
| stats count by user, gpu_index

# GPU access from non-standard users
index=gpu_metrics event_type=gpu_process
| search NOT user IN (root, dataanalyst, mlresearcher)
| table _time, user, process, gpu_memory

# ECC error correlation
index=gpu_security sourcetype=nvidia:gpu "ECC"
| rex field=_raw "GPU (?<gpu_id>\d+).*(?<ecc_count>\d+) errors"
| timechart span=5m sum(ecc_count) by gpu_id

# Incident timeline correlation
index=incident_response sourcetype=gpu:forensics
| transaction maxspan=1h gpu_index
| table _time, gpu_index, user, event_type, details
```

---
