# FORENSIC ANALYSIS PROCEDURES

### Analyzing Packet Captures

```bash
# Open in Wireshark (recommended)
wireshark gpu_traffic.pcap

# Command-line analysis with tshark

# 1. Top talkers (highest bandwidth)
tshark -r gpu_traffic.pcap -q -z conv,ip | grep -E "^[0-9]" | sort -k6 -rn | head -20

# 2. DNS queries
tshark -r gpu_traffic.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | \
  sort -u

# 3. HTTP requests
tshark -r gpu_traffic.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# 4. Connections to specific IP
tshark -r gpu_traffic.pcap -Y "ip.addr == 203.0.113.42"

# 5. Large transfers (> 10MB)
tshark -r gpu_traffic.pcap -q -z conv,ip | awk '$6 > 10000000 {print}'

# 6. SSL/TLS connections
tshark -r gpu_traffic.pcap -Y "ssl.handshake.type == 1" -T fields -e ip.dst -e ssl.handshake.extensions_server_name
```

### Checking IPs Against Threat Intelligence

```bash
# VirusTotal (requires API key)
VT_API_KEY="your_api_key_here"

check_ip() {
    ip=$1
    curl -s --request GET \
      --url "https://www.virustotal.com/api/v3/ip_addresses/$ip" \
      --header "x-apikey: $VT_API_KEY" | \
      jq -r '.data.attributes.last_analysis_stats'
}

# Check all IPs from incident
while read ip; do
    echo "Checking: $ip"
    check_ip $ip
done < remote_ips.txt

# AbuseIPDB
ABUSEIPDB_KEY="your_key_here"

check_abuse() {
    ip=$1
    curl -s -G https://api.abuseipdb.com/api/v2/check \
      --data-urlencode "ipAddress=$ip" \
      -H "Key: $ABUSEIPDB_KEY" | \
      jq -r '.data.abuseConfidenceScore'
}

# Tor exit node check
check_tor() {
    ip=$1
    curl -s "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=$ip" | \
      grep -q "^$ip$" && echo "$ip is TOR exit node"
}
```

### Binary Analysis

```bash
# Hash comparison
suspicious_binary="/proc/12345/exe"
sha256sum $suspicious_binary

# Check against VirusTotal
file_hash=$(sha256sum $suspicious_binary | cut -d' ' -f1)
curl -s --request GET \
  --url "https://www.virustotal.com/api/v3/files/$file_hash" \
  --header "x-apikey: $VT_API_KEY" | \
  jq -r '.data.attributes.last_analysis_stats'

# Extract strings for analysis
strings $suspicious_binary | grep -E "http|pool|mining|password|key" | head -50

# File type identification
file $suspicious_binary

# Check for packed/obfuscated binary
file $suspicious_binary | grep -i "packed\|upx\|strip"
```

### Memory Analysis

```bash
# If GPU memory dump was collected (gpu_memory_*.bin)

# Search for model file signatures
strings gpu_memory_12345.bin | grep -E "pytorch|tensorflow|\.pth|\.ckpt" | head -20

# Search for credentials/API keys
strings gpu_memory_12345.bin | grep -iE "password|secret|key|token|api" | head -50

# Search for network indicators
strings gpu_memory_12345.bin | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u

# Entropy analysis (high entropy = encrypted/compressed data)
python3 << EOF
import math
from collections import Counter

def calculate_entropy(data):
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count/length) * math.log2(count/length) 
                   for count in counter.values())
    return entropy

with open('gpu_memory_12345.bin', 'rb') as f:
    data = f.read(1024*1024)  # First 1MB
    entropy = calculate_entropy(data)
    print(f"Entropy: {entropy:.2f} bits/byte")
    print("7.9-8.0 = likely encrypted")
    print("4.0-6.0 = typical binary/text")
EOF
```

---
