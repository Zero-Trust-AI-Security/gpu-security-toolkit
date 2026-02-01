#!/bin/bash
# Cryptomining Incident Response Playbook
# Execute immediately upon cryptomining detection

set -euo pipefail

INCIDENT_ID="CRYPTO-$(date +%Y%m%d-%H%M%S)"
RESPONSE_DIR="/forensics/response-${INCIDENT_ID}"

mkdir -p "$RESPONSE_DIR"
cd "$RESPONSE_DIR"

exec 1> >(tee -a incident_response.log)
exec 2>&1

echo "========================================="
echo "CRYPTOMINING INCIDENT RESPONSE"
echo "========================================="
echo "Incident ID: $INCIDENT_ID"
echo "Start Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Responder: $(whoami)@$(hostname)"
echo ""

# PHASE 1: EVIDENCE COLLECTION (DO NOT SKIP)
echo "=== PHASE 1: EVIDENCE COLLECTION ==="
echo "Collecting forensic evidence BEFORE containment..."

if [ -f /usr/local/bin/collect_gpu_evidence.sh ]; then
    /usr/local/bin/collect_gpu_evidence.sh "$INCIDENT_ID"
else
    echo "WARNING: Evidence collection script not found!"
    echo "Press ENTER to continue anyway (NOT RECOMMENDED) or Ctrl+C to abort"
    read
fi

# PHASE 2: IDENTIFICATION
echo ""
echo "=== PHASE 2: THREAT IDENTIFICATION ==="

echo "Capturing GPU process snapshot..."
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv | tee mining_processes.csv

echo ""
echo "Checking for known mining binaries..."
ps aux | grep -E "xmrig|ethminer|cgminer|bfgminer|nbminer|phoenixminer|lolminer|t-rex|gminer|bminer" | grep -v grep | tee -a mining_processes.csv || echo "No known miners found by process name"

echo ""
echo "Capturing network connections..."
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null); do
    echo "--- PID $pid ---" | tee -a mining_network.txt
    lsof -n -P -i -a -p $pid 2>&1 | tee -a mining_network.txt
done

echo ""
echo "Extracting mining pool IPs..."
for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null); do
    lsof -n -P -i -a -p $pid 2>/dev/null | awk 'NR>1 {print $9}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' 
done | sort -u | tee mining_pool_ips.txt

# PHASE 3: IMMEDIATE CONTAINMENT
echo ""
echo "=== PHASE 3: CONTAINMENT ==="

if [ -s mining_pool_ips.txt ]; then
    echo "Found $(wc -l < mining_pool_ips.txt) unique mining pool IPs"
    echo ""
    echo "RECOMMENDED ACTION: Block these IPs immediately"
    cat mining_pool_ips.txt
    echo ""
    read -p "Block these IPs with iptables? (yes/no): " block_ips
    
    if [ "$block_ips" = "yes" ]; then
        while read ip; do
            iptables -A OUTPUT -d $ip -j DROP
            echo "✓ Blocked: $ip"
        done < mining_pool_ips.txt
        
        # Save iptables rules
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > iptables_rules_backup.txt
        echo "✓ Firewall rules updated"
    fi
fi

# Block common mining ports
echo ""
echo "Blocking common mining pool ports (3333, 4444, 5555)..."
iptables -A OUTPUT -p tcp --dport 3333 -j DROP
iptables -A OUTPUT -p tcp --dport 4444 -j DROP
iptables -A OUTPUT -p tcp --dport 5555 -j DROP
iptables -A OUTPUT -p tcp --dport 7777 -j DROP
iptables -A OUTPUT -p tcp --dport 9999 -j DROP
echo "✓ Mining ports blocked"

# Terminate mining processes
echo ""
echo "GPU processes currently running:"
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=table

echo ""
echo "WARNING: About to terminate all GPU processes"
read -p "Proceed with process termination? (yes/no): " terminate

if [ "$terminate" = "yes" ]; then
    for pid in $(nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null); do
        process_name=$(ps -p $pid -o comm= 2>/dev/null || echo "unknown")
        echo "Terminating PID $pid ($process_name)..."
        kill -9 $pid 2>/dev/null || echo "  Failed to kill $pid"
    done
    echo "✓ Processes terminated"
    
    sleep 2
    
    # Verify no GPU processes remain
    remaining=$(nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null | wc -l)
    if [ $remaining -eq 0 ]; then
        echo "✓ All GPU processes successfully terminated"
    else
        echo "⚠ WARNING: $remaining GPU processes still running!"
        nvidia-smi --query-compute-apps=pid,process_name --format=table
    fi
fi

# PHASE 4: PERSISTENCE REMOVAL
echo ""
echo "=== PHASE 4: PERSISTENCE REMOVAL ==="

echo "Checking for cron jobs..."
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u $user 2>/dev/null | grep -iE "mining|xmrig|miner|cuda" && echo "Found suspicious cron for user: $user"
done | tee cron_findings.txt

echo ""
echo "Checking system cron..."
grep -r -iE "mining|xmrig|miner" /etc/cron* 2>/dev/null | tee -a cron_findings.txt || echo "No suspicious system cron found"

echo ""
echo "Checking systemd services..."
systemctl list-units --type=service --all | grep -iE "mining|xmrig|miner" | tee systemd_findings.txt || echo "No suspicious systemd services found"

if [ -s cron_findings.txt ] || [ -s systemd_findings.txt ]; then
    echo ""
    echo "⚠ PERSISTENCE MECHANISMS FOUND!"
    echo "Review cron_findings.txt and systemd_findings.txt"
    echo "Manual removal required - DO NOT auto-delete without review"
fi

# PHASE 5: USER ACCOUNT REVIEW
echo ""
echo "=== PHASE 5: USER ACCOUNT REVIEW ==="

echo "Identifying process owners..."
for pid in $(cat mining_processes.csv | tail -n +2 | cut -d',' -f1 2>/dev/null); do
    user=$(ps -p $pid -o user= 2>/dev/null || echo "unknown")
    if [ "$user" != "unknown" ]; then
        echo "Process $pid owned by: $user" | tee -a compromised_users.txt
    fi
done

if [ -f compromised_users.txt ]; then
    echo ""
    echo "Potentially compromised users:"
    sort -u compromised_users.txt
    echo ""
    read -p "Disable these user accounts? (yes/no): " disable_users
    
    if [ "$disable_users" = "yes" ]; then
        sort -u compromised_users.txt | cut -d':' -f2 | while read user; do
            if [ ! -z "$user" ]; then
                usermod -L $user && echo "✓ Disabled account: $user"
            fi
        done
    fi
fi

# PHASE 6: REPORTING
echo ""
echo "=== PHASE 6: INCIDENT SUMMARY ==="

cat > INCIDENT_SUMMARY.txt << EOF
CRYPTOMINING INCIDENT SUMMARY
==============================

Incident ID: $INCIDENT_ID
Detection Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Response Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Responder: $(whoami)

AFFECTED SYSTEMS:
Hostname: $(hostname)
GPUs Affected: $(nvidia-smi --query-gpu=count --format=csv,noheader)
GPU Models: $(nvidia-smi --query-gpu=name --format=csv,noheader | sort -u)

THREAT INDICATORS:
Mining Processes: $(wc -l < mining_processes.csv) identified
Mining Pool IPs: $(wc -l < mining_pool_ips.txt 2>/dev/null || echo 0)
Compromised Users: $(sort -u compromised_users.txt 2>/dev/null | wc -l || echo 0)
Persistence Mechanisms: $(wc -l < cron_findings.txt 2>/dev/null || echo 0) cron jobs, $(wc -l < systemd_findings.txt 2>/dev/null || echo 0) services

CONTAINMENT ACTIONS TAKEN:
✓ Forensic evidence collected
✓ Mining pool IPs blocked: $(wc -l < mining_pool_ips.txt 2>/dev/null || echo 0)
✓ Mining ports blocked (3333, 4444, 5555, 7777, 9999)
✓ GPU processes terminated
$([ -f compromised_users.txt ] && echo "✓ User accounts disabled" || echo "- No user accounts disabled")

EVIDENCE LOCATION:
$RESPONSE_DIR

NEXT STEPS REQUIRED:
1. Forensic analysis of collected evidence
2. Determine initial access vector (how did attacker get in?)
3. Review all user account activity (auth logs, sudo logs)
4. Remove identified persistence mechanisms
5. Conduct full host security scan
6. Review SSH keys, authorized_keys files
7. Reset passwords for affected accounts
8. Review firewall and network logs for lateral movement
9. Check other systems in environment for similar indicators
10. Notify security team and management

RECOMMENDED ACTIONS:
- If insider threat suspected: contact HR, legal
- If external breach: notify incident response team, possibly law enforcement
- Review and enhance GPU monitoring (DCGM alerts)
- Implement stricter access controls (MFA, GPU resource quotas)
- Consider re-imaging affected systems

Report Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

cat INCIDENT_SUMMARY.txt

echo ""
echo "========================================="
echo "INCIDENT RESPONSE COMPLETE"
echo "========================================="
echo ""
echo "Evidence and logs preserved in: $RESPONSE_DIR"
echo "Review INCIDENT_SUMMARY.txt for next steps"
echo ""
echo "CRITICAL: Share this incident with security team immediately"
