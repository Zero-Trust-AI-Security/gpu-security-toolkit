# Summary

[Introduction](./introduction/README.md)
- [Quick Start Guide](./introduction/quick-start.md)
- [About This Toolkit](./introduction/about.md)
- [Who Should Use This](./introduction/audience.md)
- [How to Navigate](./introduction/navigation.md)

---

# Part I: Security Controls & Architecture

- [NIST 800-53 Controls](./controls/README.md)
  - [Access Control (AC)](./controls/access-control.md)
  - [Audit & Accountability (AU)](./controls/audit-accountability.md)
  - [Configuration Management (CM)](./controls/configuration-management.md)
  - [Identification & Authentication (IA)](./controls/identification-authentication.md)
  - [System & Communications Protection (SC)](./controls/system-communications.md)
  - [System & Information Integrity (SI)](./controls/system-integrity.md)
  - [Risk Assessment (RA)](./controls/risk-assessment.md)
  - [Physical & Environmental Protection (PE)](./controls/physical-environmental.md)
  
- [Zero Trust Architecture](./controls/zero-trust.md)
  - [Never Trust, Always Verify](./controls/zero-trust.md#never-trust)
  - [Continuous Verification](./controls/zero-trust.md#continuous-verification)
  - [Microsegmentation](./controls/zero-trust.md#microsegmentation)
  
- [Performance Impact Analysis](./controls/performance-impact.md)

---

# Part II: Threat Intelligence & Risk

- [Threat Model Overview](./threats/README.md)
- [GPU Attack Surface](./threats/attack-surface.md)
- [Security Frameworks](./threats/frameworks.md)
  - [MITRE ATT&CK for GPUs](./threats/mitre-attack.md)
  - [CIS Controls](./threats/cis-controls.md)
  - [OWASP Cloud-Native](./threats/owasp.md)
  - [NIST AI RMF](./threats/ai-rmf.md)
  - [HIPAA for GPU Workloads](./threats/hipaa.md)
  - [PCI DSS](./threats/pci-dss.md)
  - [FedRAMP](./threats/fedramp.md)
  - [CMMC](./threats/cmmc.md)
  
- [Threat Scenarios](./threats/scenarios.md)
  - [Scenario 1: Cryptomining Hijacking](./threats/scenario-cryptomining.md)
  - [Scenario 2: Model Theft](./threats/scenario-model-theft.md)
  - [Scenario 3: Container Escape](./threats/scenario-container-escape.md)
  - [Scenario 4: Firmware Compromise](./threats/scenario-firmware.md)
  - [Scenario 5: Resource DoS](./threats/scenario-dos.md)
  - [Scenario 6: Driver Exploitation](./threats/scenario-driver.md)
  - [Scenario 7: Fault Injection](./threats/scenario-fault-injection.md)
  - [Scenario 8: Model Poisoning](./threats/scenario-poisoning.md)
  
- [Risk Matrix](./threats/risk-matrix.md)
- [Defense in Depth](./threats/defense-in-depth.md)

---

# Part III: Platform-Specific Security

- [GPU Deployment Scenarios](./use-cases/README.md)
- [Single GPU Workstation](./use-cases/workstation.md)
  - [Security Requirements](./use-cases/workstation.md#requirements)
  - [Configuration Scripts](./use-cases/workstation.md#configuration)
  - [Performance Impact](./use-cases/workstation.md#performance)
  
- [Multi-GPU Training Server](./use-cases/training-server.md)
  - [8-GPU Configuration](./use-cases/training-server.md#8gpu)
  - [MIG Isolation](./use-cases/training-server.md#mig)
  - [Network Fabric Security](./use-cases/training-server.md#fabric)
  
- [HPC Compute Node](./use-cases/hpc.md)
  - [SLURM Integration](./use-cases/hpc.md#slurm)
  - [InfiniBand Security](./use-cases/hpc.md#infiniband)
  - [ECC Configuration](./use-cases/hpc.md#ecc)
  
- [Virtualized GPU Server](./use-cases/vgpu.md)
  - [vGPU Profiles](./use-cases/vgpu.md#profiles)
  - [VM Isolation](./use-cases/vgpu.md#isolation)
  - [License Server Security](./use-cases/vgpu.md#license)
  
- [Container/Kubernetes GPU](./use-cases/kubernetes.md)
  - [GPU Operator Security](./use-cases/kubernetes.md#operator)
  - [Pod Security Standards](./use-cases/kubernetes.md#pod-security)
  - [Network Policies](./use-cases/kubernetes.md#network)

- [GPU Hardware Reference](./use-cases/hardware.md)
  - [Hopper Architecture (H100/H200)](./use-cases/hardware-hopper.md)
  - [Ampere Architecture (A100/A30)](./use-cases/hardware-ampere.md)
  - [Ada Lovelace (L40S/L4)](./use-cases/hardware-ada.md)
  - [Professional GPUs (RTX 6000 Ada)](./use-cases/hardware-professional.md)
  - [GPU Selection Matrix](./use-cases/hardware-selection.md)

---

# Part IV: Incident Response & Forensics

- [Incident Response Overview](./forensics/README.md)
  - [Incident Types & Priorities](./forensics/incident-types.md)
  - [Response Team Roles](./forensics/team-roles.md)
  - [Evidence Collection Principles](./forensics/evidence-principles.md)

- [Evidence Collection](./forensics/evidence-collection.md)
  - [Volatile Evidence](./forensics/volatile-evidence.md)
  - [Non-Volatile Evidence](./forensics/non-volatile-evidence.md)
  - [Network Traffic Capture](./forensics/network-capture.md)
  - [Timeline Reconstruction](./forensics/timeline.md)

- [Incident Response Playbooks](./playbooks/README.md)
  - [Playbook 1: Cryptomining Response](./playbooks/cryptomining.md)
  - [Playbook 2: Model Theft Response](./playbooks/model-theft.md)
  - [Playbook 3: Container Escape Response](./playbooks/container-escape.md)
  - [Playbook 4: Firmware Compromise Response](./playbooks/firmware.md)

- [Forensic Analysis](./forensics/analysis.md)
  - [Packet Capture Analysis](./forensics/pcap-analysis.md)
  - [Binary Analysis](./forensics/binary-analysis.md)
  - [Memory Forensics](./forensics/memory-forensics.md)
  - [Threat Intelligence Lookup](./forensics/threat-intel.md)

- [Recovery & Remediation](./forensics/recovery.md)
  - [System Hardening](./forensics/hardening.md)
  - [Baseline Restoration](./forensics/baseline.md)
  - [Verification Procedures](./forensics/verification.md)

---

# Part V: Scripts & Automation

- [Forensic Scripts](./scripts/README.md)
  - [collect_gpu_evidence.sh](./scripts/collect-evidence.md)
  - [analyze_gpu_process.sh](./scripts/analyze-process.md)
  - [capture_gpu_network.sh](./scripts/capture-network.md)
  - [reconstruct_timeline.sh](./scripts/reconstruct-timeline.md)

- [Response Automation](./scripts/automation.md)
  - [respond_cryptomining.sh](./scripts/respond-cryptomining.md)
  - [respond_model_theft.sh](./scripts/respond-model-theft.md)
  - [respond_container_escape.sh](./scripts/respond-container-escape.md)

- [Security Baselines](./scripts/baselines.md)
  - [Workstation Baseline](./scripts/baseline-workstation.md)
  - [Multi-GPU Server Baseline](./scripts/baseline-multigpu.md)
  - [HPC Baseline](./scripts/baseline-hpc.md)
  - [Kubernetes Baseline](./scripts/baseline-k8s.md)

---

# Part VI: Monitoring & Detection

- [Monitoring Overview](./monitoring/README.md)
- [DCGM Configuration](./monitoring/dcgm.md)
  - [Installation](./monitoring/dcgm.md#installation)
  - [Policy Configuration](./monitoring/dcgm.md#policies)
  - [Alert Rules](./monitoring/dcgm.md#alerts)

- [Prometheus Integration](./monitoring/prometheus.md)
  - [DCGM Exporter Setup](./monitoring/prometheus.md#exporter)
  - [Alert Rules](./monitoring/prometheus.md#rules)
  - [Dashboards](./monitoring/prometheus.md#dashboards)

- [SIEM Integration](./monitoring/siem.md)
  - [Splunk Configuration](./monitoring/siem-splunk.md)
  - [ELK Stack Configuration](./monitoring/siem-elk.md)
  - [Detection Queries](./monitoring/siem-queries.md)

- [Anomaly Detection](./monitoring/anomaly-detection.md)
  - [Cryptomining Detection](./monitoring/anomaly-cryptomining.md)
  - [Data Exfiltration Detection](./monitoring/anomaly-exfiltration.md)
  - [Insider Threat Detection](./monitoring/anomaly-insider.md)

---

# Part VII: Implementation & Deployment

- [Deployment Guide](./appendix/deployment.md)
  - [Phase 1: Foundation (Weeks 1-4)](./appendix/deployment-phase1.md)
  - [Phase 2: Access Controls (Weeks 5-8)](./appendix/deployment-phase2.md)
  - [Phase 3: Encryption & Monitoring (Weeks 9-12)](./appendix/deployment-phase3.md)
  - [Phase 4: Zero Trust (Weeks 13-16)](./appendix/deployment-phase4.md)

- [Compliance Checklists](./appendix/compliance.md)
  - [NIST 800-53 Checklist](./appendix/compliance-nist.md)
  - [FedRAMP Checklist](./appendix/compliance-fedramp.md)
  - [HIPAA Checklist](./appendix/compliance-hipaa.md)
  - [PCI DSS Checklist](./appendix/compliance-pci.md)

- [Testing & Validation](./appendix/testing.md)
  - [Security Testing](./appendix/testing-security.md)
  - [Compliance Validation](./appendix/testing-compliance.md)
  - [Tabletop Exercises](./appendix/testing-tabletop.md)

---

# Appendix

- [Glossary](./appendix/glossary.md)
- [Command Reference](./appendix/command-reference.md)
- [Configuration Examples](./appendix/config-examples.md)
- [Troubleshooting](./appendix/troubleshooting.md)
- [Additional Resources](./appendix/resources.md)
- [Contributing](./appendix/contributing.md)
- [License](./appendix/license.md)
