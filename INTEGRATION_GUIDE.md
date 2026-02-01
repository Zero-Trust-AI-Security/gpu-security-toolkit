# GPU Security Toolkit - Integration Guide

This repository contains your complete GPU security documentation ready for mdBook deployment.

## Current Status

✅ **Repository structure created** - All directories in place  
✅ **mdBook configuration ready** - book.toml configured  
✅ **Table of contents complete** - 80+ chapter structure in SUMMARY.md  
✅ **GitHub Actions configured** - Auto-deploy on push  
✅ **Introduction written** - Professional README and Quick Start  
⏳ **Content splitting needed** - Your 5 large docs need to be split into chapters

## Your Source Documents (Ready to Split)

You have **~170KB of production-ready security documentation**:

1. `nvidia_gpu_security_controls.md` (27KB) - NIST 800-53 controls
2. `gpu_threat_model_frameworks.md` (46KB) - 10 frameworks + 8 threats
3. `gpu_use_case_security_guide.md` (45KB) - Platform configs + hardware
4. `gpu_forensics_complete_guide.md` (28KB) - Forensics procedures
5. `gpu_forensics_incident_response.md` (24KB) - Additional forensics

## Quick Start Options

### Option 1: Deploy Immediately (Recommended for Testing)

```bash
# 1. Create a "monolithic" version first (all content in one file per section)
cp nvidia_gpu_security_controls.md src/controls/nist-800-53-full.md
cp gpu_threat_model_frameworks.md src/threats/threat-model-full.md
cp gpu_use_case_security_guide.md src/use-cases/platform-guide-full.md
cp gpu_forensics_complete_guide.md src/forensics/forensics-full.md

# 2. Update SUMMARY.md to point to these monolithic files temporarily
# (Or use the split structure we created)

# 3. Test build
cargo install mdbook  # If not already installed
mdbook build
mdbook serve --open

# 4. Push to GitHub
git init
git add .
git commit -m "Initial commit: GPU Security Toolkit"
git remote add origin https://github.com/YOUR-ORG/gpu-security-toolkit.git
git push -u origin main
```

### Option 2: Split Content Properly (Best for Final Deployment)

Use this Python script to automatically split your documents:

```python
#!/usr/bin/env python3
# save as: split_docs.py

import re
import os
from pathlib import Path

def split_by_h2_headers(input_file, output_dir):
    """Split markdown file by ## headers"""
    
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Split on ## headers (H2)
    sections = re.split(r'^## (.+)$', content, flags=re.MULTILINE)
    
    # First section is before any H2 (overview)
    intro = sections[0].strip()
    if intro:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        with open(f"{output_dir}/README.md", 'w') as f:
            f.write(intro + "\n")
    
    # Process H2 sections
    for i in range(1, len(sections), 2):
        if i+1 >= len(sections):
            break
            
        title = sections[i].strip()
        body = sections[i+1].strip()
        
        # Create filename from title
        filename = re.sub(r'[^\w\s-]', '', title.lower())
        filename = re.sub(r'[-\s]+', '-', filename)
        filename = f"{filename}.md"
        
        # Write file
        filepath = Path(output_dir) / filename
        with open(filepath, 'w') as f:
            f.write(f"# {title}\n\n{body}\n")
        
        print(f"Created: {filepath}")

# Split all documents
split_by_h2_headers('nvidia_gpu_security_controls.md', 'src/controls')
split_by_h2_headers('gpu_threat_model_frameworks.md', 'src/threats')
split_by_h2_headers('gpu_use_case_security_guide.md', 'src/use-cases')
split_by_h2_headers('gpu_forensics_complete_guide.md', 'src/forensics')

print("\n✓ All documents split successfully!")
print("Review the files in src/ directories")
print("Update src/SUMMARY.md to link to the new files")
```

Run with:
```bash
python3 split_docs.py
```

### Option 3: Manual Organization (Most Control)

Manually copy relevant sections from your source documents to the mdBook structure:

**Example: NIST 800-53 Controls**
```bash
# Extract AC controls from nvidia_gpu_security_controls.md
# Copy to: src/controls/access-control.md

# Extract AU controls
# Copy to: src/controls/audit-accountability.md

# Etc for each control family
```

## Repository Structure

```
gpu-security-toolkit/
├── README.md                     ✅ Professional GitHub README
├── SETUP.md                      ✅ Deployment instructions
├── INTEGRATION_GUIDE.md          ✅ This file
├── LICENSE                       ✅ Apache 2.0
├── Makefile                      ✅ Installation automation
├── book.toml                     ✅ mdBook config
│
├── Source Documents (To Split)
│   ├── nvidia_gpu_security_controls.md
│   ├── gpu_threat_model_frameworks.md
│   ├── gpu_use_case_security_guide.md
│   ├── gpu_forensics_complete_guide.md
│   └── gpu_forensics_incident_response.md
│
├── src/                          ✅ mdBook source
│   ├── SUMMARY.md               ✅ 80-chapter TOC
│   ├── introduction/            ✅ Intro + Quick Start
│   ├── controls/                📝 Copy from nvidia_gpu_security_controls.md
│   ├── threats/                 📝 Copy from gpu_threat_model_frameworks.md
│   ├── use-cases/               📝 Copy from gpu_use_case_security_guide.md
│   ├── forensics/               📝 Copy from gpu_forensics_complete_guide.md
│   ├── playbooks/               📝 Extract from forensics docs
│   ├── scripts/                 ✅ Created
│   ├── monitoring/              ✅ Created
│   └── appendix/                ✅ Glossary started
│
├── scripts/                     ✅ Executable scripts
│   └── respond_cryptomining.sh  ✅ Ready to use
│
├── configs/                     📝 Add your configs here
│   ├── kubernetes/
│   ├── prometheus/
│   └── dcgm/
│
└── .github/workflows/           ✅ Auto-deployment
    └── deploy.yml
```

## Next Steps

### 1. Choose Your Approach

**Quick Test:** Use Option 1 (monolithic files)  
**Final Deployment:** Use Option 2 (automated split)  
**Maximum Control:** Use Option 3 (manual curation)

### 2. Test Locally

```bash
# Install mdbook if needed
cargo install mdbook

# Build
mdbook build

# Serve and preview
mdbook serve --open
# Opens http://localhost:3000
```

### 3. Deploy to GitHub

```bash
# Initialize repo
git init
git add .
git commit -m "Initial commit: GPU Security Toolkit"

# Create repo on GitHub: gpu-security-toolkit

# Push
git remote add origin https://github.com/YOUR-ORG/gpu-security-toolkit.git
git branch -M main
git push -u origin main
```

### 4. Enable GitHub Pages

1. Go to repo Settings → Pages
2. Source: Deploy from a branch
3. Branch: `gh-pages` / `(root)`
4. Save
5. Wait 2-5 minutes
6. Visit: `https://YOUR-ORG.github.io/gpu-security-toolkit/`

## Content Mapping Reference

Here's where each section of your source docs should go:

### nvidia_gpu_security_controls.md → src/controls/

- Section 1 (Overview) → README.md
- Section 2 (Access Control) → access-control.md
- Section 3 (Audit & Accountability) → audit-accountability.md
- Section 4 (Configuration Management) → configuration-management.md
- Etc for all 8 control families
- Zero Trust section → zero-trust.md
- Performance section → performance-impact.md

### gpu_threat_model_frameworks.md → src/threats/

- Overview → README.md
- Attack Surface → attack-surface.md
- MITRE ATT&CK → mitre-attack.md
- Each framework → its own file
- Each threat scenario → scenario-*.md files
- Risk matrix → risk-matrix.md

### gpu_use_case_security_guide.md → src/use-cases/

- Overview → README.md
- Workstation section → workstation.md
- Multi-GPU section → training-server.md
- HPC section → hpc.md
- vGPU section → vgpu.md
- Kubernetes section → kubernetes.md
- Each GPU family → hardware-*.md files

### gpu_forensics_complete_guide.md → Multiple sections

- Evidence collection → src/forensics/evidence-collection.md
- Volatile evidence → src/forensics/volatile-evidence.md
- Network capture → src/forensics/network-capture.md
- Timeline → src/forensics/timeline.md
- Cryptomining playbook → src/playbooks/cryptomining.md
- Model theft playbook → src/playbooks/model-theft.md
- Container escape → src/playbooks/container-escape.md
- Script docs → src/scripts/*.md

## Customization

### Update book.toml

```toml
[book]
title = "Enterprise GPU Security Toolkit"
authors = ["Your Name", "Your Team"]

[output.html]
git-repository-url = "https://github.com/YOUR-ORG/gpu-security-toolkit"
cname = "gpu-security.your-domain.com"  # Optional custom domain
```

### Update README.md

Replace placeholder URLs:
- `YOUR-ORG` → Your GitHub organization
- `your-domain.com` → Your domain (if using custom domain)

## Support

- **mdBook docs:** https://rust-lang.github.io/mdBook/
- **Setup questions:** See SETUP.md
- **GitHub Actions:** Check `.github/workflows/deploy.yml`

## Ready to Deploy?

```bash
# Quick test deployment
mdbook build && mdbook serve --open

# If it looks good
git push origin main

# Your documentation will be live at:
# https://YOUR-ORG.github.io/gpu-security-toolkit/
```

---

**Questions?** Review SETUP.md for detailed instructions.
