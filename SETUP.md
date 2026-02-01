# GPU Security Toolkit - Setup Guide

This guide walks you through setting up the complete GPU Security Toolkit repository and deploying the mdBook documentation.

## Repository Structure

```
gpu-security-toolkit/
├── README.md                    # Main repository README
├── LICENSE                      # Apache 2.0 license
├── CONTRIBUTING.md              # Contribution guidelines
├── Makefile                     # Installation automation
├── book.toml                    # mdBook configuration
│
├── .github/
│   └── workflows/
│       └── deploy.yml           # Auto-deploy to GitHub Pages
│
├── src/                         # mdBook source (Markdown files)
│   ├── SUMMARY.md              # Table of contents
│   ├── introduction/           # Getting started guides
│   ├── controls/               # NIST 800-53 controls
│   ├── threats/                # Threat model & frameworks
│   ├── use-cases/              # Platform-specific security
│   ├── forensics/              # Evidence collection
│   ├── playbooks/              # Incident response
│   ├── scripts/                # Script documentation
│   ├── monitoring/             # DCGM, Prometheus, SIEM
│   └── appendix/               # Reference materials
│
├── scripts/                     # Executable scripts
│   ├── collect_gpu_evidence.sh
│   ├── respond_cryptomining.sh
│   ├── respond_model_theft.sh
│   ├── respond_container_escape.sh
│   ├── analyze_gpu_process.sh
│   ├── capture_gpu_network.sh
│   ├── baseline-workstation.sh
│   ├── baseline-multigpu.sh
│   ├── baseline-hpc.sh
│   └── baseline-k8s.sh
│
├── configs/                     # Configuration files
│   ├── kubernetes/             # K8s manifests
│   ├── prometheus/             # Alert rules
│   ├── dcgm/                   # Monitoring configs
│   └── splunk/                 # SIEM queries
│
└── theme/                       # Custom mdBook theme (optional)
    ├── custom.css
    └── custom.js
```

## Quick Setup

### 1. Create GitHub Repository

```bash
# Create new repository on GitHub
# Repository name: gpu-security-toolkit
# Description: Enterprise GPU Security: NIST 800-53 Controls, Incident Response & Forensics
# Public or Private: Your choice
# Initialize with: README (we'll overwrite it)

# Clone your new repository
git clone https://github.com/YOUR-ORG/gpu-security-toolkit.git
cd gpu-security-toolkit
```

### 2. Copy Toolkit Files

```bash
# Copy all files from your working directory
# (Assuming you have the files from this session)

cp -r /path/to/gpu-security-toolkit/* .

# Or manually copy:
# - book.toml
# - README.md
# - LICENSE
# - Makefile
# - src/ directory
# - scripts/ directory
# - .github/ directory
```

### 3. Organize Your Existing Content

You have these documents that need to be split into mdBook chapters:

1. **nvidia_gpu_security_controls.md** → Split into `src/controls/*.md`
2. **gpu_threat_model_frameworks.md** → Split into `src/threats/*.md`
3. **gpu_use_case_security_guide.md** → Split into `src/use-cases/*.md`
4. **gpu_forensics_complete_guide.md** → Split into `src/forensics/*.md` and `src/playbooks/*.md`
5. **gpu_security_diagrams.pptx** → Add to `src/introduction/` or as downloadable asset

#### Content Splitting Example

```bash
# Example: Split controls document
# From: nvidia_gpu_security_controls.md
# To:   src/controls/access-control.md (AC controls)
#       src/controls/audit-accountability.md (AU controls)
#       src/controls/configuration-management.md (CM controls)
#       ... etc

# You can use this script to help:
python3 split_documents.py
```

### 4. Commit Initial Setup

```bash
git add .
git commit -m "Initial commit: GPU Security Toolkit mdBook setup"
git push origin main
```

### 5. Enable GitHub Pages

1. Go to repository Settings → Pages
2. Source: **Deploy from a branch**
3. Branch: **gh-pages** / **(root)**
4. Save

GitHub Actions will automatically build and deploy on every push to main.

## Local Development

### Install Dependencies

```bash
# Install Rust (required for mdbook)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install mdbook
cargo install mdbook

# Verify installation
mdbook --version
```

### Build and Serve Locally

```bash
# Build the book
mdbook build

# Serve with live reload (opens browser automatically)
mdbook serve --open

# Or serve on specific port
mdbook serve --port 8080
```

Access at: http://localhost:3000

### Development Workflow

```bash
# 1. Make changes to src/*.md files

# 2. mdbook serve will auto-reload in browser

# 3. Commit when ready
git add src/
git commit -m "Add X section to Y chapter"
git push

# 4. GitHub Actions auto-deploys to GitHub Pages
```

## Content Organization Guide

### How to Split Your Documents

Each of your large markdown documents should be split into focused chapters:

#### Example: nvidia_gpu_security_controls.md

**Original structure:**
```markdown
# NIST 800-53 Controls
## 1. Access Control (AC)
### AC-2: Account Management
### AC-3: Access Enforcement
## 2. Audit & Accountability (AU)
...
```

**Split into:**
```
src/controls/
  ├── README.md (overview)
  ├── access-control.md (all AC controls)
  ├── audit-accountability.md (all AU controls)
  ├── configuration-management.md (all CM controls)
  ├── identification-authentication.md (all IA controls)
  ├── system-communications.md (all SC controls)
  ├── system-integrity.md (all SI controls)
  ├── risk-assessment.md (all RA controls)
  ├── physical-environmental.md (all PE controls)
  ├── zero-trust.md (Zero Trust architecture)
  └── performance-impact.md (performance analysis)
```

#### Example: gpu_threat_model_frameworks.md

**Split into:**
```
src/threats/
  ├── README.md (threat model overview)
  ├── attack-surface.md
  ├── frameworks.md (overview of all frameworks)
  ├── mitre-attack.md (MITRE ATT&CK specific)
  ├── cis-controls.md
  ├── owasp.md
  ├── ai-rmf.md
  ├── hipaa.md
  ├── pci-dss.md
  ├── fedramp.md
  ├── cmmc.md
  ├── scenarios.md (overview)
  ├── scenario-cryptomining.md
  ├── scenario-model-theft.md
  ├── scenario-container-escape.md
  ├── scenario-firmware.md
  ├── scenario-dos.md
  ├── scenario-driver.md
  ├── scenario-fault-injection.md
  ├── scenario-poisoning.md
  ├── risk-matrix.md
  └── defense-in-depth.md
```

### Semi-Automated Splitting

Create a Python script to help:

```python
#!/usr/bin/env python3
# split_documents.py

import re
import os

def split_by_headers(input_file, output_dir, header_level=2):
    """Split markdown file by headers into separate files"""
    
    with open(input_file, 'r') as f:
        content = f.read()
    
    # Split by headers (e.g., ## Header)
    pattern = f'^{"#" * header_level} (.+)$'
    sections = re.split(pattern, content, flags=re.MULTILINE)
    
    os.makedirs(output_dir, exist_ok=True)
    
    for i in range(1, len(sections), 2):
        title = sections[i].strip()
        body = sections[i+1].strip() if i+1 < len(sections) else ""
        
        # Create filename from title
        filename = title.lower().replace(' ', '-').replace('/', '-')
        filename = re.sub(r'[^a-z0-9-]', '', filename)
        filename = f"{filename}.md"
        
        # Write file
        output_path = os.path.join(output_dir, filename)
        with open(output_path, 'w') as f:
            f.write(f"# {title}\n\n{body}\n")
        
        print(f"Created: {output_path}")

# Example usage:
split_by_headers('nvidia_gpu_security_controls.md', 'src/controls', header_level=2)
split_by_headers('gpu_threat_model_frameworks.md', 'src/threats', header_level=2)
split_by_headers('gpu_use_case_security_guide.md', 'src/use-cases', header_level=2)
```

## Customization

### Theme Customization

Create `theme/custom.css`:

```css
/* Custom GPU Security Toolkit theme */

:root {
    --sidebar-bg: #1E2761;
    --sidebar-fg: #CADCFC;
    --links: #F96167;
}

.sidebar {
    background-color: var(--sidebar-bg);
}

.chapter li a {
    color: var(--sidebar-fg);
}

/* Code blocks for security scripts */
pre {
    background-color: #f6f8fa;
    border-left: 3px solid #2C5F2D;
}
```

Reference in `book.toml`:
```toml
[output.html]
additional-css = ["theme/custom.css"]
```

### Add Custom JavaScript

Create `theme/custom.js`:

```javascript
// Add copy buttons to code blocks
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('pre > code').forEach(function(codeBlock) {
        const button = document.createElement('button');
        button.className = 'copy-button';
        button.textContent = 'Copy';
        
        button.addEventListener('click', function() {
            navigator.clipboard.writeText(codeBlock.textContent);
            button.textContent = 'Copied!';
            setTimeout(() => button.textContent = 'Copy', 2000);
        });
        
        codeBlock.parentNode.insertBefore(button, codeBlock);
    });
});
```

## Deployment

### Automatic Deployment (Recommended)

GitHub Actions automatically builds and deploys on push to main:

```bash
git push origin main
# Wait ~2 minutes
# Visit: https://YOUR-ORG.github.io/gpu-security-toolkit/
```

### Manual Deployment

```bash
# Build locally
mdbook build

# The book/ directory contains the static site
# Deploy to your web server:
rsync -avz book/ user@server:/var/www/gpu-security-toolkit/
```

### Custom Domain

1. Add CNAME file to repository root:
   ```
   gpu-security.your-domain.com
   ```

2. Update DNS:
   ```
   CNAME gpu-security YOUR-ORG.github.io
   ```

3. Update `book.toml`:
   ```toml
   [output.html]
   cname = "gpu-security.your-domain.com"
   ```

## Testing

### Test mdBook Build

```bash
# Test that book builds without errors
mdbook build

# Test with strict mode (fails on warnings)
mdbook build --strict
```

### Test Scripts

```bash
# Test script syntax
for script in scripts/*.sh; do
    bash -n "$script" && echo "✓ $script" || echo "✗ $script"
done

# Run script tests (if you have a test suite)
make test
```

### Validate Links

```bash
# Install mdbook-linkcheck
cargo install mdbook-linkcheck

# Add to book.toml:
# [preprocessor.linkcheck]

# Build with link checking
mdbook build
```

## Maintenance

### Updating Content

```bash
# 1. Edit markdown files in src/
vim src/controls/access-control.md

# 2. Review locally
mdbook serve

# 3. Commit and push
git add src/controls/access-control.md
git commit -m "Update AC-2 control with new MIG requirements"
git push origin main
```

### Adding New Sections

```bash
# 1. Create new markdown file
echo "# New Chapter" > src/new-chapter.md

# 2. Add to SUMMARY.md
vim src/SUMMARY.md
# Add: - [New Chapter](./new-chapter.md)

# 3. Build and verify
mdbook build
```

### Versioning

```bash
# Tag releases
git tag -a v1.0.0 -m "Initial release"
git push origin v1.0.0

# Build specific version
git checkout v1.0.0
mdbook build
```

## Troubleshooting

### mdbook not found

```bash
# Ensure Rust is in PATH
source $HOME/.cargo/env

# Reinstall mdbook
cargo install mdbook --force
```

### GitHub Pages not updating

1. Check Actions tab for build errors
2. Verify GitHub Pages settings
3. Check branch is set to `gh-pages`
4. Wait 5-10 minutes for CDN propagation

### Broken links

```bash
# Use linkcheck preprocessor
cargo install mdbook-linkcheck

# Add to book.toml
[preprocessor.linkcheck]

# Build
mdbook build
```

### Custom domain not working

1. Verify CNAME DNS record
2. Check CNAME file in repository
3. Wait for DNS propagation (up to 48 hours)
4. Verify HTTPS certificate provisioned

## Next Steps

After setup is complete:

1. ✅ Split your documents into focused chapters
2. ✅ Test locally with `mdbook serve`
3. ✅ Push to GitHub
4. ✅ Verify GitHub Pages deployment
5. ✅ Share with your team!

## Questions?

- Documentation: https://rust-lang.github.io/mdBook/
- Issues: Create GitHub issue in your repository
- mdBook Community: https://github.com/rust-lang/mdBook/discussions

---

**Ready to deploy?**

```bash
git clone https://github.com/YOUR-ORG/gpu-security-toolkit.git
cd gpu-security-toolkit
mdbook serve --open
```
