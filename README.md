# GPU Security Toolkit
Complete security toolkit for enterprise NVIDIA GPU infrastructure. Includes NIST 800-53 controls, Zero Trust architecture, threat models, incident response playbooks, forensic scripts, and monitoring configurations for H100/A100/L40S and other datacenter GPUs.

> This repository is under significant development - please come back later.

## 📖 About This Repository

This repository is authored and published as an **mdBook** report.  
It can be:
- Read directly as Markdown in `src/`
- Built locally into HTML
- Built in CI into both HTML and PDF
 
## Build locally (Quick Start)
If you already have `mdbook` installed:

```bash  
mdbook build           # HTML at ./book/  
mdbook build -d book   # explicitly set output directory  
```
To preview locally with live reload:
```bash
mdbook serve
```
Then open:
[http://localhost:3000](http://localhost:3000)

## Local Environment Setup

Building this report locally requires:  
* Rust (via `rustup`)
* mdBook
* (Optional) Pandoc + Tectonic for PDF builds

**Full installation and setup guide:**
[docs/local_setup.md](docs/local_setup.md)

## PDF Build

The PDF is built automatically in CI using:
* `mdbook-pandoc`
* Pandoc
* Tectonic (LaTeX engine)

The GitHub Action publishes the PDF as a workflow artifact named:
`report-pdf`  

Local PDF builds are optional and documented in the setup guide.

## `book.toml` (mdBook + Pandoc PDF profile)

`mdbook-pandoc` renders the PDF using a **profile** defined in `book.toml`.

```toml
[book]
title = "GPU Security Toolkit"
authors = ["Zero Trust AI Security"]
language = "en"
multilingual = false
src = "src"

[build]
create-missing = true

# HTML (default mdBook output)
[output.html]
default-theme = "light"
git-repository-url = "https://github.com/Zero-Trust-AI-Security/gpu-security-toolkit"

# Pandoc backend to produce PDF (via LaTeX/Tectonic on CI)
[output.pandoc]

# enable some markdown extensions if you like (optional)
[output.pandoc.markdown.extensions]
gfm = true

# Define a "pdf" profile that renders to LaTeX/PDF
[output.pandoc.profile.pdf]
to = "latex"
output-file = "GPU-Security-Toolkit.pdf"
# You can tweak Pandoc variables here (margins, fontsize, geometry, etc.)
# [output.pandoc.profile.pdf.variables]
# geometry = "margin=1in"
```

## ⚠️ Disclaimer

This toolkit and report are provided for research and defensive security purposes only.  
They do not constitute compliance certification or production security guarantees.  

