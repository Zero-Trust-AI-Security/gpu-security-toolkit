# Local Environment Setup

This guide explains how to set up a local environment to build the GPU Security Toolkit using mdBook.

---

## 1. Install Rust

mdBook is installed via Rust’s package manager (`cargo`).

### Linux / macOS

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Restart your shell, then verify:

```bash
rustc --version
cargo --version
```

### Windows
1. Download the installer from `https://rustup.rs`
2. Run the installer with default options
3. Restart your terminal
4. Verify:
```powershell
rustc --version
cargo --version
```

## 2. Install mdBook
```bash
cargo install mdbook
```
Verify:
```bash
mdbook --version
```

## 3. Clone the Repository
```bash
git clone https://github.com/Zero-Trust-AI-Security/gpu-security-toolkit.git
cd gpu-security-toolkit
```

## 4. Build HTML Locally
```bash
mdbook build
```

Output will be written to:
```bash
./book/
```
Open `book/index.html` in your browser.

## 5. Live Preview (Recommended)
```bash
mdbook serve
```
Open:
```bash
http://localhost:3000
```

## 6. Optional: Local PDF Builds
PDF builds require additional tooling:
* Pandoc
* Tectonic
* mdbook-pandoc

### Install mdbook-pandoc
```bash
cargo install mdbook-pandoc
```
### Install Pandoc
[https://pandoc.org/installing.html](https://pandoc.org/installing.html)

### Install Tectonic
[https://tectonic-typesetting.github.io/en-US/install.html](https://tectonic-typesetting.github.io/en-US/install.html)

Once installed:

```bash
mdbook build
```

The PDF will be generated using the `pdf` profile in `book.toml`.
> Note: PDF generation is fully supported in CI; local PDF builds are optional.

## 7. Troubleshooting

`mdbook: command not found`

Ensure Cargo’s bin directory is in your PATH:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

### Clean rebuild
```bash
mdbook clean
mdbook build
```
