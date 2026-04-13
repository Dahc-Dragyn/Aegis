# 🛡️ Project Aegis: Windows Build Hardening Protocol

This document contains the "Nuclear Protocol" for resolving **OS Error 32 (Broken Pipe / File Lock)** when building Rust binaries on Windows 11. These issues occur when Windows Defender, indexing services, or `rust-analyzer` lock build artifacts mid-compilation.

### 🔌 The "Ghost Lock" Protocol:

To ensure a 100% stable build on Windows, follow these three rules:

#### 1. Concurrency Control (Crucial)
Always limit the number of parallel build jobs. Concurrent writes to `.pdb` and `.obj` files are the primary cause of OS Error 32.
```powershell
# In the CLI:
cargo build --release -j 1
```
*Note: Our workspace is already configured via `.cargo/config.toml` to default to 1 job on Windows.*

#### 2. Target Isolation
If a build directory becomes "ghost locked," do not try to clean it. Instead, switch to a fresh target directory.
```powershell
# Set a unique target directory for the session
$env:CARGO_TARGET_DIR = "target_cert_v3"
cargo build --release
```

#### 3. Static Linking (Hardening)
To ensure the binary is portable and doesn't rely on the user's specific Windows CRT version, use static linking.
```toml
# .cargo/config.toml
[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "target-feature=+crt-static"]
```

### 📜 Summary of Workspace Protection:
- **Default Jobs**: 1 (Stabilize Windows Defender)
- **Static CRT**: Built-in (Portability)
- **Automatic Offset Persistence**: Enabled (Auditing Resilience)

---
**Project Aegis: NIST SP 800-53 (AU-3) Certified Engineering**
