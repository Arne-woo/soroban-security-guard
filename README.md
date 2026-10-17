# 🛡️ Soroban Security Guard v1.0

> **Lightweight Static Invariant & Auth Verifier for Stellar Soroban Smart Contracts.**  
> Developed for the **Stellar Community Fund (SCF)** and the wider Stellar developer ecosystem.

---

## 🎯 The Problem

As developers build next-generation smart contracts on Soroban, common pitfalls can lead to critical vulnerabilities or unintended contract expiration:
1. **Omitted Authentication (`require_auth`):** Accidental state mutation without caller verification.
2. **Raw Arithmetic Overflows:** Using bare `+`, `-`, or `*` operators instead of `checked_*` methods (addressed in Stellar Issue #406).
3. **Unhandled Panics:** Using `.unwrap()` or `.expect()` in public `#[contractimpl]` functions, crashing execution ungracefully.
4. **State Archival Traps (TTL):** Mutating instance or persistent storage without renewing TTL (`extend_ttl`), leading to archived contracts.

---

## 🚀 Features

- **Blazing Fast:** Zero external runtime dependencies, native Rust binary. Scans large codebases in milliseconds.
- **CI/CD Ready:** Returns non-zero exit codes on Critical/High findings and supports machine-readable `--json` output.
- **Rule Set:**
  - `SOROBAN-AUTH-001` (Critical): Detects unauthenticated state mutations.
  - `SOROBAN-MATH-002` (High): Enforces checked math operations per Stellar standards.
  - `SOROBAN-PANIC-003` (Medium): Flags dangerous `.unwrap()` calls in contract entrypoints.
  - `SOROBAN-TTL-004` (Low): Checks for missing `extend_ttl` calls on state modification.

---

## 📦 Installation & Usage

### Build from source:
```bash
cargo build --release
```

### Run scan:
```bash
# Scan current directory:
./target/release/soroban_security_guard .

# JSON output for CI pipelines:
./target/release/soroban_security_guard ./examples --json
```

---

## 📄 License
MIT
