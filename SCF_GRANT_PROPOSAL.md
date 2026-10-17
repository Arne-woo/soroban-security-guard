# 🌟 Stellar Community Fund (SCF) Grant Application Proposal

**Project Title:** Soroban Security Guard — Lightweight Static Invariant & Auth Verifier for Soroban Smart Contracts  
**Target Track:** Soroban Tooling & Security Infrastructure  
**Requested Amount:** 30,000 XLM  
**Applicant:** Arne (Platform Architect) & AURIX OS Autonomous Engineering  

---

### 1. Elevator Pitch
Soroban Security Guard is an open-source, zero-dependency Rust CLI and static analysis engine that empowers Soroban smart contract developers to eliminate missing authorization checks, unhandled arithmetic overflows, and storage TTL expiration issues before deploying to Stellar Testnet/Mainnet.

---

### 2. Problem Statement
As the Soroban ecosystem scales, contract security remains paramount. Common issues like omitted `require_auth()` checks on storage setters, unhandled arithmetic panic traps (addressed in Stellar Issue #406), and state archival expiration due to missing `extend_ttl` calls represent recurring vulnerabilities. Existing multi-chain tools lack deep domain-specific heuristics for Soroban's unique storage and auth model.

---

### 3. Milestones & Deliverables
1. **Milestone 1 (Complete):** Core Rust analyzer CLI, 4 Soroban security rules (Auth, Checked Math, Panic, TTL), reference escrow contract, and test suite. (10,000 XLM)
2. **Milestone 2:** CI/CD GitHub Action integration (`soroban-security-action`) for automated pull request scanning in Soroban repos. (10,000 XLM)
3. **Milestone 3:** Automated Soroban WASM gas consumption and state storage footprint calculator. (10,000 XLM)
