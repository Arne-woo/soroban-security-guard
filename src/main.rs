// AURIX Soroban Security Guard v1.0
// High-performance static security analyzer and invariant verifier for Stellar Soroban contracts.
// Developed under AURIX OS Pillar 2 (Stellar Community Fund Tooling Initiative).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityAlert {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub snippet: String,
    pub recommendation: &'static str,
}

#[derive(Default)]
pub struct AnalysisReport {
    pub files_scanned: usize,
    pub total_alerts: usize,
    pub alerts: Vec<SecurityAlert>,
}

/// Recursively find all .rs files in target path
pub fn find_rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    if dir.is_file() {
        if dir.extension().and_then(|s| s.to_str()) == Some("rs") {
            results.push(dir.to_path_buf());
        }
        return results;
    }

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            if path.is_dir() {
                results.extend(find_rust_files(&path));
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                results.push(path);
            }
        }
    }
    results
}

/// Core Soroban security rules engine
pub fn analyze_soroban_code(file_path: &str, content: &str) -> Vec<SecurityAlert> {
    let mut alerts = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    let is_soroban_contract = content.contains("#[contract]")
        || content.contains("#[contractimpl]")
        || content.contains("soroban_sdk");

    // Rule 1: Missing Authentication on State Mutation (SOROBAN-AUTH-001)
    let mut in_contractimpl = false;
    let mut current_fn: Option<(String, usize)> = None;
    let mut fn_has_auth = false;
    let mut fn_mutates_state = false;
    let mut brace_depth = 0;

    for (idx, line) in lines.iter().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        if trimmed.starts_with("//") {
            continue;
        }

        if trimmed.contains("#[contractimpl]") {
            in_contractimpl = true;
        }

        // Track braces
        brace_depth += line.matches('{').count();
        let close_braces = line.matches('}').count();

        // Detect public function inside contractimpl
        if in_contractimpl && (trimmed.starts_with("pub fn ") || trimmed.contains("pub fn ")) {
            if let Some(fn_start) = trimmed.find("pub fn ") {
                let rest = &trimmed[fn_start + 7..];
                if let Some(paren) = rest.find('(') {
                    let fn_name = rest[..paren].trim().to_string();
                    current_fn = Some((fn_name, line_num));
                    fn_has_auth = false;
                    fn_mutates_state = false;
                }
            }
        }

        if current_fn.is_some() {
            // Check auth calls
            if trimmed.contains(".require_auth()") || trimmed.contains(".require_auth_for_args(") {
                fn_has_auth = true;
            }
            // Check state mutation calls
            if (trimmed.contains(".storage()") && (trimmed.contains(".set(") || trimmed.contains(".remove(")))
                || trimmed.contains("env.storage().instance().set")
                || trimmed.contains("env.storage().persistent().set")
            {
                fn_mutates_state = true;
            }
        }

        // Rule 2: Unhandled Raw Arithmetic in Contract (SOROBAN-MATH-002, Stellar Issue #406)
        if is_soroban_contract {
            let has_raw_op = (trimmed.contains(" + ") || trimmed.contains(" - ") || trimmed.contains(" * "))
                && !trimmed.starts_with("//")
                && !trimmed.contains("checked_add")
                && !trimmed.contains("checked_sub")
                && !trimmed.contains("checked_mul");

            if has_raw_op && (trimmed.contains("amount") || trimmed.contains("balance") || trimmed.contains("total") || trimmed.contains("count")) {
                alerts.push(SecurityAlert {
                    rule_id: "SOROBAN-MATH-002",
                    title: "Raw Arithmetic Operation in Soroban Contract",
                    severity: Severity::High,
                    file: file_path.to_string(),
                    line: line_num,
                    snippet: trimmed.to_string(),
                    recommendation: "Replace raw '+', '-', '*' operators with checked methods (e.g. amount.checked_add(x).ok_or(Error::Overflow)?) to prevent panics and underflows per Stellar guidelines (Issue #406).",
                });
            }
        }

        // Rule 3: Dangerous unwrap() / expect() in Public Entrypoint (SOROBAN-PANIC-003)
        if in_contractimpl && current_fn.is_some() {
            if (trimmed.contains(".unwrap()") || trimmed.contains(".expect(")) && !trimmed.starts_with("//") {
                alerts.push(SecurityAlert {
                    rule_id: "SOROBAN-PANIC-003",
                    title: "Unhandled unwrap/expect in Public Contract Function",
                    severity: Severity::Medium,
                    file: file_path.to_string(),
                    line: line_num,
                    snippet: trimmed.to_string(),
                    recommendation: "Avoid '.unwrap()' in Soroban contract functions. Return 'Result<T, Error>' with descriptive custom Soroban contract errors.",
                });
            }
        }

        // Rule 4: Instance Storage Mutation without TTL Extension (SOROBAN-TTL-004)
        if trimmed.contains(".storage().instance().set") || trimmed.contains(".storage().persistent().set") {
            let next_lines: Vec<&str> = lines.iter().skip(idx).take(15).cloned().collect();
            let has_ttl_extend = next_lines.iter().any(|l| l.contains("extend_ttl") || l.contains(".bump("));
            if !has_ttl_extend {
                alerts.push(SecurityAlert {
                    rule_id: "SOROBAN-TTL-004",
                    title: "Storage Entry Set Without TTL Renewal",
                    severity: Severity::Low,
                    file: file_path.to_string(),
                    line: line_num,
                    snippet: trimmed.to_string(),
                    recommendation: "Soroban entries expire if not extended. Always invoke 'env.storage().instance().extend_ttl(...)' when writing key state.",
                });
            }
        }

        // End of function scope
        if brace_depth >= close_braces {
            brace_depth -= close_braces;
        } else {
            brace_depth = 0;
        }

        if brace_depth == 1 && current_fn.is_some() {
            // Function completed
            if let Some((fn_name, fn_line)) = current_fn.take() {
                // If it mutates state and is not initialize/constructor and has no require_auth
                if fn_mutates_state && !fn_has_auth && !fn_name.contains("init") && !fn_name.contains("new") {
                    alerts.push(SecurityAlert {
                        rule_id: "SOROBAN-AUTH-001",
                        title: "State-Mutating Function Missing require_auth()",
                        severity: Severity::Critical,
                        file: file_path.to_string(),
                        line: fn_line,
                        snippet: format!("pub fn {}() mutates storage without caller authorization", fn_name),
                        recommendation: "Verify caller identity before mutating contract storage using 'caller.require_auth()' or 'caller.require_auth_for_args(...)'.",
                    });
                }
            }
        }
    }

    alerts
}

pub fn run_analyzer(target_path: &Path) -> AnalysisReport {
    let mut report = AnalysisReport::default();
    let files = find_rust_files(target_path);
    report.files_scanned = files.len();

    for file in files {
        let path_str = file.to_string_lossy().to_string();
        if let Ok(content) = fs::read_to_string(&file) {
            let file_alerts = analyze_soroban_code(&path_str, &content);
            report.total_alerts += file_alerts.len();
            report.alerts.extend(file_alerts);
        }
    }

    report
}

fn print_json_report(report: &AnalysisReport) {
    let critical_count = report.alerts.iter().filter(|a| a.severity == Severity::Critical).count();
    let high_count = report.alerts.iter().filter(|a| a.severity == Severity::High).count();
    let medium_count = report.alerts.iter().filter(|a| a.severity == Severity::Medium).count();
    let low_count = report.alerts.iter().filter(|a| a.severity == Severity::Low).count();

    println!("{{");
    println!("  \"tool\": \"soroban_security_guard\",");
    println!("  \"version\": \"1.0.0\",");
    println!("  \"status\": \"{}\",", if critical_count + high_count == 0 { "VERIFIED" } else { "BREACHED" });
    println!("  \"decision\": \"{}\",", if critical_count + high_count == 0 { "PASS" } else { "POISONED" });
    println!("  \"filesScanned\": {},", report.files_scanned);
    println!("  \"totalAlerts\": {},", report.total_alerts);
    println!("  \"summary\": {{");
    println!("    \"critical\": {},", critical_count);
    println!("    \"high\": {},", high_count);
    println!("    \"medium\": {},", medium_count);
    println!("    \"low\": {}", low_count);
    println!("  }},");
    println!("  \"alerts\": [");
    for (i, alert) in report.alerts.iter().enumerate() {
        let is_last = i == report.alerts.len() - 1;
        println!("    {{");
        println!("      \"ruleId\": \"{}\",", alert.rule_id);
        println!("      \"title\": \"{}\",", alert.title);
        println!("      \"severity\": \"{}\",", alert.severity.as_str());
        println!("      \"file\": \"{}\",", alert.file.replace('\\', "/"));
        println!("      \"line\": {},", alert.line);
        println!("      \"snippet\": \"{}\",", alert.snippet.replace('\"', "\\\""));
        println!("      \"recommendation\": \"{}\"", alert.recommendation.replace('\"', "\\\""));
        println!("    }}{}", if is_last { "" } else { "," });
    }
    println!("  ]");
    println!("}}");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let target = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from(".")
    };

    let as_json = args.iter().any(|a| a == "--json");

    if !as_json {
        println!("=================================================================");
        println!("🛡️ AURIX SOROBAN SECURITY GUARD v1.0 — STATIC INVARIANT ANALYZER");
        println!("Target path: {}", target.display());
        println!("=================================================================");
    }

    let report = run_analyzer(&target);

    if as_json {
        print_json_report(&report);
    } else {
        println!("\n🔍 Files scanned: {}", report.files_scanned);
        println!("🚨 Total security alerts: {}", report.total_alerts);

        for alert in &report.alerts {
            println!("\n[{}] {} ({}:{})", alert.severity.as_str(), alert.title, alert.file, alert.line);
            println!("  Rule:   {}", alert.rule_id);
            println!("  Code:   {}", alert.snippet);
            println!("  Action: {}", alert.recommendation);
        }

        println!("\n=================================================================");
        if report.alerts.iter().any(|a| a.severity == Severity::Critical || a.severity == Severity::High) {
            println!("❌ VERDICT: POISONED / INVARIANTS VIOLATED (Critical or High risks detected)");
            process::exit(1);
        } else {
            println!("✅ VERDICT: PASS / INVARIANTS VERIFIED (Clean Soroban contract)");
            process::exit(0);
        }
    }

    if report.alerts.iter().any(|a| a.severity == Severity::Critical || a.severity == Severity::High) {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_unauthenticated_state_mutation() {
        let bad_code = r#"
            #[contract]
            pub struct Vault;

            #[contractimpl]
            impl Vault {
                pub fn withdraw(env: Env, to: Address, amount: i128) {
                    // Missing require_auth!
                    env.storage().instance().set(&DataKey::Balance, &0);
                }
            }
        "#;
        let alerts = analyze_soroban_code("test.rs", bad_code);
        assert!(alerts.iter().any(|a| a.rule_id == "SOROBAN-AUTH-001"));
    }

    #[test]
    fn test_detects_raw_math_operator() {
        let bad_math = r#"
            #[contract]
            pub struct Token;

            #[contractimpl]
            impl Token {
                pub fn add_balance(env: Env, amount: i128) {
                    let total = amount + 100;
                }
            }
        "#;
        let alerts = analyze_soroban_code("test_math.rs", bad_math);
        assert!(alerts.iter().any(|a| a.rule_id == "SOROBAN-MATH-002"));
    }

    #[test]
    fn test_passes_clean_authorized_checked_contract() {
        let clean_code = r#"
            #[contract]
            pub struct CleanVault;

            #[contractimpl]
            impl CleanVault {
                pub fn deposit(env: Env, user: Address, amount: i128) -> Result<i128, Error> {
                    user.require_auth();
                    let current = 100i128;
                    let new_bal = current.checked_add(amount).ok_or(Error::Overflow)?;
                    env.storage().instance().set(&DataKey::Balance, &new_bal);
                    env.storage().instance().extend_ttl(100, 1000);
                    Ok(new_bal)
                }
            }
        "#;
        let alerts = analyze_soroban_code("clean.rs", clean_code);
        let critical_or_high = alerts.iter().filter(|a| a.severity == Severity::Critical || a.severity == Severity::High).count();
        assert_eq!(critical_or_high, 0);
    }
}
