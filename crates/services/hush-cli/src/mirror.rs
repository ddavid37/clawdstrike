//! `hush pkg mirror` subcommands — mirror packages from an upstream registry.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Subcommand;

use crate::registry_config::RegistryConfig;
use crate::ExitCode;

// ---------------------------------------------------------------------------
// Clap types
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum MirrorCommands {
    /// Mirror a specific package from upstream
    Sync {
        /// Package name (e.g., @scope/guard-name)
        name: String,
        /// Specific version (default: latest)
        #[arg(long)]
        version: Option<String>,
        /// Upstream registry URL
        #[arg(long)]
        from: String,
        /// Local registry URL to push to (mutually exclusive with --output-dir)
        #[arg(long, conflicts_with = "output_dir")]
        to: Option<String>,
        /// Download to local directory instead of re-publishing
        #[arg(long, conflicts_with = "to")]
        output_dir: Option<PathBuf>,
    },
    /// Bulk mirror all packages matching a filter
    BulkSync {
        /// Scope filter (e.g., "@clawdstrike")
        #[arg(long)]
        scope: Option<String>,
        /// Minimum trust level (unverified, signed, verified, certified)
        #[arg(long, default_value = "signed")]
        min_trust: String,
        /// Upstream registry URL
        #[arg(long)]
        from: String,
        /// Local directory to save packages
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// List mirrored packages in a local directory
    List {
        /// Directory containing mirrored .cpkg files
        dir: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

pub fn cmd_mirror(
    command: MirrorCommands,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    match command {
        MirrorCommands::Sync {
            name,
            version,
            from,
            to,
            output_dir,
        } => cmd_mirror_sync(
            &name,
            version.as_deref(),
            &from,
            to.as_deref(),
            output_dir,
            stdout,
            stderr,
        ),
        MirrorCommands::BulkSync {
            scope,
            min_trust,
            from,
            output_dir,
        } => cmd_mirror_bulk_sync(
            scope.as_deref(),
            &min_trust,
            &from,
            &output_dir,
            stdout,
            stderr,
        ),
        MirrorCommands::List { dir } => cmd_mirror_list(&dir, stdout, stderr),
    }
}

// ---------------------------------------------------------------------------
// mirror sync
// ---------------------------------------------------------------------------

fn cmd_mirror_sync(
    name: &str,
    version: Option<&str>,
    from: &str,
    to: Option<&str>,
    output_dir: Option<PathBuf>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let version_segment = version.unwrap_or("latest");
    let url = format!(
        "{}/api/v1/packages/{}/{}/download",
        from.trim_end_matches('/'),
        name,
        version_segment
    );

    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let _ = writeln!(
        stdout,
        "Downloading {} v{} from {} ...",
        name, version_segment, from
    );

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: download failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(
            stderr,
            "Error: upstream registry returned HTTP {status}: {body}"
        );
        return ExitCode::RuntimeError;
    }

    let bytes = match resp.bytes() {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(stderr, "Error: failed to read response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Verify integrity: compute SHA-256 hash of downloaded bytes
    let hash = hush_core::sha256(&bytes);
    let _ = writeln!(
        stdout,
        "Downloaded {} bytes, SHA-256: {}",
        bytes.len(),
        hash.to_hex()
    );

    // Fetch and verify signature from upstream if available
    let sig_url = format!(
        "{}/api/v1/packages/{}/{}/signature",
        from.trim_end_matches('/'),
        name,
        version_segment
    );

    let verified = match client.get(&sig_url).send() {
        Ok(sig_resp) if sig_resp.status().is_success() => {
            match sig_resp.json::<clawdstrike::pkg::integrity::PackageSignature>() {
                Ok(sig) => {
                    if sig.hash != hash {
                        let _ = writeln!(
                            stderr,
                            "Error: package hash mismatch (expected {}, got {})",
                            sig.hash.to_hex(),
                            hash.to_hex()
                        );
                        return ExitCode::Fail;
                    }
                    if let Some(ref pk) = sig.public_key {
                        if pk.verify(hash.as_bytes(), &sig.signature) {
                            let _ =
                                writeln!(stdout, "Signature verified (publisher: {})", pk.to_hex());
                            true
                        } else {
                            let _ = writeln!(stderr, "Error: signature verification failed");
                            return ExitCode::Fail;
                        }
                    } else {
                        let _ = writeln!(
                            stdout,
                            "Warning: no public key in signature, hash-only verification"
                        );
                        true
                    }
                }
                Err(e) => {
                    let _ = writeln!(
                        stdout,
                        "Warning: could not parse signature: {e} (hash-only verification)"
                    );
                    true
                }
            }
        }
        _ => {
            let _ = writeln!(
                stdout,
                "Warning: no signature available from upstream (hash-only verification)"
            );
            true
        }
    };

    if !verified {
        return ExitCode::Fail;
    }

    let filename = format!(
        "{}-{}.cpkg",
        name.replace('/', "-").replace('@', ""),
        version_segment
    );

    // Save to output directory or re-publish to local registry
    if let Some(ref dir) = output_dir {
        return save_to_dir(dir, &filename, &bytes, &hash, stdout, stderr);
    }

    if let Some(to_url) = to {
        return republish_to_registry(to_url, name, &bytes, stdout, stderr);
    }

    // Default: save to current directory
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot determine current directory: {e}");
            return ExitCode::RuntimeError;
        }
    };
    save_to_dir(&cwd, &filename, &bytes, &hash, stdout, stderr)
}

fn save_to_dir(
    dir: &Path,
    filename: &str,
    bytes: &[u8],
    hash: &hush_core::Hash,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if let Err(e) = std::fs::create_dir_all(dir) {
        let _ = writeln!(
            stderr,
            "Error: cannot create directory {}: {e}",
            dir.display()
        );
        return ExitCode::RuntimeError;
    }

    let dest = dir.join(filename);
    if let Err(e) = std::fs::write(&dest, bytes) {
        let _ = writeln!(stderr, "Error: cannot write {}: {e}", dest.display());
        return ExitCode::RuntimeError;
    }

    // Write a companion .sha256 file for offline verification
    let hash_file = dest.with_extension("cpkg.sha256");
    let _ = std::fs::write(&hash_file, format!("{}  {}\n", hash.to_hex(), filename));

    let _ = writeln!(stdout, "Saved: {}", dest.display());
    ExitCode::Ok
}

fn republish_to_registry(
    to_url: &str,
    name: &str,
    bytes: &[u8],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(Some(to_url));
    let upload_url = format!(
        "{}/api/v1/packages/{}/upload",
        cfg.registry_url.trim_end_matches('/'),
        name
    );

    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let mut req = client.post(&upload_url).body(bytes.to_vec());
    if let Some(ref token) = cfg.auth_token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    match req.send() {
        Ok(resp) if resp.status().is_success() => {
            let _ = writeln!(stdout, "Published to {}", to_url);
            ExitCode::Ok
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            let _ = writeln!(
                stderr,
                "Error: target registry returned HTTP {status}: {body}"
            );
            ExitCode::RuntimeError
        }
        Err(e) => {
            let _ = writeln!(stderr, "Error: publish failed: {e}");
            ExitCode::RuntimeError
        }
    }
}

// ---------------------------------------------------------------------------
// mirror bulk-sync
// ---------------------------------------------------------------------------

fn cmd_mirror_bulk_sync(
    scope: Option<&str>,
    min_trust: &str,
    from: &str,
    output_dir: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Search upstream registry for packages
    let query = scope.unwrap_or("*");
    let search_url = format!(
        "{}/api/v1/packages?q={}&limit=1000",
        from.trim_end_matches('/'),
        query
    );

    let _ = writeln!(
        stdout,
        "Searching upstream {} for packages matching '{}' ...",
        from, query
    );

    let resp = match client.get(&search_url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: search failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(
            stderr,
            "Error: upstream registry returned HTTP {status}: {body}"
        );
        return ExitCode::RuntimeError;
    }

    let body = match resp.text() {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(stderr, "Error: failed to read response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let packages: Vec<BulkPackageEntry> = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid search response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let _ = writeln!(
        stdout,
        "Found {} packages, filtering by trust level >= {} ...",
        packages.len(),
        min_trust
    );

    let trust_order = trust_level_order(min_trust);
    let filtered: Vec<&BulkPackageEntry> = packages
        .iter()
        .filter(|p| trust_level_order(&p.trust_level) >= trust_order)
        .filter(|p| {
            if let Some(s) = scope {
                p.name.starts_with(s)
            } else {
                true
            }
        })
        .collect();

    let _ = writeln!(
        stdout,
        "Mirroring {} packages to {} ...",
        filtered.len(),
        output_dir.display()
    );

    if let Err(e) = std::fs::create_dir_all(output_dir) {
        let _ = writeln!(stderr, "Error: cannot create output directory: {e}");
        return ExitCode::RuntimeError;
    }

    let mut success = 0u32;
    let mut failed = 0u32;

    for pkg in &filtered {
        let result = cmd_mirror_sync(
            &pkg.name,
            Some(&pkg.version),
            from,
            None,
            Some(output_dir.to_path_buf()),
            stdout,
            stderr,
        );
        if result == ExitCode::Ok {
            success += 1;
        } else {
            failed += 1;
        }
    }

    let _ = writeln!(
        stdout,
        "\nBulk sync complete: {} succeeded, {} failed",
        success, failed
    );

    if failed > 0 {
        ExitCode::Warn
    } else {
        ExitCode::Ok
    }
}

#[derive(serde::Deserialize)]
struct BulkPackageEntry {
    name: String,
    version: String,
    #[serde(default = "default_trust_level")]
    trust_level: String,
}

fn default_trust_level() -> String {
    "unverified".to_string()
}

fn trust_level_order(level: &str) -> u8 {
    match level {
        "unverified" => 0,
        "signed" => 1,
        "verified" => 2,
        "certified" => 3,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// mirror list
// ---------------------------------------------------------------------------

fn cmd_mirror_list(dir: &Path, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    if !dir.is_dir() {
        let _ = writeln!(stderr, "Error: {} is not a directory", dir.display());
        return ExitCode::InvalidArgs;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot read {}: {e}", dir.display());
            return ExitCode::RuntimeError;
        }
    };

    let mut packages: Vec<MirrorListEntry> = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("cpkg") {
            continue;
        }

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

        // Check for companion .sha256 file
        let hash_file = path.with_extension("cpkg.sha256");
        let hash = if hash_file.exists() {
            std::fs::read_to_string(&hash_file)
                .ok()
                .and_then(|h| h.split_whitespace().next().map(String::from))
        } else {
            None
        };

        packages.push(MirrorListEntry {
            filename,
            size,
            hash,
        });
    }

    packages.sort_by(|a, b| a.filename.cmp(&b.filename));

    if packages.is_empty() {
        let _ = writeln!(stdout, "No .cpkg packages found in {}", dir.display());
        return ExitCode::Ok;
    }

    let _ = writeln!(stdout, "{:<50} {:>10}  SHA-256", "PACKAGE", "SIZE");
    let _ = writeln!(stdout, "{}", "-".repeat(100));

    for pkg in &packages {
        let hash_display = pkg.hash.as_deref().unwrap_or("(no hash)");
        let size_display = format_size(pkg.size);
        let _ = writeln!(
            stdout,
            "{:<50} {:>10}  {}",
            pkg.filename, size_display, hash_display
        );
    }

    let _ = writeln!(
        stdout,
        "\n{} package(s) in {}",
        packages.len(),
        dir.display()
    );
    ExitCode::Ok
}

struct MirrorListEntry {
    filename: String,
    size: u64,
    hash: Option<String>,
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_client() -> Result<reqwest::blocking::Client, reqwest::Error> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_level_ordering() {
        assert!(trust_level_order("certified") > trust_level_order("verified"));
        assert!(trust_level_order("verified") > trust_level_order("signed"));
        assert!(trust_level_order("signed") > trust_level_order("unverified"));
    }

    #[test]
    fn format_size_displays_correctly() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(2048), "2.0 KB");
        assert_eq!(format_size(1_500_000), "1.4 MB");
    }

    #[test]
    fn mirror_list_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = cmd_mirror_list(tmp.path(), &mut stdout, &mut stderr);
        assert_eq!(code, ExitCode::Ok);
        let out = String::from_utf8_lossy(&stdout);
        assert!(out.contains("No .cpkg packages found"));
    }

    #[test]
    fn mirror_list_finds_cpkg_files() {
        let tmp = tempfile::tempdir().unwrap();
        let cpkg_path = tmp.path().join("test-guard-1.0.0.cpkg");
        std::fs::write(&cpkg_path, b"fake package").unwrap();

        // Write companion hash file
        let hash_path = tmp.path().join("test-guard-1.0.0.cpkg.sha256");
        std::fs::write(&hash_path, "abc123  test-guard-1.0.0.cpkg\n").unwrap();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = cmd_mirror_list(tmp.path(), &mut stdout, &mut stderr);
        assert_eq!(code, ExitCode::Ok);
        let out = String::from_utf8_lossy(&stdout);
        assert!(out.contains("test-guard-1.0.0.cpkg"));
        assert!(out.contains("abc123"));
        assert!(out.contains("1 package(s)"));
    }

    #[test]
    fn save_to_dir_creates_hash_file() {
        let tmp = tempfile::tempdir().unwrap();
        let hash = hush_core::sha256(b"hello");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = save_to_dir(
            tmp.path(),
            "test.cpkg",
            b"hello",
            &hash,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, ExitCode::Ok);

        let saved = tmp.path().join("test.cpkg");
        assert!(saved.exists());
        assert_eq!(std::fs::read(&saved).unwrap(), b"hello");

        let hash_file = tmp.path().join("test.cpkg.sha256");
        assert!(hash_file.exists());
        let hash_content = std::fs::read_to_string(&hash_file).unwrap();
        assert!(hash_content.contains(&hash.to_hex()));
    }
}
