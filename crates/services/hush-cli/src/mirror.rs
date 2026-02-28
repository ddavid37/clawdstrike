//! `hush pkg mirror` subcommands — mirror packages from an upstream registry.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use clawdstrike::pkg::{
    archive,
    integrity::sign_package,
    manifest::parse_pkg_manifest_toml,
    merkle::{verify_inclusion_proof, InclusionProof, LeafData},
};
use hush_core::{PublicKey, Signature};

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

#[derive(Debug, serde::Deserialize)]
struct MirrorAttestation {
    checksum: String,
    publisher_key: String,
    publisher_sig: String,
    registry_sig: Option<String>,
    registry_key: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct MirrorProof {
    leaf_index: u64,
    tree_size: u64,
    hashes: Vec<String>,
    #[serde(default)]
    root: Option<String>,
    #[serde(default)]
    checkpoint_timestamp: Option<String>,
    #[serde(default)]
    checkpoint_sig: Option<String>,
    #[serde(default)]
    checkpoint_key: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct MirrorSearchResponse {
    packages: Vec<MirrorSearchEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct MirrorSearchEntry {
    name: String,
    latest_version: Option<String>,
}

fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX_UPPER[(b >> 4) as usize]));
                out.push(char::from(HEX_UPPER[(b & 0x0f) as usize]));
            }
        }
    }
    out
}

const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

fn verify_attestation(
    attestation: &MirrorAttestation,
    expected_hash: Option<&hush_core::Hash>,
    expected_registry_key: Option<&str>,
) -> Result<(bool, bool), String> {
    let content_hash = hush_core::Hash::from_hex(&attestation.checksum)
        .map_err(|e| format!("invalid checksum in attestation: {e}"))?;
    if let Some(hash) = expected_hash {
        if *hash != content_hash {
            return Err("attestation checksum mismatch".to_string());
        }
    }

    let publisher_key = PublicKey::from_hex(&attestation.publisher_key)
        .map_err(|e| format!("invalid publisher key in attestation: {e}"))?;
    let publisher_sig = Signature::from_hex(&attestation.publisher_sig)
        .map_err(|e| format!("invalid publisher signature in attestation: {e}"))?;
    if !publisher_key.verify(content_hash.as_bytes(), &publisher_sig) {
        return Err("publisher signature verification failed".to_string());
    }

    let registry_verified = if let Some(registry_sig_hex) = &attestation.registry_sig {
        let registry_key_hex = attestation
            .registry_key
            .as_deref()
            .ok_or_else(|| "registry signature present without registry key".to_string())?;
        let Some(expected) = expected_registry_key else {
            return Ok((true, false));
        };
        if expected != registry_key_hex {
            return Err(
                "attestation registry key does not match configured trust anchor".to_string(),
            );
        }
        let registry_key = PublicKey::from_hex(registry_key_hex)
            .map_err(|e| format!("invalid registry key in attestation: {e}"))?;
        let registry_sig = Signature::from_hex(registry_sig_hex)
            .map_err(|e| format!("invalid registry signature in attestation: {e}"))?;
        if !registry_key.verify(content_hash.as_bytes(), &registry_sig) {
            return Err("registry counter-signature verification failed".to_string());
        }
        true
    } else {
        false
    };

    Ok((true, registry_verified))
}

fn checkpoint_signature_message(root: &str, tree_size: u64, timestamp: &str) -> String {
    format!("clawdstrike-checkpoint:v1:{root}:{tree_size}:{timestamp}")
}

fn verify_checkpoint_signature(
    root: &str,
    tree_size: u64,
    timestamp: &str,
    sig_hex: &str,
    key_hex: &str,
) -> Result<(), String> {
    hush_core::Hash::from_hex(root).map_err(|e| format!("invalid checkpoint root hex: {e}"))?;
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|e| format!("invalid checkpoint timestamp: {e}"))?;

    let key = PublicKey::from_hex(key_hex).map_err(|e| format!("invalid checkpoint key: {e}"))?;
    let sig =
        Signature::from_hex(sig_hex).map_err(|e| format!("invalid checkpoint signature: {e}"))?;
    let message = checkpoint_signature_message(root, tree_size, timestamp);
    if key.verify(message.as_bytes(), &sig) {
        Ok(())
    } else {
        Err("checkpoint signature verification failed".to_string())
    }
}

fn verify_transparency_proof(
    name: &str,
    version: &str,
    attestation: &MirrorAttestation,
    proof: &MirrorProof,
    expected_registry_key: &str,
) -> Result<(), String> {
    let root = proof
        .root
        .as_deref()
        .ok_or_else(|| "proof response missing root".to_string())?;
    let checkpoint_timestamp = proof
        .checkpoint_timestamp
        .as_deref()
        .ok_or_else(|| "proof response missing checkpoint timestamp".to_string())?;
    let checkpoint_sig = proof
        .checkpoint_sig
        .as_deref()
        .ok_or_else(|| "proof response missing checkpoint signature".to_string())?;
    let checkpoint_key = proof
        .checkpoint_key
        .as_deref()
        .ok_or_else(|| "proof response missing checkpoint key".to_string())?;
    if checkpoint_key != expected_registry_key {
        return Err(
            "proof checkpoint key does not match configured/attested registry key".to_string(),
        );
    }
    verify_checkpoint_signature(
        root,
        proof.tree_size,
        checkpoint_timestamp,
        checkpoint_sig,
        checkpoint_key,
    )?;

    let timestamp = attestation
        .published_at
        .as_deref()
        .ok_or_else(|| "attestation missing published_at timestamp".to_string())?;
    let leaf_data = LeafData {
        package_name: name.to_string(),
        version: version.to_string(),
        content_hash: attestation.checksum.clone(),
        publisher_key: attestation.publisher_key.clone(),
        timestamp: timestamp.to_string(),
    };
    let leaf_hash = leaf_data
        .leaf_hash()
        .map_err(|e| format!("failed to build transparency leaf hash: {e}"))?
        .to_hex();
    let inclusion = InclusionProof {
        leaf_index: proof.leaf_index,
        tree_size: proof.tree_size,
        proof_path: proof.hashes.clone(),
    };
    if verify_inclusion_proof(&inclusion, &leaf_hash, root) {
        Ok(())
    } else {
        Err("merkle inclusion proof verification failed".to_string())
    }
}

fn required_registry_public_key_for_trust<'a>(
    cfg: &'a RegistryConfig,
    trust_level: &str,
) -> Result<Option<&'a str>, String> {
    if matches!(trust_level, "verified" | "certified") {
        cfg.registry_public_key
            .as_deref()
            .ok_or_else(|| {
                "registry public key trust anchor is required for verified/certified trust; \
                 set [registry].public_key or CLAWDSTRIKE_REGISTRY_PUBLIC_KEY"
                    .to_string()
            })
            .map(Some)
    } else {
        Ok(None)
    }
}

fn fetch_attestation(
    client: &reqwest::blocking::Client,
    base_url: &str,
    name: &str,
    version: &str,
) -> Result<MirrorAttestation, String> {
    let url = format!(
        "{}/api/v1/packages/{}/{}/attestation",
        base_url.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version)
    );
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("failed to fetch attestation: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "attestation endpoint returned HTTP {}",
            resp.status()
        ));
    }
    resp.json::<MirrorAttestation>()
        .map_err(|e| format!("invalid attestation response: {e}"))
}

fn resolve_latest_version(
    client: &reqwest::blocking::Client,
    from: &str,
    name: &str,
) -> Result<String, String> {
    let stats_url = format!(
        "{}/api/v1/packages/{}/stats",
        from.trim_end_matches('/'),
        urlencoding_simple(name)
    );
    let stats_resp = client
        .get(&stats_url)
        .send()
        .map_err(|e| format!("failed to fetch package stats: {e}"))?;
    if !stats_resp.status().is_success() {
        return Err(format!(
            "failed to resolve latest version (HTTP {})",
            stats_resp.status()
        ));
    }
    let stats: serde_json::Value = stats_resp
        .json()
        .map_err(|e| format!("invalid stats response: {e}"))?;
    stats
        .get("versions")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|entry| entry.get("version"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| "latest version missing from stats response".to_string())
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
    let cfg = RegistryConfig::load(None);
    let expected_registry_key = cfg.registry_public_key.as_deref();

    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let resolved_version = match version {
        Some(v) => v.to_string(),
        None => match resolve_latest_version(&client, from, name) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(stderr, "Error: {e}");
                return ExitCode::RuntimeError;
            }
        },
    };
    let version_segment = resolved_version.as_str();
    let url = format!(
        "{}/api/v1/packages/{}/{}/download",
        from.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version_segment)
    );

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

    let attestation = match fetch_attestation(&client, from, name, version_segment) {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::Fail;
        }
    };
    let (publisher_verified, registry_verified) =
        match verify_attestation(&attestation, Some(&hash), expected_registry_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(stderr, "Error: trust verification failed: {e}");
                return ExitCode::Fail;
            }
        };
    if !publisher_verified {
        let _ = writeln!(stderr, "Error: package is not publisher-signed");
        return ExitCode::Fail;
    }

    let proof_url = format!(
        "{}/api/v1/packages/{}/{}/proof",
        from.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version_segment)
    );
    let certified = if registry_verified {
        match client.get(&proof_url).send() {
            Ok(resp) if resp.status().is_success() => match resp.json::<MirrorProof>() {
                Ok(proof) => {
                    let key_for_proof = expected_registry_key
                        .or(attestation.registry_key.as_deref())
                        .ok_or_else(|| {
                            "registry key unavailable for transparency verification".to_string()
                        });
                    match key_for_proof.and_then(|k| {
                        verify_transparency_proof(name, version_segment, &attestation, &proof, k)
                    }) {
                        Ok(()) => true,
                        Err(e) => {
                            let _ =
                                writeln!(stderr, "Error: transparency verification failed: {e}");
                            return ExitCode::Fail;
                        }
                    }
                }
                Err(e) => {
                    let _ = writeln!(stderr, "Error: invalid proof response: {e}");
                    return ExitCode::Fail;
                }
            },
            Ok(resp) => {
                let _ = writeln!(
                    stderr,
                    "Error: transparency proof not available (HTTP {})",
                    resp.status()
                );
                return ExitCode::Fail;
            }
            Err(e) => {
                let _ = writeln!(stderr, "Error: cannot fetch transparency proof: {e}");
                return ExitCode::Fail;
            }
        }
    } else {
        false
    };
    let trust = if certified {
        "certified"
    } else if registry_verified {
        "verified"
    } else {
        "signed"
    };
    let _ = writeln!(stdout, "Trust verified: {}", trust);

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
        return republish_to_registry(to_url, &bytes, stdout, stderr);
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
    bytes: &[u8],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(Some(to_url));
    let upload_url = format!("{}/api/v1/packages", cfg.registry_url.trim_end_matches('/'));

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: target registry auth token missing (set CLAWDSTRIKE_AUTH_TOKEN)"
            );
            return ExitCode::ConfigError;
        }
    };

    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let keypair = match crate::registry_config::load_or_generate_publisher_keypair(&cfg, stderr) {
        Ok(kp) => kp,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let (archive_path, manifest_toml, _tmp_dir) = match write_archive_and_extract_manifest(bytes) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot parse mirrored package manifest: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let signature = match sign_package(&archive_path, &keypair) {
        Ok(sig) => sig,
        Err(e) => {
            let _ = writeln!(stderr, "Error: failed to sign package for republish: {e}");
            return ExitCode::RuntimeError;
        }
    };

    use base64::Engine as _;
    let body = serde_json::json!({
        "archive_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
        "publisher_key": keypair.public_key().to_hex(),
        "publisher_sig": signature.signature.to_hex(),
        "manifest_toml": manifest_toml,
    });

    match client
        .post(&upload_url)
        .bearer_auth(auth_token)
        .json(&body)
        .send()
    {
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

fn write_archive_and_extract_manifest(bytes: &[u8]) -> Result<(PathBuf, String, PathBuf), String> {
    let nonce: u64 = rand::Rng::random(&mut rand::rng());
    let tmp_dir = std::env::temp_dir().join(format!("clawdstrike_mirror_republish_{nonce:x}"));
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| format!("failed to create temp dir {}: {e}", tmp_dir.display()))?;
    let archive_path = tmp_dir.join("mirror.cpkg");
    std::fs::write(&archive_path, bytes).map_err(|e| {
        format!(
            "failed to write temp archive {}: {e}",
            archive_path.display()
        )
    })?;

    let unpack_dir = tmp_dir.join("unpacked");
    archive::unpack(&archive_path, &unpack_dir)
        .map_err(|e| format!("failed to unpack mirrored archive: {e}"))?;
    let manifest_path = unpack_dir.join("clawdstrike-pkg.toml");
    let manifest_toml = std::fs::read_to_string(&manifest_path).map_err(|e| {
        format!(
            "missing clawdstrike-pkg.toml in mirrored archive ({}): {e}",
            manifest_path.display()
        )
    })?;
    parse_pkg_manifest_toml(&manifest_toml)
        .map_err(|e| format!("invalid mirrored package manifest: {e}"))?;

    Ok((archive_path, manifest_toml, tmp_dir))
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
    let cfg = RegistryConfig::load(None);
    let expected_registry_key = match required_registry_public_key_for_trust(&cfg, min_trust) {
        Ok(k) => k,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::ConfigError;
        }
    };

    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Search upstream registry for packages.
    let query = scope.unwrap_or("");
    let search_url = format!(
        "{}/api/v1/search?q={}&limit=1000&offset=0",
        from.trim_end_matches('/'),
        urlencoding_simple(query)
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

    let search: MirrorSearchResponse = match resp.json() {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid search response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let _ = writeln!(
        stdout,
        "Found {} packages, verifying trust level >= {} ...",
        search.packages.len(),
        min_trust
    );

    let trust_order = trust_level_order(min_trust);
    let mut filtered: Vec<BulkPackageEntry> = Vec::new();
    for pkg in &search.packages {
        let Some(version) = pkg.latest_version.as_deref() else {
            continue;
        };
        if let Some(s) = scope {
            if !pkg.name.starts_with(s) {
                continue;
            }
        }

        let attestation = match fetch_attestation(&client, from, &pkg.name, version) {
            Ok(a) => a,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "Warning: skipping {}@{} (attestation unavailable: {})",
                    pkg.name, version, e
                );
                continue;
            }
        };
        let trust_level = match verify_attestation(&attestation, None, expected_registry_key) {
            Ok((_publisher_ok, registry_ok)) => {
                let proof_url = format!(
                    "{}/api/v1/packages/{}/{}/proof",
                    from.trim_end_matches('/'),
                    urlencoding_simple(&pkg.name),
                    urlencoding_simple(version)
                );
                let certified = if registry_ok {
                    match client.get(&proof_url).send() {
                        Ok(resp) if resp.status().is_success() => {
                            match resp.json::<MirrorProof>() {
                                Ok(proof) => expected_registry_key
                                    .or(attestation.registry_key.as_deref())
                                    .is_some_and(|k| {
                                        verify_transparency_proof(
                                            &pkg.name,
                                            version,
                                            &attestation,
                                            &proof,
                                            k,
                                        )
                                        .is_ok()
                                    }),
                                Err(_) => false,
                            }
                        }
                        _ => false,
                    }
                } else {
                    false
                };
                if certified {
                    "certified"
                } else if registry_ok {
                    "verified"
                } else {
                    "signed"
                }
            }
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "Warning: skipping {}@{} (signature verification failed: {})",
                    pkg.name, version, e
                );
                continue;
            }
        };

        if trust_level_order(trust_level) < trust_order {
            continue;
        }

        filtered.push(BulkPackageEntry {
            name: pkg.name.clone(),
            version: version.to_string(),
        });
    }

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

    for pkg in filtered {
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

struct BulkPackageEntry {
    name: String,
    version: String,
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

    #[test]
    fn certified_transparency_verification_rejects_tampered_path() {
        let registry = hush_core::Keypair::from_seed(&[55u8; 32]);
        let attestation = MirrorAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: Some("sig".to_string()),
            registry_key: Some(registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let inclusion = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let ts = "2026-02-28T00:00:00Z".to_string();
        let checkpoint_sig = registry
            .sign(checkpoint_signature_message(root.as_str(), inclusion.tree_size, &ts).as_bytes())
            .to_hex();

        let proof = MirrorProof {
            leaf_index: inclusion.leaf_index,
            tree_size: inclusion.tree_size,
            hashes: vec!["00".repeat(32)],
            root: Some(root),
            checkpoint_timestamp: Some(ts),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(registry.public_key().to_hex()),
        };

        let err = verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof,
            &registry.public_key().to_hex(),
        )
        .unwrap_err();
        assert!(err.contains("merkle inclusion proof verification failed"));
    }

    #[test]
    fn certified_transparency_verification_accepts_valid_path() {
        let registry = hush_core::Keypair::from_seed(&[56u8; 32]);
        let attestation = MirrorAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: Some("sig".to_string()),
            registry_key: Some(registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let inclusion = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let ts = "2026-02-28T00:00:00Z".to_string();
        let checkpoint_sig = registry
            .sign(checkpoint_signature_message(root.as_str(), inclusion.tree_size, &ts).as_bytes())
            .to_hex();

        let proof = MirrorProof {
            leaf_index: inclusion.leaf_index,
            tree_size: inclusion.tree_size,
            hashes: inclusion.proof_path,
            root: Some(root),
            checkpoint_timestamp: Some(ts),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(registry.public_key().to_hex()),
        };

        verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof,
            &registry.public_key().to_hex(),
        )
        .unwrap();
    }

    #[test]
    fn certified_transparency_verification_rejects_checkpoint_key_mismatch() {
        let trusted_registry = hush_core::Keypair::from_seed(&[57u8; 32]);
        let proof_signer = hush_core::Keypair::from_seed(&[58u8; 32]);
        let attestation = MirrorAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: Some("sig".to_string()),
            registry_key: Some(trusted_registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let inclusion = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let ts = "2026-02-28T00:00:00Z".to_string();
        let checkpoint_sig = proof_signer
            .sign(checkpoint_signature_message(root.as_str(), inclusion.tree_size, &ts).as_bytes())
            .to_hex();

        let proof = MirrorProof {
            leaf_index: inclusion.leaf_index,
            tree_size: inclusion.tree_size,
            hashes: inclusion.proof_path,
            root: Some(root),
            checkpoint_timestamp: Some(ts),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(proof_signer.public_key().to_hex()),
        };

        let err = verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof,
            &trusted_registry.public_key().to_hex(),
        )
        .unwrap_err();
        assert!(err.contains("checkpoint key does not match"));
    }

    #[test]
    fn certified_transparency_verification_rejects_invalid_checkpoint_timestamp() {
        let registry = hush_core::Keypair::from_seed(&[59u8; 32]);
        let attestation = MirrorAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: Some("sig".to_string()),
            registry_key: Some(registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let inclusion = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let bad_ts = "not-a-timestamp".to_string();
        let checkpoint_sig = registry
            .sign(
                checkpoint_signature_message(root.as_str(), inclusion.tree_size, &bad_ts)
                    .as_bytes(),
            )
            .to_hex();

        let proof = MirrorProof {
            leaf_index: inclusion.leaf_index,
            tree_size: inclusion.tree_size,
            hashes: inclusion.proof_path,
            root: Some(root),
            checkpoint_timestamp: Some(bad_ts),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(registry.public_key().to_hex()),
        };

        let err = verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof,
            &registry.public_key().to_hex(),
        )
        .unwrap_err();
        assert!(err.contains("invalid checkpoint timestamp"));
    }
}
