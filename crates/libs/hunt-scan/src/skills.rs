//! Skill directory scanning — SKILL.md discovery and entity mapping.
//!
//! Agent "skills" are directory-based extensions containing a `SKILL.md` file
//! with YAML frontmatter. This module scans skill directories and maps their
//! contents to MCP entity types (Prompt, Tool, Resource) for analysis.

use std::path::Path;

use serde::Deserialize;
use tracing::warn;

use crate::models::{
    Prompt, Resource, ScanError, ServerConfig, ServerScanResult, ServerSignature, SkillServer, Tool,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by skill scanning.
#[derive(Debug, thiserror::Error)]
pub enum SkillError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Skill directory not found: {0}")]
    DirNotFound(String),
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Frontmatter
// ---------------------------------------------------------------------------

/// YAML frontmatter parsed from a SKILL.md file.
#[derive(Debug, Clone, Deserialize)]
pub struct SkillFrontmatter {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// Parse YAML frontmatter between `---` delimiters at the start of a file.
///
/// Returns `None` if the frontmatter cannot be extracted or parsed.
pub fn parse_skill_frontmatter(content: &str) -> Option<SkillFrontmatter> {
    let chunks: Vec<&str> = content.splitn(3, "---").collect();
    if chunks.len() < 3 {
        return None;
    }
    let yaml_str = chunks[1].trim();
    serde_yaml::from_str(yaml_str).ok()
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Scan a skill directory and return a [`ServerScanResult`] with its contents
/// mapped to MCP entity types.
///
/// The function looks for a `SKILL.md` (case-insensitive) in `dir`, parses its
/// YAML frontmatter, and recursively walks the directory tree to map files.
pub fn scan_skills_dir(dir: &Path) -> Result<ServerScanResult, SkillError> {
    let expanded = expand_home(dir);
    if !expanded.is_dir() {
        return Err(SkillError::DirNotFound(
            expanded.to_string_lossy().to_string(),
        ));
    }

    // Find SKILL.md (case-insensitive).
    let skill_md_name = find_skill_md(&expanded)?;
    let Some(skill_md_name) = skill_md_name else {
        return Ok(ServerScanResult {
            name: dir.file_name().map(|n| n.to_string_lossy().to_string()),
            server: ServerConfig::Skill(SkillServer {
                path: dir.to_string_lossy().to_string(),
                server_type: Some("skill".to_string()),
            }),
            signature: None,
            error: Some(ScanError::skill_scan_error(format!(
                "SKILL.md not found in {}",
                dir.display()
            ))),
        });
    };

    let skill_md_path = expanded.join(&skill_md_name);
    let content = std::fs::read_to_string(&skill_md_path)?;

    // Parse frontmatter.
    let frontmatter = parse_skill_frontmatter(&content);
    let name = frontmatter
        .as_ref()
        .and_then(|f| f.name.clone())
        .unwrap_or_else(|| {
            dir.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });
    let description = frontmatter
        .as_ref()
        .and_then(|f| f.description.clone())
        .unwrap_or_default();

    // Extract the markdown body (everything after the second ---).
    let body = content.splitn(3, "---").nth(2).unwrap_or("").to_string();

    // Build the base prompt from the SKILL.md body.
    let base_prompt = Prompt {
        name: "SKILL.md".to_string(),
        description: Some(body),
        arguments: vec![],
    };

    // Traverse directory tree.
    let (mut prompts_json, resources_json, tools) =
        traverse_skill_tree(&expanded, None, &skill_md_name);

    // Prepend base prompt.
    let base_prompt_json = serde_json::to_value(&base_prompt).unwrap_or(serde_json::Value::Null);
    prompts_json.insert(0, base_prompt_json);

    // Build synthetic metadata.
    let metadata = serde_json::json!({
        "protocolVersion": "built-in",
        "instructions": description,
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": name,
            "version": "skills"
        }
    });

    let signature = ServerSignature {
        metadata,
        prompts: prompts_json,
        resources: resources_json,
        resource_templates: vec![],
        tools,
    };

    Ok(ServerScanResult {
        name: Some(name),
        server: ServerConfig::Skill(SkillServer {
            path: dir.to_string_lossy().to_string(),
            server_type: Some("skill".to_string()),
        }),
        signature: Some(signature),
        error: None,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Find a `SKILL.md` file (case-insensitive) in the given directory.
fn find_skill_md(dir: &Path) -> Result<Option<String>, SkillError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name.to_lowercase() == "skill.md" {
            return Ok(Some(name.to_string()));
        }
    }
    Ok(None)
}

/// Recursively traverse the skill directory tree and map files to entity types.
///
/// Returns `(prompts, resources, tools)` as serde_json Value vecs and Tool vecs.
fn traverse_skill_tree(
    skill_root: &Path,
    relative_path: Option<&str>,
    skill_md_name: &str,
) -> (Vec<serde_json::Value>, Vec<serde_json::Value>, Vec<Tool>) {
    let current_dir = match relative_path {
        Some(rel) => skill_root.join(rel),
        None => skill_root.to_path_buf(),
    };

    let mut prompts = Vec::new();
    let mut resources = Vec::new();
    let mut tools = Vec::new();

    let entries = match std::fs::read_dir(&current_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(dir = %current_dir.display(), error = %e, "Failed to read skill directory");
            return (prompts, resources, tools);
        }
    };

    for entry in entries {
        let Ok(entry) = entry else { continue };
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy().to_string();
        let full_path = entry.path();

        let relative_full = match relative_path {
            Some(rel) => format!("{rel}/{name}"),
            None => name.clone(),
        };

        if full_path.is_dir() {
            let (p, r, t) = traverse_skill_tree(skill_root, Some(&relative_full), skill_md_name);
            prompts.extend(p);
            resources.extend(r);
            tools.extend(t);
            continue;
        }

        // Skip the SKILL.md itself at the root level.
        if relative_path.is_none() && name.to_lowercase() == skill_md_name.to_lowercase() {
            continue;
        }

        let ext = full_path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase());

        match ext.as_deref() {
            Some("md") => {
                let content = read_file_lossy(&full_path);
                let prompt = Prompt {
                    name: relative_full,
                    description: Some(content),
                    arguments: vec![],
                };
                if let Ok(val) = serde_json::to_value(&prompt) {
                    prompts.push(val);
                }
            }
            Some("py" | "js" | "ts" | "sh") => {
                let code = read_file_lossy(&full_path);
                tools.push(Tool {
                    name: name.clone(),
                    description: Some(format!(
                        "Script: {name}. Code:\n{}",
                        if code.is_empty() {
                            "No code available".to_string()
                        } else {
                            code
                        }
                    )),
                    input_schema: Some(serde_json::json!({})),
                });
            }
            _ => {
                let content = read_file_lossy(&full_path);
                let resource = Resource {
                    name: name.clone(),
                    uri: format!("skill://{}", relative_full.replace('\\', "/")),
                    description: Some(content),
                    mime_type: None,
                };
                if let Ok(val) = serde_json::to_value(&resource) {
                    resources.push(val);
                }
            }
        }
    }

    (prompts, resources, tools)
}

/// Read a file as UTF-8, falling back to a placeholder for binary content.
fn read_file_lossy(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => "Binary file. No content available.".to_string(),
    }
}

/// Expand `~` to the user's home directory.
fn expand_home(path: &Path) -> std::path::PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with("~/") || s == "~" {
        if let Some(home) = dirs::home_dir() {
            return home.join(s.strip_prefix("~/").unwrap_or(""));
        }
    }
    path.to_path_buf()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_parse_skill_frontmatter_valid() {
        let content = "---\nname: My Skill\ndescription: Does things\n---\n# Body";
        let fm = parse_skill_frontmatter(content);
        assert!(fm.is_some());
        let fm = fm.unwrap();
        assert_eq!(fm.name.as_deref(), Some("My Skill"));
        assert_eq!(fm.description.as_deref(), Some("Does things"));
    }

    #[test]
    fn test_parse_skill_frontmatter_missing_delimiters() {
        let content = "Just some markdown without frontmatter";
        assert!(parse_skill_frontmatter(content).is_none());
    }

    #[test]
    fn test_parse_skill_frontmatter_partial() {
        let content = "---\nname: Only Name\n---\nBody";
        let fm = parse_skill_frontmatter(content).unwrap();
        assert_eq!(fm.name.as_deref(), Some("Only Name"));
        assert!(fm.description.is_none());
    }

    #[test]
    fn test_scan_skills_dir_not_found() {
        let result = scan_skills_dir(Path::new("/nonexistent/path/abc123"));
        assert!(result.is_err());
        match result.unwrap_err() {
            SkillError::DirNotFound(_) => {}
            other => panic!("expected DirNotFound, got {other:?}"),
        }
    }

    #[test]
    fn test_scan_skills_dir_no_skill_md() {
        let tmp = tempdir();
        fs::write(tmp.path().join("README.md"), "hello").unwrap();
        let result = scan_skills_dir(tmp.path()).unwrap();
        assert!(result.error.is_some());
        assert!(result.signature.is_none());
    }

    #[test]
    fn test_scan_skills_dir_with_skill_md() {
        let tmp = tempdir();
        let skill_content = "---\nname: Test Skill\ndescription: A test\n---\n# Body\nContent here";
        fs::write(tmp.path().join("SKILL.md"), skill_content).unwrap();
        fs::write(tmp.path().join("helper.py"), "print('hello')").unwrap();
        fs::write(tmp.path().join("notes.md"), "# Notes").unwrap();
        fs::write(tmp.path().join("data.json"), r#"{"key": "val"}"#).unwrap();

        let result = scan_skills_dir(tmp.path()).unwrap();
        assert!(result.error.is_none());
        let sig = result.signature.unwrap();

        // Should have prompts: SKILL.md body + notes.md
        assert!(sig.prompts.len() >= 2);
        // Should have tools: helper.py
        assert_eq!(sig.tools.len(), 1);
        assert_eq!(sig.tools[0].name, "helper.py");
        // Should have resources: data.json
        assert_eq!(sig.resources.len(), 1);
    }

    #[test]
    fn test_scan_skills_dir_js_file_is_tool() {
        let tmp = tempdir();
        fs::write(
            tmp.path().join("SKILL.md"),
            "---\nname: JS Skill\n---\n# JS Skill",
        )
        .unwrap();
        fs::write(tmp.path().join("action.js"), "console.log('hello')").unwrap();

        let result = scan_skills_dir(tmp.path()).unwrap();
        let sig = result.signature.unwrap();
        assert_eq!(sig.tools.len(), 1);
        assert_eq!(sig.tools[0].name, "action.js");
        assert!(sig.tools[0]
            .description
            .as_ref()
            .unwrap()
            .contains("Script:"));
    }

    #[test]
    fn test_scan_skills_dir_ts_and_sh_are_tools() {
        let tmp = tempdir();
        fs::write(
            tmp.path().join("SKILL.md"),
            "---\nname: Multi Skill\n---\n# Body",
        )
        .unwrap();
        fs::write(tmp.path().join("run.ts"), "import something").unwrap();
        fs::write(tmp.path().join("setup.sh"), "#!/bin/bash\necho hi").unwrap();

        let result = scan_skills_dir(tmp.path()).unwrap();
        let sig = result.signature.unwrap();
        assert_eq!(sig.tools.len(), 2);
        let names: Vec<&str> = sig.tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"run.ts"));
        assert!(names.contains(&"setup.sh"));
    }

    #[test]
    fn test_scan_skills_dir_subdirectory() {
        let tmp = tempdir();
        fs::write(
            tmp.path().join("SKILL.md"),
            "---\nname: Nested\n---\n# Body",
        )
        .unwrap();
        let sub = tmp.path().join("subdir");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("nested.py"), "pass").unwrap();
        fs::write(sub.join("readme.md"), "# Nested readme").unwrap();
        fs::write(sub.join("config.yaml"), "key: val").unwrap();

        let result = scan_skills_dir(tmp.path()).unwrap();
        let sig = result.signature.unwrap();

        // nested.py -> tool
        assert!(sig.tools.iter().any(|t| t.name == "nested.py"));
        // readme.md -> prompt (plus SKILL.md body)
        assert!(sig.prompts.len() >= 2);
        // config.yaml -> resource
        assert!(sig.resources.iter().any(|r| {
            serde_json::from_value::<crate::models::Resource>(r.clone())
                .map(|res| res.name == "config.yaml")
                .unwrap_or(false)
        }));
    }

    #[test]
    fn test_scan_skills_dir_case_insensitive_skill_md() {
        let tmp = tempdir();
        // lowercase skill.md should also be found
        fs::write(
            tmp.path().join("skill.md"),
            "---\nname: Lowercase\n---\n# Body",
        )
        .unwrap();

        let result = scan_skills_dir(tmp.path()).unwrap();
        assert!(result.error.is_none());
        assert!(result.signature.is_some());
    }

    #[test]
    fn test_parse_skill_frontmatter_empty_yaml() {
        let content = "---\n---\n# Body with no frontmatter fields";
        let fm = parse_skill_frontmatter(content);
        assert!(fm.is_some());
        let fm = fm.unwrap();
        assert!(fm.name.is_none());
        assert!(fm.description.is_none());
    }

    #[test]
    fn test_parse_skill_frontmatter_single_delimiter() {
        let content = "---\nname: Only one delimiter";
        assert!(parse_skill_frontmatter(content).is_none());
    }

    #[test]
    fn test_skill_error_display() {
        let err = SkillError::DirNotFound("/missing/dir".into());
        assert!(err.to_string().contains("/missing/dir"));

        let err = SkillError::Other("custom error".into());
        assert_eq!(err.to_string(), "custom error");
    }

    /// Create a temporary directory for testing (auto-cleaned on drop).
    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create temp dir")
    }
}
