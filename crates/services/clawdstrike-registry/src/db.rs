//! SQLite database layer for package metadata and search.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::RegistryError;

/// A row from the `packages` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageRow {
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// A row from the `versions` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionRow {
    pub name: String,
    pub version: String,
    pub pkg_type: String,
    pub checksum: String,
    pub manifest_toml: String,
    pub publisher_key: String,
    pub publisher_sig: String,
    pub registry_sig: Option<String>,
    pub dependencies_json: String,
    pub yanked: bool,
    pub published_at: String,
    /// SHA-256 hash of the publish attestation (if created).
    #[serde(default)]
    pub attestation_hash: Option<String>,
    /// Key ID of the registry key that counter-signed this version.
    #[serde(default)]
    pub key_id: Option<String>,
}

/// A row from the `api_keys` table.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ApiKeyRow {
    pub key_hash: String,
    pub publisher_key: Option<String>,
    pub created_at: String,
}

/// Search result item.
#[derive(Clone, Debug, Serialize)]
pub struct SearchResult {
    pub name: String,
    pub description: Option<String>,
    pub latest_version: Option<String>,
}

/// Database handle wrapping a SQLite connection.
pub struct RegistryDb {
    conn: Connection,
}

impl RegistryDb {
    /// Open (or create) the registry database at the given path.
    pub fn open(path: &Path) -> Result<Self, RegistryError> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    #[allow(dead_code)]
    pub fn open_in_memory() -> Result<Self, RegistryError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<(), RegistryError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS packages (
                name TEXT PRIMARY KEY,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS versions (
                name TEXT NOT NULL REFERENCES packages(name),
                version TEXT NOT NULL,
                pkg_type TEXT NOT NULL,
                checksum TEXT NOT NULL,
                manifest_toml TEXT NOT NULL,
                publisher_key TEXT NOT NULL,
                publisher_sig TEXT NOT NULL,
                registry_sig TEXT,
                dependencies_json TEXT NOT NULL DEFAULT '{}',
                yanked INTEGER NOT NULL DEFAULT 0,
                published_at TEXT NOT NULL,
                PRIMARY KEY (name, version)
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                key_hash TEXT PRIMARY KEY,
                publisher_key TEXT,
                created_at TEXT NOT NULL
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
                name, description, keywords
            );

            CREATE TABLE IF NOT EXISTS registry_keys (
                key_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                valid_until TEXT,
                status TEXT NOT NULL DEFAULT 'active'
            );
            ",
        )?;

        // Add columns that may not exist in older databases.
        // SQLite does not support ADD COLUMN IF NOT EXISTS, so we
        // swallow the "duplicate column" error.
        let _ = self
            .conn
            .execute("ALTER TABLE versions ADD COLUMN attestation_hash TEXT", []);
        let _ = self
            .conn
            .execute("ALTER TABLE versions ADD COLUMN key_id TEXT", []);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Packages
    // -----------------------------------------------------------------------

    /// Insert or update a package row. Returns `true` if a new package was created.
    pub fn upsert_package(
        &self,
        name: &str,
        description: Option<&str>,
        now: &str,
    ) -> Result<bool, RegistryError> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT name FROM packages WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;

        if existing.is_some() {
            self.conn.execute(
                "UPDATE packages SET description = COALESCE(?1, description), updated_at = ?2 WHERE name = ?3",
                params![description, now, name],
            )?;
            Ok(false)
        } else {
            self.conn.execute(
                "INSERT INTO packages (name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
                params![name, description, now],
            )?;
            // Update FTS index.
            self.conn.execute(
                "INSERT INTO search_index (name, description, keywords) VALUES (?1, ?2, '')",
                params![name, description.unwrap_or("")],
            )?;
            Ok(true)
        }
    }

    /// Get a package by name.
    pub fn get_package(&self, name: &str) -> Result<Option<PackageRow>, RegistryError> {
        let row = self
            .conn
            .query_row(
                "SELECT name, description, created_at, updated_at FROM packages WHERE name = ?1",
                params![name],
                |row| {
                    Ok(PackageRow {
                        name: row.get(0)?,
                        description: row.get(1)?,
                        created_at: row.get(2)?,
                        updated_at: row.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    // -----------------------------------------------------------------------
    // Versions
    // -----------------------------------------------------------------------

    /// Insert a new version row. Returns an error if the version already exists.
    pub fn insert_version(&self, v: &VersionRow) -> Result<(), RegistryError> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT version FROM versions WHERE name = ?1 AND version = ?2",
                params![v.name, v.version],
                |row| row.get(0),
            )
            .optional()?;

        if existing.is_some() {
            return Err(RegistryError::Conflict(format!(
                "version {} of {} already exists",
                v.version, v.name
            )));
        }

        self.conn.execute(
            "INSERT INTO versions (name, version, pkg_type, checksum, manifest_toml, publisher_key, publisher_sig, registry_sig, dependencies_json, yanked, published_at, attestation_hash, key_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                v.name,
                v.version,
                v.pkg_type,
                v.checksum,
                v.manifest_toml,
                v.publisher_key,
                v.publisher_sig,
                v.registry_sig,
                v.dependencies_json,
                v.yanked as i32,
                v.published_at,
                v.attestation_hash,
                v.key_id,
            ],
        )?;
        Ok(())
    }

    /// List all versions for a package.
    pub fn list_versions(&self, name: &str) -> Result<Vec<VersionRow>, RegistryError> {
        let mut stmt = self.conn.prepare(
            "SELECT name, version, pkg_type, checksum, manifest_toml, publisher_key, publisher_sig, registry_sig, dependencies_json, yanked, published_at, attestation_hash, key_id FROM versions WHERE name = ?1 ORDER BY published_at ASC",
        )?;
        let rows = stmt
            .query_map(params![name], |row| {
                Ok(VersionRow {
                    name: row.get(0)?,
                    version: row.get(1)?,
                    pkg_type: row.get(2)?,
                    checksum: row.get(3)?,
                    manifest_toml: row.get(4)?,
                    publisher_key: row.get(5)?,
                    publisher_sig: row.get(6)?,
                    registry_sig: row.get(7)?,
                    dependencies_json: row.get(8)?,
                    yanked: row.get::<_, i32>(9)? != 0,
                    published_at: row.get(10)?,
                    attestation_hash: row.get(11)?,
                    key_id: row.get(12)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get a specific version.
    pub fn get_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<VersionRow>, RegistryError> {
        let row = self
            .conn
            .query_row(
                "SELECT name, version, pkg_type, checksum, manifest_toml, publisher_key, publisher_sig, registry_sig, dependencies_json, yanked, published_at, attestation_hash, key_id FROM versions WHERE name = ?1 AND version = ?2",
                params![name, version],
                |row| {
                    Ok(VersionRow {
                        name: row.get(0)?,
                        version: row.get(1)?,
                        pkg_type: row.get(2)?,
                        checksum: row.get(3)?,
                        manifest_toml: row.get(4)?,
                        publisher_key: row.get(5)?,
                        publisher_sig: row.get(6)?,
                        registry_sig: row.get(7)?,
                        dependencies_json: row.get(8)?,
                        yanked: row.get::<_, i32>(9)? != 0,
                        published_at: row.get(10)?,
                        attestation_hash: row.get(11)?,
                        key_id: row.get(12)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Yank a version.
    pub fn yank_version(&self, name: &str, version: &str) -> Result<bool, RegistryError> {
        let count = self.conn.execute(
            "UPDATE versions SET yanked = 1 WHERE name = ?1 AND version = ?2 AND yanked = 0",
            params![name, version],
        )?;
        Ok(count > 0)
    }

    // -----------------------------------------------------------------------
    // Registry Keys
    // -----------------------------------------------------------------------

    /// Insert or update a registry key record.
    pub fn upsert_registry_key(
        &self,
        key_info: &crate::keys::RegistryKeyInfo,
    ) -> Result<(), RegistryError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO registry_keys (key_id, public_key, created_at, valid_until, status) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                key_info.key_id,
                key_info.public_key,
                key_info.created_at,
                key_info.valid_until,
                key_info.status.to_string(),
            ],
        )?;
        Ok(())
    }

    /// Update the attestation hash for a specific version.
    #[allow(dead_code)]
    pub fn set_attestation_hash(
        &self,
        name: &str,
        version: &str,
        attestation_hash: &str,
        key_id: &str,
    ) -> Result<(), RegistryError> {
        self.conn.execute(
            "UPDATE versions SET attestation_hash = ?1, key_id = ?2 WHERE name = ?3 AND version = ?4",
            params![attestation_hash, key_id, name, version],
        )?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Search
    // -----------------------------------------------------------------------

    /// Full-text search across packages.
    pub fn search(
        &self,
        query: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SearchResult>, RegistryError> {
        // Use FTS5 MATCH if query is non-empty, otherwise list all.
        if query.is_empty() {
            let mut stmt = self.conn.prepare(
                "SELECT p.name, p.description, (SELECT v.version FROM versions v WHERE v.name = p.name ORDER BY v.published_at DESC LIMIT 1) FROM packages p ORDER BY p.updated_at DESC LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt
                .query_map(params![limit, offset], |row| {
                    Ok(SearchResult {
                        name: row.get(0)?,
                        description: row.get(1)?,
                        latest_version: row.get(2)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        } else {
            // Sanitize query: wrap in double quotes to prevent FTS5 syntax errors from
            // user-supplied special characters.
            let safe_query = format!("\"{}\"", query.replace('"', "\"\""));
            let mut stmt = self.conn.prepare(
                "SELECT p.name, p.description, (SELECT v.version FROM versions v WHERE v.name = p.name ORDER BY v.published_at DESC LIMIT 1) FROM search_index si JOIN packages p ON p.name = si.name WHERE search_index MATCH ?1 ORDER BY rank LIMIT ?2 OFFSET ?3",
            )?;
            let rows = stmt
                .query_map(params![safe_query, limit, offset], |row| {
                    Ok(SearchResult {
                        name: row.get(0)?,
                        description: row.get(1)?,
                        latest_version: row.get(2)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        }
    }

    // -----------------------------------------------------------------------
    // API Keys
    // -----------------------------------------------------------------------

    /// Insert an API key hash.
    #[allow(dead_code)]
    pub fn insert_api_key(
        &self,
        key_hash: &str,
        publisher_key: Option<&str>,
        now: &str,
    ) -> Result<(), RegistryError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO api_keys (key_hash, publisher_key, created_at) VALUES (?1, ?2, ?3)",
            params![key_hash, publisher_key, now],
        )?;
        Ok(())
    }

    /// Look up an API key by its SHA-256 hash.
    #[allow(dead_code)]
    pub fn get_api_key(&self, key_hash: &str) -> Result<Option<ApiKeyRow>, RegistryError> {
        let row = self
            .conn
            .query_row(
                "SELECT key_hash, publisher_key, created_at FROM api_keys WHERE key_hash = ?1",
                params![key_hash],
                |row| {
                    Ok(ApiKeyRow {
                        key_hash: row.get(0)?,
                        publisher_key: row.get(1)?,
                        created_at: row.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> RegistryDb {
        RegistryDb::open_in_memory().unwrap()
    }

    #[test]
    fn create_and_get_package() {
        let db = test_db();
        let created = db
            .upsert_package("my-guard", Some("A guard"), "2025-01-01T00:00:00Z")
            .unwrap();
        assert!(created);

        let pkg = db.get_package("my-guard").unwrap().unwrap();
        assert_eq!(pkg.name, "my-guard");
        assert_eq!(pkg.description.as_deref(), Some("A guard"));
    }

    #[test]
    fn upsert_package_updates() {
        let db = test_db();
        db.upsert_package("my-guard", Some("v1"), "2025-01-01T00:00:00Z")
            .unwrap();
        let created = db
            .upsert_package("my-guard", Some("v2"), "2025-01-02T00:00:00Z")
            .unwrap();
        assert!(!created);

        let pkg = db.get_package("my-guard").unwrap().unwrap();
        assert_eq!(pkg.description.as_deref(), Some("v2"));
        assert_eq!(pkg.updated_at, "2025-01-02T00:00:00Z");
    }

    #[test]
    fn insert_and_list_versions() {
        let db = test_db();
        db.upsert_package("my-guard", None, "2025-01-01T00:00:00Z")
            .unwrap();

        let v = VersionRow {
            name: "my-guard".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc123".into(),
            manifest_toml: "[package]\nname = \"my-guard\"".into(),
            publisher_key: "pubkey_hex".into(),
            publisher_sig: "sig_hex".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
        };
        db.insert_version(&v).unwrap();

        let versions = db.list_versions("my-guard").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.0.0");
    }

    #[test]
    fn duplicate_version_rejected() {
        let db = test_db();
        db.upsert_package("pkg", None, "2025-01-01T00:00:00Z")
            .unwrap();

        let v = VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
        };
        db.insert_version(&v).unwrap();

        let err = db.insert_version(&v).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn yank_version() {
        let db = test_db();
        db.upsert_package("pkg", None, "2025-01-01T00:00:00Z")
            .unwrap();

        let v = VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
        };
        db.insert_version(&v).unwrap();

        let yanked = db.yank_version("pkg", "1.0.0").unwrap();
        assert!(yanked);

        let row = db.get_version("pkg", "1.0.0").unwrap().unwrap();
        assert!(row.yanked);

        // Yanking again returns false.
        let yanked_again = db.yank_version("pkg", "1.0.0").unwrap();
        assert!(!yanked_again);
    }

    #[test]
    fn search_packages() {
        let db = test_db();
        db.upsert_package(
            "secret-scanner",
            Some("Scans for secrets"),
            "2025-01-01T00:00:00Z",
        )
        .unwrap();
        db.upsert_package(
            "path-guard",
            Some("Path access control"),
            "2025-01-02T00:00:00Z",
        )
        .unwrap();

        let results = db.search("secret", 10, 0).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "secret-scanner");
    }

    #[test]
    fn search_empty_query_lists_all() {
        let db = test_db();
        db.upsert_package("pkg-a", None, "2025-01-01T00:00:00Z")
            .unwrap();
        db.upsert_package("pkg-b", None, "2025-01-02T00:00:00Z")
            .unwrap();

        let results = db.search("", 10, 0).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn api_key_crud() {
        let db = test_db();
        db.insert_api_key("hash123", Some("pubkey_hex"), "2025-01-01T00:00:00Z")
            .unwrap();

        let row = db.get_api_key("hash123").unwrap().unwrap();
        assert_eq!(row.publisher_key.as_deref(), Some("pubkey_hex"));

        // Non-existent key.
        assert!(db.get_api_key("nope").unwrap().is_none());
    }
}
