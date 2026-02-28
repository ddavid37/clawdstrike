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

/// A row from the `organizations` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Organization {
    pub id: i64,
    pub name: String,
    pub display_name: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub verified: bool,
}

/// A row from the `org_members` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgMember {
    pub publisher_key: String,
    pub role: String,
    pub joined_at: String,
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

            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                display_name TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                verified INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS org_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL REFERENCES organizations(id),
                publisher_key TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                invited_by TEXT,
                joined_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(org_id, publisher_key)
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

    // -----------------------------------------------------------------------
    // Organizations
    // -----------------------------------------------------------------------

    /// Create a new organization. The creator automatically becomes an owner.
    /// Returns the new organization's ID.
    pub fn create_organization(
        &self,
        name: &str,
        display_name: Option<&str>,
        creator_key: &str,
    ) -> Result<i64, RegistryError> {
        let now = chrono::Utc::now().to_rfc3339();

        // Check for existing org with this name.
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM organizations WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;

        if existing.is_some() {
            return Err(RegistryError::Conflict(format!(
                "organization '{}' already exists",
                name
            )));
        }

        self.conn.execute(
            "INSERT INTO organizations (name, display_name, created_by, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![name, display_name, creator_key, now],
        )?;

        let org_id = self.conn.last_insert_rowid();

        // Creator becomes owner.
        self.conn.execute(
            "INSERT INTO org_members (org_id, publisher_key, role, invited_by, joined_at) VALUES (?1, ?2, 'owner', ?3, ?4)",
            params![org_id, creator_key, creator_key, now],
        )?;

        Ok(org_id)
    }

    /// Get an organization by name.
    pub fn get_organization(&self, name: &str) -> Result<Option<Organization>, RegistryError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, name, display_name, created_by, created_at, verified FROM organizations WHERE name = ?1",
                params![name],
                |row| {
                    Ok(Organization {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        display_name: row.get(2)?,
                        created_by: row.get(3)?,
                        created_at: row.get(4)?,
                        verified: row.get::<_, i32>(5)? != 0,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// List all organizations.
    #[allow(dead_code)]
    pub fn list_organizations(&self) -> Result<Vec<Organization>, RegistryError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, display_name, created_by, created_at, verified FROM organizations ORDER BY name ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(Organization {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    display_name: row.get(2)?,
                    created_by: row.get(3)?,
                    created_at: row.get(4)?,
                    verified: row.get::<_, i32>(5)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Add a member to an organization.
    pub fn add_org_member(
        &self,
        org_id: i64,
        publisher_key: &str,
        role: &str,
        invited_by: Option<&str>,
    ) -> Result<(), RegistryError> {
        let now = chrono::Utc::now().to_rfc3339();

        // Check if already a member.
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT role FROM org_members WHERE org_id = ?1 AND publisher_key = ?2",
                params![org_id, publisher_key],
                |row| row.get(0),
            )
            .optional()?;

        if existing.is_some() {
            return Err(RegistryError::Conflict(format!(
                "key '{}' is already a member of this organization",
                publisher_key
            )));
        }

        self.conn.execute(
            "INSERT INTO org_members (org_id, publisher_key, role, invited_by, joined_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![org_id, publisher_key, role, invited_by, now],
        )?;

        Ok(())
    }

    /// Remove a member from an organization.
    /// Returns an error if the member is the last owner.
    pub fn remove_org_member(&self, org_id: i64, publisher_key: &str) -> Result<(), RegistryError> {
        // Check the member's current role.
        let role: Option<String> = self
            .conn
            .query_row(
                "SELECT role FROM org_members WHERE org_id = ?1 AND publisher_key = ?2",
                params![org_id, publisher_key],
                |row| row.get(0),
            )
            .optional()?;

        let role = match role {
            Some(r) => r,
            None => {
                return Err(RegistryError::NotFound(
                    "member not found in organization".into(),
                ));
            }
        };

        // If the member is an owner, ensure they're not the last one.
        if role == "owner" {
            let owner_count: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM org_members WHERE org_id = ?1 AND role = 'owner'",
                params![org_id],
                |row| row.get(0),
            )?;
            if owner_count <= 1 {
                return Err(RegistryError::BadRequest(
                    "cannot remove the last owner of an organization".into(),
                ));
            }
        }

        self.conn.execute(
            "DELETE FROM org_members WHERE org_id = ?1 AND publisher_key = ?2",
            params![org_id, publisher_key],
        )?;

        Ok(())
    }

    /// List all members of an organization.
    pub fn get_org_members(&self, org_id: i64) -> Result<Vec<OrgMember>, RegistryError> {
        let mut stmt = self.conn.prepare(
            "SELECT publisher_key, role, joined_at FROM org_members WHERE org_id = ?1 ORDER BY joined_at ASC",
        )?;
        let rows = stmt
            .query_map(params![org_id], |row| {
                Ok(OrgMember {
                    publisher_key: row.get(0)?,
                    role: row.get(1)?,
                    joined_at: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get a member's role in an organization.
    pub fn get_member_role(
        &self,
        org_id: i64,
        publisher_key: &str,
    ) -> Result<Option<String>, RegistryError> {
        let role = self
            .conn
            .query_row(
                "SELECT role FROM org_members WHERE org_id = ?1 AND publisher_key = ?2",
                params![org_id, publisher_key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(role)
    }

    /// Check if a publisher key is a member of an organization (by name).
    #[allow(dead_code)]
    pub fn is_org_member(
        &self,
        org_name: &str,
        publisher_key: &str,
    ) -> Result<bool, RegistryError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM org_members m JOIN organizations o ON o.id = m.org_id WHERE o.name = ?1 AND m.publisher_key = ?2",
            params![org_name, publisher_key],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// List all packages in an organization's scope.
    pub fn list_org_packages(&self, org_name: &str) -> Result<Vec<PackageRow>, RegistryError> {
        let prefix = format!("@{}/", org_name);
        let mut stmt = self.conn.prepare(
            "SELECT name, description, created_at, updated_at FROM packages WHERE name LIKE ?1 ORDER BY name ASC",
        )?;
        let pattern = format!("{}%", prefix);
        let rows = stmt
            .query_map(params![pattern], |row| {
                Ok(PackageRow {
                    name: row.get(0)?,
                    description: row.get(1)?,
                    created_at: row.get(2)?,
                    updated_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Count members in an organization.
    pub fn count_org_members(&self, org_id: i64) -> Result<i64, RegistryError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM org_members WHERE org_id = ?1",
            params![org_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Count packages in an organization's scope.
    pub fn count_org_packages(&self, org_name: &str) -> Result<i64, RegistryError> {
        let pattern = format!("@{}/%", org_name);
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM packages WHERE name LIKE ?1",
            params![pattern],
            |row| row.get(0),
        )?;
        Ok(count)
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

    // -------------------------------------------------------------------
    // Organization tests
    // -------------------------------------------------------------------

    #[test]
    fn create_and_get_organization() {
        let db = test_db();
        let org_id = db
            .create_organization("acme", Some("Acme Corp"), "creator_key_hex")
            .unwrap();
        assert!(org_id > 0);

        let org = db.get_organization("acme").unwrap().unwrap();
        assert_eq!(org.name, "acme");
        assert_eq!(org.display_name.as_deref(), Some("Acme Corp"));
        assert_eq!(org.created_by, "creator_key_hex");
        assert!(!org.verified);
    }

    #[test]
    fn create_org_duplicate_rejected() {
        let db = test_db();
        db.create_organization("acme", None, "key1").unwrap();
        let err = db.create_organization("acme", None, "key2").unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn creator_becomes_owner() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "creator_key").unwrap();

        let role = db.get_member_role(org_id, "creator_key").unwrap();
        assert_eq!(role.as_deref(), Some("owner"));
    }

    #[test]
    fn add_and_list_org_members() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();

        db.add_org_member(org_id, "member_key", "member", Some("owner_key"))
            .unwrap();
        db.add_org_member(org_id, "maintainer_key", "maintainer", Some("owner_key"))
            .unwrap();

        let members = db.get_org_members(org_id).unwrap();
        assert_eq!(members.len(), 3); // owner + member + maintainer

        let count = db.count_org_members(org_id).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn add_duplicate_member_rejected() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();

        let err = db
            .add_org_member(org_id, "owner_key", "member", None)
            .unwrap_err();
        assert!(err.to_string().contains("already a member"));
    }

    #[test]
    fn remove_org_member() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();

        db.add_org_member(org_id, "member_key", "member", Some("owner_key"))
            .unwrap();

        db.remove_org_member(org_id, "member_key").unwrap();

        let role = db.get_member_role(org_id, "member_key").unwrap();
        assert!(role.is_none());
    }

    #[test]
    fn cannot_remove_last_owner() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();

        let err = db.remove_org_member(org_id, "owner_key").unwrap_err();
        assert!(err.to_string().contains("last owner"));
    }

    #[test]
    fn remove_owner_if_not_last() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner1").unwrap();
        db.add_org_member(org_id, "owner2", "owner", Some("owner1"))
            .unwrap();

        // Now there are two owners, removing one should work.
        db.remove_org_member(org_id, "owner1").unwrap();

        let role = db.get_member_role(org_id, "owner1").unwrap();
        assert!(role.is_none());
    }

    #[test]
    fn is_org_member_check() {
        let db = test_db();
        db.create_organization("acme", None, "owner_key").unwrap();

        assert!(db.is_org_member("acme", "owner_key").unwrap());
        assert!(!db.is_org_member("acme", "stranger_key").unwrap());
    }

    #[test]
    fn list_org_packages() {
        let db = test_db();
        db.create_organization("acme", None, "owner_key").unwrap();

        db.upsert_package("@acme/guard-a", Some("Guard A"), "2025-01-01T00:00:00Z")
            .unwrap();
        db.upsert_package("@acme/guard-b", None, "2025-01-02T00:00:00Z")
            .unwrap();
        db.upsert_package("unscoped-pkg", None, "2025-01-03T00:00:00Z")
            .unwrap();

        let packages = db.list_org_packages("acme").unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().all(|p| p.name.starts_with("@acme/")));

        let count = db.count_org_packages("acme").unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn list_organizations() {
        let db = test_db();
        db.create_organization("acme", Some("Acme Corp"), "key1")
            .unwrap();
        db.create_organization("beta", None, "key2").unwrap();

        let orgs = db.list_organizations().unwrap();
        assert_eq!(orgs.len(), 2);
        assert_eq!(orgs[0].name, "acme");
        assert_eq!(orgs[1].name, "beta");
    }

    #[test]
    fn remove_nonexistent_member_fails() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();

        let err = db.remove_org_member(org_id, "nonexistent").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
