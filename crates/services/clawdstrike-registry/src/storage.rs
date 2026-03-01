//! Content-addressed blob storage for .cpkg archives.

use std::fs;
use std::path::PathBuf;

use crate::error::RegistryError;

/// Filesystem-based content-addressed blob storage.
pub struct BlobStorage {
    root: PathBuf,
}

impl BlobStorage {
    /// Create a new blob storage rooted at the given directory.
    pub fn new(root: PathBuf) -> Result<Self, RegistryError> {
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Store raw bytes and return the SHA-256 hex digest used as the key.
    #[allow(dead_code)]
    pub fn store(&self, data: &[u8]) -> Result<String, RegistryError> {
        let hash = hush_core::sha256_hex(data);
        self.ensure_parent(&hash)?;
        let blob_path = self.blob_path(&hash);

        if !blob_path.exists() {
            // Write to a temporary file first, then rename for atomicity.
            let tmp_path = self.root.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
            fs::write(&tmp_path, data)?;
            fs::rename(&tmp_path, &blob_path)?;
        }

        Ok(hash)
    }

    /// Load raw bytes by SHA-256 hex digest.
    pub fn load(&self, hash: &str) -> Result<Vec<u8>, RegistryError> {
        let canonical = Self::canonical_hash(hash)?;
        let blob_path = self.blob_path(&canonical);
        if !blob_path.exists() {
            return Err(RegistryError::NotFound(format!(
                "blob not found: {canonical}"
            )));
        }
        Ok(fs::read(&blob_path)?)
    }

    /// Check if a blob exists.
    #[allow(dead_code)]
    pub fn exists(&self, hash: &str) -> bool {
        Self::canonical_hash(hash)
            .ok()
            .is_some_and(|canonical| self.blob_path(&canonical).exists())
    }

    /// Get the filesystem path for a blob.
    fn blob_path(&self, hash: &str) -> PathBuf {
        // Use a two-level directory structure (first 2 chars / rest) to avoid
        // too many files in a single directory.
        let (prefix, _rest) = if hash.len() >= 2 {
            hash.split_at(2)
        } else {
            (hash, "")
        };
        self.root.join(prefix).join(hash)
    }

    fn canonical_hash(hash: &str) -> Result<String, RegistryError> {
        let raw = hash
            .strip_prefix("0x")
            .or_else(|| hash.strip_prefix("0X"))
            .unwrap_or(hash);
        if raw.len() != 64 || !raw.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return Err(RegistryError::BadRequest(
                "invalid blob hash format; expected 0x-prefixed SHA-256 hex".into(),
            ));
        }
        Ok(format!("0x{}", raw.to_ascii_lowercase()))
    }

    /// Ensure the parent directory of a blob exists.
    fn ensure_parent(&self, hash: &str) -> Result<(), RegistryError> {
        let path = self.blob_path(hash);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    /// Store with a pre-computed hash (for verified content).
    pub fn store_with_hash(&self, data: &[u8], hash: &str) -> Result<(), RegistryError> {
        let canonical = Self::canonical_hash(hash)?;
        let computed = hush_core::sha256_hex(data);
        if computed != canonical {
            return Err(RegistryError::Integrity(
                "provided hash does not match payload digest".into(),
            ));
        }

        self.ensure_parent(&canonical)?;
        let blob_path = self.blob_path(&canonical);

        if !blob_path.exists() {
            let tmp_path = self.root.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
            fs::write(&tmp_path, data)?;
            fs::rename(&tmp_path, &blob_path)?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let data = b"hello world";
        let hash = storage.store(data).unwrap();
        assert!(!hash.is_empty());
        assert!(storage.exists(&hash));

        let loaded = storage.load(&hash).unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn store_with_hash_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let data = b"test content";
        let hash = hush_core::sha256_hex(data);
        storage.store_with_hash(data, &hash).unwrap();

        let loaded = storage.load(&hash).unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn load_missing_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let err = storage.load(&"00".repeat(32)).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn idempotent_store() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let data = b"duplicate";
        let h1 = storage.store(data).unwrap();
        let h2 = storage.store(data).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn rejects_invalid_hash_format_for_store_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let err = storage
            .store_with_hash(b"abc", "../../../etc/passwd")
            .unwrap_err();
        assert!(err.to_string().contains("invalid blob hash format"));

        let err = storage.load("../../../etc/passwd").unwrap_err();
        assert!(err.to_string().contains("invalid blob hash format"));
    }

    #[test]
    fn store_with_hash_rejects_digest_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let data = b"trusted payload";
        let wrong_hash = hush_core::sha256_hex(b"different payload");
        let err = storage.store_with_hash(data, &wrong_hash).unwrap_err();
        assert!(err.to_string().contains("does not match payload digest"));
        assert!(!storage.exists(&wrong_hash));
    }
}
