//! `.cpkg` archive format — zstd-compressed tar with content-hash integrity.

use std::fs;
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::Path;

use hush_core::Hash;

use crate::error::{Error, Result};

/// Maximum uncompressed archive size (100 MB) to prevent zip bombs.
const MAX_UNCOMPRESSED_SIZE: u64 = 100 * 1024 * 1024;

/// Compression level for zstd.
const ZSTD_LEVEL: i32 = 3;

/// Pack a directory into a `.cpkg` archive (tar + zstd).
///
/// Returns the SHA-256 content hash of the compressed bytes.
pub fn pack(source_dir: &Path, output_path: &Path) -> Result<Hash> {
    if !source_dir.is_dir() {
        return Err(Error::PkgError(format!(
            "source path is not a directory: {}",
            source_dir.display()
        )));
    }

    // Build tar in memory, measuring uncompressed size.
    let mut tar_bytes: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        builder.append_dir_all(".", source_dir)?;
        builder.finish()?;
    }

    if tar_bytes.len() as u64 > MAX_UNCOMPRESSED_SIZE {
        return Err(Error::PkgError(format!(
            "uncompressed archive size ({} bytes) exceeds limit ({} bytes)",
            tar_bytes.len(),
            MAX_UNCOMPRESSED_SIZE
        )));
    }

    // Compress with zstd.
    let mut compressed: Vec<u8> = Vec::new();
    {
        let mut encoder = zstd::stream::write::Encoder::new(&mut compressed, ZSTD_LEVEL)?;
        encoder.write_all(&tar_bytes)?;
        encoder.finish()?;
    }

    fs::write(output_path, &compressed)?;

    Ok(hush_core::sha256(&compressed))
}

/// Unpack a `.cpkg` archive into a target directory.
///
/// Returns the SHA-256 content hash of the compressed archive bytes.
pub fn unpack(archive_path: &Path, target_dir: &Path) -> Result<Hash> {
    let compressed = fs::read(archive_path)?;
    let hash = hush_core::sha256(&compressed);

    // Decompress.
    let mut decoder = zstd::stream::read::Decoder::new(compressed.as_slice())?;
    let mut tar_bytes: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut tar_bytes)?;

    if tar_bytes.len() as u64 > MAX_UNCOMPRESSED_SIZE {
        return Err(Error::PkgError(format!(
            "uncompressed archive size ({} bytes) exceeds limit ({} bytes)",
            tar_bytes.len(),
            MAX_UNCOMPRESSED_SIZE
        )));
    }

    // Extract, validating paths against traversal.
    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    let canonical_target = if target_dir.exists() {
        target_dir.canonicalize()?
    } else {
        fs::create_dir_all(target_dir)?;
        target_dir.canonicalize()?
    };

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?;

        // Resolve the destination and ensure it stays inside target_dir.
        let dest = canonical_target.join(&entry_path);
        let dest_canonical = if dest.exists() {
            dest.canonicalize()?
        } else {
            // Parent must exist inside the target.
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            // Normalize by resolving parent + filename.
            match dest.parent() {
                Some(p) => p.canonicalize()?.join(
                    dest.file_name()
                        .ok_or_else(|| Error::PkgError("entry with no filename".to_string()))?,
                ),
                None => dest.clone(),
            }
        };

        if !dest_canonical.starts_with(&canonical_target) {
            return Err(Error::PkgError(format!(
                "path traversal detected: {}",
                entry_path.display()
            )));
        }

        entry.unpack(&dest_canonical)?;
    }

    Ok(hash)
}

/// Compute the SHA-256 content hash of an archive file without extracting it.
pub fn content_hash(archive_path: &Path) -> Result<Hash> {
    let bytes = fs::read(archive_path)?;
    Ok(hush_core::sha256(&bytes))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn round_trip_pack_unpack() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("hello.txt"), b"hello world").unwrap();
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("sub/nested.txt"), b"nested").unwrap();

        let archive = tmp.path().join("out.cpkg");
        let pack_hash = pack(&src, &archive).unwrap();

        let dest = tmp.path().join("dest");
        let unpack_hash = unpack(&archive, &dest).unwrap();

        assert_eq!(pack_hash, unpack_hash);
        assert_eq!(
            fs::read_to_string(dest.join("hello.txt")).unwrap(),
            "hello world"
        );
        assert_eq!(
            fs::read_to_string(dest.join("sub/nested.txt")).unwrap(),
            "nested"
        );
    }

    #[test]
    fn content_hash_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("data.bin"), b"deterministic").unwrap();

        let archive = tmp.path().join("out.cpkg");
        let pack_hash = pack(&src, &archive).unwrap();
        let hash = content_hash(&archive).unwrap();

        assert_eq!(pack_hash, hash);
    }

    #[test]
    fn rejects_non_directory_source() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file.txt");
        fs::write(&file, b"not a dir").unwrap();

        let archive = tmp.path().join("out.cpkg");
        let err = pack(&file, &archive).unwrap_err();
        assert!(err.to_string().contains("not a directory"));
    }

    #[test]
    fn path_traversal_rejected() {
        // Craft a tar that contains `../escape.txt` by writing raw header bytes.
        let tmp = tempfile::tempdir().unwrap();
        let archive_path = tmp.path().join("evil.cpkg");

        // Build tar in memory with a traversal path.
        // We write the path directly into the header name field to bypass
        // the `tar` crate's safety checks on `set_path`.
        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let data = b"malicious";
            let mut header = tar::Header::new_gnu();
            // Write the traversal path directly into the name field bytes.
            {
                let raw = header.as_gnu_mut().unwrap();
                let name_bytes = b"../escape.txt\0";
                raw.name[..name_bytes.len()].copy_from_slice(name_bytes);
            }
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
            builder.finish().unwrap();
        }

        // Compress with zstd.
        let mut compressed: Vec<u8> = Vec::new();
        {
            let mut encoder =
                zstd::stream::write::Encoder::new(&mut compressed, ZSTD_LEVEL).unwrap();
            encoder.write_all(&tar_bytes).unwrap();
            encoder.finish().unwrap();
        }
        fs::write(&archive_path, &compressed).unwrap();

        let dest = tmp.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        let err = unpack(&archive_path, &dest).unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }
}
