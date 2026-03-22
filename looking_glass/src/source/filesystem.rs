use std::path::{Path, PathBuf};

use crate::error::SourceError;
use crate::models::{FileContents, FileEntry, SourceMetadata};
use super::Source;

/// Reads files from a local directory.
pub struct FilesystemSource {
    root: PathBuf,
}

impl FilesystemSource {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl Source for FilesystemSource {
    fn files(&self) -> Result<Vec<FileEntry>, SourceError> {
        if !self.root.exists() {
            return Err(SourceError::PathNotFound {
                path: self.root.display().to_string(),
            });
        }
        let mut entries = Vec::new();
        collect_files(&self.root, &mut entries)?;
        Ok(entries)
    }

    fn source_metadata(&self) -> SourceMetadata {
        SourceMetadata {
            source_type: "filesystem".to_string(),
            target: self.root.display().to_string(),
        }
    }
}

fn collect_files(dir: &Path, entries: &mut Vec<FileEntry>) -> Result<(), SourceError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, entries)?;
        } else if path.is_file() {
            let bytes = std::fs::read(&path)?;
            let contents = if is_binary_content(&bytes) {
                FileContents::Binary(bytes)
            } else {
                FileContents::Text(String::from_utf8_lossy(&bytes).into_owned())
            };
            entries.push(FileEntry { path, contents });
        }
    }
    Ok(())
}

/// Heuristic: check for ELF, Mach-O, or PE magic bytes, or null bytes in first 512 bytes.
/// This function is public because it's reused by the OCI module.
pub fn is_binary_content(bytes: &[u8]) -> bool {
    if bytes.len() >= 4 {
        // ELF
        if bytes[..4] == [0x7f, 0x45, 0x4c, 0x46] {
            return true;
        }
        // Mach-O (32-bit and 64-bit, both endiannesses)
        if bytes[..4] == [0xfe, 0xed, 0xfa, 0xce]
            || bytes[..4] == [0xce, 0xfa, 0xed, 0xfe]
            || bytes[..4] == [0xfe, 0xed, 0xfa, 0xcf]
            || bytes[..4] == [0xcf, 0xfa, 0xed, 0xfe]
        {
            return true;
        }
    }
    if bytes.len() >= 2 {
        // PE (MZ header)
        if bytes[..2] == [0x4d, 0x5a] {
            return true;
        }
    }
    // Check for null bytes in the first 512 bytes
    let check_len = bytes.len().min(512);
    bytes[..check_len].contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_filesystem_source_reads_files() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("go.mod");
        fs::write(&file_path, "module example.com/foo\n\ngo 1.21\n").unwrap();

        let source = FilesystemSource::new(dir.path().to_path_buf());
        let files = source.files().unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, file_path);
        assert!(files[0].as_text().unwrap().contains("module example.com/foo"));
    }

    #[test]
    fn test_filesystem_source_reads_nested_files() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("subdir");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("go.sum"), "some content").unwrap();
        fs::write(dir.path().join("go.mod"), "module foo").unwrap();

        let source = FilesystemSource::new(dir.path().to_path_buf());
        let files = source.files().unwrap();

        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_filesystem_source_nonexistent_path() {
        let source = FilesystemSource::new(PathBuf::from("/nonexistent/path"));
        let result = source.files();
        assert!(result.is_err());
    }

    #[test]
    fn test_filesystem_source_metadata() {
        let source = FilesystemSource::new(PathBuf::from("/some/path"));
        let meta = source.source_metadata();
        assert_eq!(meta.source_type, "filesystem");
        assert_eq!(meta.target, "/some/path");
    }

    #[test]
    fn test_filesystem_source_detects_binary_files() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("app");
        // ELF magic bytes
        fs::write(&bin_path, &[0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00]).unwrap();

        let source = FilesystemSource::new(dir.path().to_path_buf());
        let files = source.files().unwrap();

        assert_eq!(files.len(), 1);
        assert!(files[0].is_binary());
    }
}
