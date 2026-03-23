use super::{DistroInfo, OsPackageParser};
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use std::collections::HashMap;
use std::io::Write as IoWrite;

pub struct RpmParser;

impl OsPackageParser for RpmParser {
    fn package_db_paths(&self) -> &[&str] {
        &[
            "/var/lib/rpm/rpmdb.sqlite",
            "var/lib/rpm/rpmdb.sqlite",
            "/usr/share/rpm/rpmdb.sqlite",
            "usr/share/rpm/rpmdb.sqlite",
        ]
    }

    fn parse_packages(
        &self,
        files: &[FileEntry],
        distro: &DistroInfo,
    ) -> Result<Vec<Package>, CatalogerError> {
        // Find an rpmdb.sqlite file in the provided file entries
        for file in files {
            let path_str = file.path.to_string_lossy();
            if path_str.ends_with("rpmdb.sqlite") {
                let bytes = file.as_bytes();
                return parse_rpmdb_sqlite(bytes, distro);
            }
        }

        eprintln!("warning: no rpmdb.sqlite found; returning empty package list");
        Ok(Vec::new())
    }
}

/// Write bytes to a temp file, then parse it as an RPM SQLite database.
pub fn parse_rpmdb_sqlite(
    data: &[u8],
    distro: &DistroInfo,
) -> Result<Vec<Package>, CatalogerError> {
    // Write to a temp file so rusqlite can open it by path
    let tmp_path = std::env::temp_dir().join(format!("looking_glass_rpmdb_{}.sqlite", uuid_hex()));

    {
        let mut f = std::fs::File::create(&tmp_path).map_err(|e| CatalogerError::ParseFailed {
            file: "rpmdb.sqlite".to_string(),
            reason: format!("failed to create temp file: {}", e),
        })?;
        f.write_all(data).map_err(|e| CatalogerError::ParseFailed {
            file: "rpmdb.sqlite".to_string(),
            reason: format!("failed to write temp file: {}", e),
        })?;
    }

    let result = parse_rpmdb_from_path(&tmp_path, distro);
    let _ = std::fs::remove_file(&tmp_path);
    result
}

/// Generate a short random hex string for temp file names.
fn uuid_hex() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:08x}{:08x}", nanos, std::process::id())
}

/// Open an RPM SQLite database file and parse all packages.
pub fn parse_rpmdb_from_path(
    path: &std::path::Path,
    distro: &DistroInfo,
) -> Result<Vec<Package>, CatalogerError> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CatalogerError::ParseFailed {
                file: "rpmdb.sqlite".to_string(),
                reason: format!("failed to open SQLite: {}", e),
            })?;

    let mut stmt =
        conn.prepare("SELECT blob FROM Packages")
            .map_err(|e| CatalogerError::ParseFailed {
                file: "rpmdb.sqlite".to_string(),
                reason: format!("failed to prepare query: {}", e),
            })?;

    let distro_id = distro_to_rpm_id(&distro.ecosystem);
    let mut packages = Vec::new();

    let rows = stmt
        .query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        })
        .map_err(|e| CatalogerError::ParseFailed {
            file: "rpmdb.sqlite".to_string(),
            reason: format!("query failed: {}", e),
        })?;

    for row in rows {
        let blob = row.map_err(|e| CatalogerError::ParseFailed {
            file: "rpmdb.sqlite".to_string(),
            reason: format!("row error: {}", e),
        })?;

        match parse_rpm_header_blob(&blob) {
            Ok(Some((name, version_str))) => {
                let purl = format!("pkg:rpm/{}/{}@{}", distro_id, name, version_str);
                packages.push(Package {
                    name,
                    version: version_str,
                    ecosystem: distro.ecosystem,
                    purl,
                    metadata: HashMap::new(),
                    source_file: None,
                });
            }
            Ok(None) => {} // skip incomplete records
            Err(e) => {
                eprintln!("warning: failed to parse RPM header blob: {}", e);
            }
        }
    }

    Ok(packages)
}

// RPM header tag numbers
const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_EPOCH: u32 = 1003;

// RPM header magic bytes: 0x8e 0xad 0xe8 0x01
const RPM_HEADER_MAGIC: [u8; 4] = [0x8e, 0xad, 0xe8, 0x01];

/// Parse an RPM header blob and return (name, version_string).
///
/// RPM header format:
///   - 3 bytes magic (8e ad e8)
///   - 1 byte version (01)
///   - 4 bytes reserved (0x00000000)
///   - 4 bytes nindex (big-endian): number of index entries
///   - 4 bytes hsize (big-endian): size of data section
///   - nindex × 16 bytes index entries:
///       tag   (4 bytes BE)
///       type  (4 bytes BE)
///       offset(4 bytes BE) — offset into data section
///       count (4 bytes BE)
///   - hsize bytes of data section
pub fn parse_rpm_header_blob(blob: &[u8]) -> Result<Option<(String, String)>, String> {
    if blob.len() < 16 {
        return Err(format!("blob too short: {} bytes", blob.len()));
    }

    // Check magic
    if &blob[0..4] != &RPM_HEADER_MAGIC {
        return Err(format!(
            "invalid RPM header magic: {:02x} {:02x} {:02x} {:02x}",
            blob[0], blob[1], blob[2], blob[3]
        ));
    }

    // bytes 4-7 are reserved
    let nindex = u32::from_be_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
    let hsize = u32::from_be_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;

    // Index section starts at offset 16
    let index_start = 16usize;
    let index_end = index_start + nindex * 16;

    if blob.len() < index_end + hsize {
        return Err(format!(
            "blob too short: need {} bytes, have {}",
            index_end + hsize,
            blob.len()
        ));
    }

    let data_section = &blob[index_end..index_end + hsize];

    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut release: Option<String> = None;
    let mut epoch: Option<u32> = None;

    for i in 0..nindex {
        let entry_start = index_start + i * 16;
        let tag = u32::from_be_bytes([
            blob[entry_start],
            blob[entry_start + 1],
            blob[entry_start + 2],
            blob[entry_start + 3],
        ]);
        let _type = u32::from_be_bytes([
            blob[entry_start + 4],
            blob[entry_start + 5],
            blob[entry_start + 6],
            blob[entry_start + 7],
        ]);
        let offset = u32::from_be_bytes([
            blob[entry_start + 8],
            blob[entry_start + 9],
            blob[entry_start + 10],
            blob[entry_start + 11],
        ]) as usize;
        let count = u32::from_be_bytes([
            blob[entry_start + 12],
            blob[entry_start + 13],
            blob[entry_start + 14],
            blob[entry_start + 15],
        ]);

        match tag {
            TAG_NAME | TAG_VERSION | TAG_RELEASE => {
                // String type: null-terminated string at data_section[offset]
                if offset >= data_section.len() {
                    continue;
                }
                let s = read_cstring(data_section, offset);
                match tag {
                    TAG_NAME => name = Some(s),
                    TAG_VERSION => version = Some(s),
                    TAG_RELEASE => release = Some(s),
                    _ => {}
                }
            }
            TAG_EPOCH => {
                // INT32 type: 4-byte big-endian integer at data_section[offset]
                if offset + 4 <= data_section.len() && count >= 1 {
                    let e = u32::from_be_bytes([
                        data_section[offset],
                        data_section[offset + 1],
                        data_section[offset + 2],
                        data_section[offset + 3],
                    ]);
                    epoch = Some(e);
                }
            }
            _ => {}
        }
    }

    match (name, version, release) {
        (Some(n), Some(v), Some(r)) => {
            let version_str = if epoch.map(|e| e > 0).unwrap_or(false) {
                format!("{}:{}-{}", epoch.unwrap(), v, r)
            } else {
                format!("{}-{}", v, r)
            };
            Ok(Some((n, version_str)))
        }
        _ => Ok(None),
    }
}

/// Read a null-terminated C string from `data` starting at `offset`.
fn read_cstring(data: &[u8], offset: usize) -> String {
    let slice = &data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

/// Map an Ecosystem to the RPM PURL distro identifier.
pub fn distro_to_rpm_id(ecosystem: &Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::RedHat => "redhat",
        Ecosystem::CentOS => "centos",
        Ecosystem::Rocky => "rocky",
        Ecosystem::AlmaLinux => "almalinux",
        Ecosystem::OracleLinux => "oraclelinux",
        Ecosystem::SUSE => "suse",
        Ecosystem::Photon => "photon",
        Ecosystem::AzureLinux => "azurelinux",
        Ecosystem::CoreOS => "coreos",
        Ecosystem::Bottlerocket => "bottlerocket",
        Ecosystem::Echo => "echo",
        Ecosystem::MinimOS => "minimos",
        // fallback
        _ => "rpm",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_string_entry(
        tag: u32,
        s: &str,
        data: &mut Vec<u8>,
        entries: &mut Vec<(u32, u32, u32, u32)>,
    ) {
        let offset = data.len() as u32;
        data.extend_from_slice(s.as_bytes());
        data.push(0u8); // null terminator
        entries.push((tag, 6u32, offset, 1u32)); // type 6 = STRING
    }

    /// Build a minimal valid RPM header blob for a package.
    fn build_rpm_blob(name: &str, version: &str, release: &str, epoch: Option<u32>) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        let mut index_entries: Vec<(u32, u32, u32, u32)> = Vec::new();

        push_string_entry(TAG_NAME, name, &mut data, &mut index_entries);
        push_string_entry(TAG_VERSION, version, &mut data, &mut index_entries);
        push_string_entry(TAG_RELEASE, release, &mut data, &mut index_entries);

        if let Some(e) = epoch {
            let offset = data.len() as u32;
            data.extend_from_slice(&e.to_be_bytes());
            index_entries.push((TAG_EPOCH, 4u32, offset, 1u32)); // type 4 = INT32
        }

        let nindex = index_entries.len() as u32;
        let hsize = data.len() as u32;

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&RPM_HEADER_MAGIC);
        blob.extend_from_slice(&[0u8; 4]); // reserved
        blob.extend_from_slice(&nindex.to_be_bytes());
        blob.extend_from_slice(&hsize.to_be_bytes());
        for (tag, typ, offset, count) in &index_entries {
            blob.extend_from_slice(&tag.to_be_bytes());
            blob.extend_from_slice(&typ.to_be_bytes());
            blob.extend_from_slice(&offset.to_be_bytes());
            blob.extend_from_slice(&count.to_be_bytes());
        }
        blob.extend_from_slice(&data);

        blob
    }

    #[test]
    fn test_parse_rpm_header_blob() {
        let blob = build_rpm_blob("openssl", "3.0.7", "25.el9", None);
        let result = parse_rpm_header_blob(&blob).unwrap();
        assert!(result.is_some());
        let (name, version) = result.unwrap();
        assert_eq!(name, "openssl");
        assert_eq!(version, "3.0.7-25.el9");
    }

    #[test]
    fn test_invalid_blob() {
        let blob = vec![0x00, 0x01, 0x02, 0x03];
        let result = parse_rpm_header_blob(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rpm_header_blob_with_epoch() {
        let blob = build_rpm_blob("bash", "5.1.8", "6.el9", Some(2));
        let result = parse_rpm_header_blob(&blob).unwrap();
        assert!(result.is_some());
        let (name, version) = result.unwrap();
        assert_eq!(name, "bash");
        assert_eq!(version, "2:5.1.8-6.el9");
    }
}
