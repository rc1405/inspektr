//! Ruby ecosystem cataloger.
//!
//! Discovers Ruby gems from `Gemfile.lock` files.

use super::Cataloger;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use std::collections::HashMap;

/// Cataloger for Ruby gems (RubyGems).
pub struct RubyCataloger;

impl Cataloger for RubyCataloger {
    fn name(&self) -> &str {
        "ruby"
    }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "Gemfile.lock"
        })
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name != "Gemfile.lock" {
                continue;
            }
            if let Some(text) = file.as_text() {
                for mut pkg in parse_gemfile_lock(text)? {
                    pkg.metadata
                        .insert("source".to_string(), "Gemfile.lock".to_string());
                    pkg.source_file = Some(file.path.display().to_string());
                    let key = format!("{}@{}", pkg.name, pkg.version);
                    if seen.insert(key) {
                        packages.push(pkg);
                    }
                }
            }
        }
        Ok(packages)
    }
}

fn make_ruby_package(name: &str, version: &str) -> Package {
    Package {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::Ruby,
        purl: format!("pkg:gem/{}@{}", name, version),
        metadata: HashMap::new(),
        source_file: None,
    }
}

pub fn parse_gemfile_lock(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let mut packages = Vec::new();
    let mut in_gem_specs = false;

    for line in content.lines() {
        // Detect section headers (lines with no leading spaces, all caps)
        if !line.starts_with(' ') {
            let trimmed = line.trim();
            if trimmed == "GEM" {
                // Don't set in_gem_specs yet; we need to find specs: sub-section
                in_gem_specs = false;
                continue;
            }
            if !trimmed.is_empty() {
                // Any top-level section header stops the specs parsing
                in_gem_specs = false;
            }
            continue;
        }

        // We're in indented territory
        let trimmed = line.trim();

        // Detect "specs:" sub-header (2-space indent)
        if line.starts_with("  ") && !line.starts_with("   ") && trimmed == "specs:" {
            in_gem_specs = true;
            continue;
        }

        // If we hit another 2-space-indent keyword (like "remote:", "specs:" again),
        // stop specs parsing when we see a new top-level GEM sub-key that isn't specs
        if line.starts_with("  ") && !line.starts_with("   ") && trimmed != "specs:" {
            // This is another sub-section key inside GEM or a different section
            // If it ends with ':', it's likely a sub-key; keep in_gem_specs state
            // unless it's a completely new top-level section
            // Actually we stop at the next non-indented line (handled above)
            continue;
        }

        if !in_gem_specs {
            continue;
        }

        // Exactly 4-space indent = package entry (not transitive deps which have 6+ spaces)
        if line.starts_with("    ") && !line.starts_with("     ") {
            // Format: "    name (version)"
            let trimmed = trimmed;
            if let Some(paren_pos) = trimmed.find(" (") {
                let name = &trimmed[..paren_pos];
                let rest = &trimmed[paren_pos + 2..];
                if let Some(close) = rest.find(')') {
                    let version = &rest[..close];
                    // version may contain constraints like "= 7.1.2", take only exact version
                    // For direct deps, version is just a plain version number
                    // For deps with constraints, it might be "= X.Y.Z"
                    let version = version.trim();
                    if !name.is_empty() && !version.is_empty() {
                        packages.push(make_ruby_package(name, version));
                    }
                }
            }
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FileContents, FileEntry};
    use std::path::PathBuf;

    fn text_entry(path: &str, content: &str) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            contents: FileContents::Text(content.to_string()),
        }
    }

    #[test]
    fn can_catalog_yes() {
        let files = vec![text_entry("/project/Gemfile.lock", "GEM\n")];
        assert!(RubyCataloger.can_catalog(&files));
    }

    #[test]
    fn can_catalog_no() {
        let files = vec![
            text_entry("/project/go.mod", "module example.com/app\n"),
            text_entry("/project/package-lock.json", "{}"),
        ];
        assert!(!RubyCataloger.can_catalog(&files));
    }

    #[test]
    fn parse_gemfile_lock_finds_rails_and_rack() {
        let content = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.2)\n      actioncable (= 7.1.2)\n    rack (3.0.8)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n";
        let pkgs = parse_gemfile_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "rails" && p.version == "7.1.2")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "rack" && p.version == "3.0.8")
        );
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::Ruby));
    }

    #[test]
    fn stops_at_platforms_section() {
        let content = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.2)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n";
        let pkgs = parse_gemfile_lock(content).unwrap();
        // Only the GEM specs section packages, not things from PLATFORMS or DEPENDENCIES
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "rails");
        // Confirm no spurious packages from PLATFORMS or DEPENDENCIES sections
        assert!(pkgs.iter().all(|p| p.name != "ruby"));
    }
}
