//! Package discovery from lockfiles, manifests, and compiled binaries.
//!
//! Each [`Cataloger`] implementation knows how to parse one or more file formats
//! for a specific ecosystem. The pipeline runs all catalogers against the
//! discovered files and collects the resulting [`Package`] values.
//!
//! # Language catalogers
//!
//! | Module | Ecosystem | Files parsed |
//! |--------|-----------|-------------|
//! | [`golang`] | Go | `go.mod`, `go.sum`, Go binaries (ELF/Mach-O/PE) |
//! | [`javascript`] | JavaScript/Node | `package-lock.json`, `yarn.lock` |
//! | [`python`] | Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock` |
//! | [`java`] | Java | `pom.xml`, `build.gradle`, `build.gradle.kts` |
//! | [`conan`] | C/C++ Conan | `conan.lock` |
//! | [`vcpkg`] | C/C++ vcpkg | `vcpkg.json` |
//! | [`dotnet`] | .NET | `packages.lock.json`, `*.csproj`, `packages.config` |
//! | [`php`] | PHP | `composer.lock` |
//! | [`rust_lang`] | Rust | `Cargo.lock` |
//! | [`ruby`] | Ruby | `Gemfile.lock` |
//! | [`swift`] | Swift | `Package.resolved` (v1, v2) |
//!
//! # OS cataloger
//!
//! The [`os`] module detects OS packages from container images using dpkg, apk,
//! and rpm package database files.

pub mod conan;
pub mod dotnet;
pub mod golang;
pub mod java;
pub mod javascript;
pub mod os;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust_lang;
pub mod swift;
pub mod vcpkg;

use crate::error::CatalogerError;
use crate::models::{FileEntry, Package};

/// Discovers packages from a set of files.
///
/// Implement this trait to add support for a new language ecosystem or package
/// format. The pipeline calls [`can_catalog()`](Cataloger::can_catalog) first
/// to check whether this cataloger is relevant, then
/// [`catalog()`](Cataloger::catalog) to extract packages.
pub trait Cataloger {
    /// A human-readable name for this cataloger (e.g., `"go"`, `"javascript"`).
    fn name(&self) -> &str;

    /// Returns `true` if this cataloger can find relevant files to parse.
    ///
    /// This is a fast check that avoids the cost of full parsing when no
    /// relevant files are present.
    fn can_catalog(&self, files: &[FileEntry]) -> bool;

    /// Parse the given files and return all discovered packages.
    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError>;
}
