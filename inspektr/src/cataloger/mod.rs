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
pub trait Cataloger {
    fn name(&self) -> &str;
    fn can_catalog(&self, files: &[FileEntry]) -> bool;
    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError>;
}
