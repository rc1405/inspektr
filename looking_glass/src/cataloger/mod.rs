pub mod golang;

use crate::error::CatalogerError;
use crate::models::{FileEntry, Package};

/// Discovers packages from a set of files.
pub trait Cataloger {
    fn name(&self) -> &str;
    fn can_catalog(&self, files: &[FileEntry]) -> bool;
    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError>;
}
