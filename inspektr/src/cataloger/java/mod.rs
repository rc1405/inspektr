//! Java ecosystem cataloger.
//!
//! Two independent catalogers live here:
//!
//! - [`JavaCataloger`] (in [`source`]) parses source-level files: `pom.xml`,
//!   `build.gradle`, `build.gradle.kts`. These describe what the project
//!   declares it depends on.
//! - [`JavaArchiveCataloger`] (in [`archive`]) parses compiled archives:
//!   `.jar`, `.war`, `.ear`, and related formats. These describe what the
//!   project actually ships. Container images usually only have archives.
//!
//! Both emit `Ecosystem::Java` packages with `pkg:maven/<groupId>/<artifactId>@<version>`
//! PURLs so the vulnerability matcher treats findings from either source
//! identically.

pub mod archive;
pub mod source;

pub use archive::JavaArchiveCataloger;
pub use source::JavaCataloger;
