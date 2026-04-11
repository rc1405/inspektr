//! Error types used throughout the library.
//!
//! All public functions return [`InspektrError`] as the top-level error type.
//! It wraps domain-specific error variants for each stage of the pipeline:
//! source discovery, cataloging, SBOM formatting, database operations, and OCI
//! registry interactions.

use thiserror::Error;

/// Top-level error type for all inspektr operations.
///
/// Each variant wraps a more specific error type corresponding to a stage
/// in the pipeline. Use pattern matching to handle specific failure modes:
///
/// ```no_run
/// use inspektr::error::InspektrError;
///
/// # fn example() -> Result<(), InspektrError> {
/// # let result: Result<(), InspektrError> = Ok(());
/// match result {
///     Err(InspektrError::Database(e)) => eprintln!("DB issue: {e}"),
///     Err(e) => eprintln!("Other error: {e}"),
///     Ok(_) => {}
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Error)]
pub enum InspektrError {
    /// An error occurred while discovering files from a source.
    #[error("Source error: {0}")]
    Source(#[from] SourceError),

    /// An error occurred while parsing files to discover packages.
    #[error("Cataloger error: {0}")]
    Cataloger(#[from] CatalogerError),

    /// An error occurred while encoding or decoding an SBOM.
    #[error("SBOM format error: {0}")]
    SbomFormat(#[from] SbomFormatError),

    /// An error occurred while querying or importing vulnerability data.
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    /// An error occurred while interacting with an OCI registry.
    #[error("OCI error: {0}")]
    Oci(#[from] OciError),
}

/// Errors from [`Source`](crate::source::Source) implementations during file discovery.
#[derive(Debug, Error)]
pub enum SourceError {
    /// The specified path does not exist.
    #[error("Path not found: {path}")]
    PathNotFound { path: String },

    /// A file could not be read.
    #[error("Failed to read file {path}: {reason}")]
    ReadFailed { path: String, reason: String },

    /// The target string could not be recognized as a filesystem path, binary, or OCI image.
    #[error("Unsupported target: {target}")]
    UnsupportedTarget { target: String },

    /// An I/O error occurred during file discovery.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from [`Cataloger`](crate::cataloger::Cataloger) implementations during
/// package discovery.
#[derive(Debug, Error)]
pub enum CatalogerError {
    /// A lockfile or manifest could not be parsed.
    #[error("Failed to parse {file}: {reason}")]
    ParseFailed { file: String, reason: String },
}

/// Errors from [`SbomFormat`](crate::sbom::SbomFormat) implementations during SBOM
/// encoding or decoding.
#[derive(Debug, Error)]
pub enum SbomFormatError {
    /// The SBOM could not be serialized to the target format.
    #[error("Failed to encode SBOM: {0}")]
    EncodeFailed(String),

    /// The SBOM data could not be deserialized from the source format.
    #[error("Failed to decode SBOM: {0}")]
    DecodeFailed(String),
}

/// Errors from vulnerability database operations.
#[derive(Debug, Error)]
pub enum DatabaseError {
    /// The vulnerability database file was not found at the expected path.
    /// Run `inspektr db update` to download it.
    #[error("Database not found at {path}. Run `inspektr db update` to download it.")]
    NotFound { path: String },

    /// A database query failed.
    #[error("Database query failed: {0}")]
    QueryFailed(String),

    /// Importing vulnerability data into the database failed.
    /// Only relevant with the `db-admin` feature.
    #[error("Failed to import vulnerability data: {0}")]
    ImportFailed(String),

    /// A low-level storage error occurred.
    #[error("Storage error: {0}")]
    Storage(String),
}

/// Errors from OCI registry operations (pull/push).
#[derive(Debug, Error)]
pub enum OciError {
    /// Failed to pull an artifact or image from a registry.
    #[error("Failed to pull {reference}: {reason}")]
    PullFailed { reference: String, reason: String },

    /// Failed to push an artifact to a registry.
    #[error("Failed to push {reference}: {reason}")]
    PushFailed { reference: String, reason: String },

    /// Registry authentication failed. Credentials may be missing or invalid.
    #[error("Authentication failed for {registry}. Provide --username and --password flags.")]
    AuthFailed { registry: String },

    /// The OCI reference string could not be parsed.
    #[error("Invalid OCI reference: {reference}")]
    InvalidReference { reference: String },
}
