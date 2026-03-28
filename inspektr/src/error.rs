use thiserror::Error;

#[derive(Debug, Error)]
pub enum LookingGlassError {
    #[error("Source error: {0}")]
    Source(#[from] SourceError),

    #[error("Cataloger error: {0}")]
    Cataloger(#[from] CatalogerError),

    #[error("SBOM format error: {0}")]
    SbomFormat(#[from] SbomFormatError),

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("OCI error: {0}")]
    Oci(#[from] OciError),
}

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("Path not found: {path}")]
    PathNotFound { path: String },

    #[error("Failed to read file {path}: {reason}")]
    ReadFailed { path: String, reason: String },

    #[error("Unsupported target: {target}")]
    UnsupportedTarget { target: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum CatalogerError {
    #[error("Failed to parse {file}: {reason}")]
    ParseFailed { file: String, reason: String },
}

#[derive(Debug, Error)]
pub enum SbomFormatError {
    #[error("Failed to encode SBOM: {0}")]
    EncodeFailed(String),

    #[error("Failed to decode SBOM: {0}")]
    DecodeFailed(String),
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Database not found at {path}. Run `inspektr db update` to download it.")]
    NotFound { path: String },

    #[error("Database query failed: {0}")]
    QueryFailed(String),

    #[error("Failed to import vulnerability data: {0}")]
    ImportFailed(String),

    #[error("Storage error: {0}")]
    Storage(String),
}

#[derive(Debug, Error)]
pub enum OciError {
    #[error("Failed to pull {reference}: {reason}")]
    PullFailed { reference: String, reason: String },

    #[error("Failed to push {reference}: {reason}")]
    PushFailed { reference: String, reason: String },

    #[error("Authentication failed for {registry}. Provide --username and --password flags.")]
    AuthFailed { registry: String },

    #[error("Invalid OCI reference: {reference}")]
    InvalidReference { reference: String },
}
