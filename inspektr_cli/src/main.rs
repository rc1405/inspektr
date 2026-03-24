use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use inspektr::models::Severity;
use inspektr::pipeline;
use inspektr::vuln::report;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Top-level CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "inspektr",
    version,
    about = "A software composition analysis tool",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a Software Bill of Materials for a target.
    Sbom {
        /// Target to scan (filesystem path or OCI image reference).
        target: String,

        /// Write output to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// SBOM format to produce.
        #[arg(long, default_value = "cyclonedx")]
        format: String,
    },

    /// Scan a target or SBOM for known vulnerabilities.
    Vuln {
        /// Target to scan (filesystem path or OCI image reference).
        /// Mutually exclusive with --sbom.
        target: Option<String>,

        /// Path to an existing SBOM file to scan instead of a live target.
        #[arg(long)]
        sbom: Option<PathBuf>,

        /// Write output to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format: table or json (default: table for stdout, json for file output)
        #[arg(long)]
        format: Option<String>,

        /// Exit with a non-zero status if any vulnerability at or above this
        /// severity is found.  Accepted values: none, low, medium, high, critical.
        #[arg(long)]
        fail_on: Option<String>,

        /// Path to the vulnerability database.
        #[arg(long)]
        db: Option<PathBuf>,
    },

    /// Manage the local vulnerability database.
    Db {
        #[command(subcommand)]
        subcommand: DbCommands,
    },
}

#[derive(Debug, Subcommand)]
enum DbCommands {
    /// Pull the latest pre-built vulnerability database from Docker Hub.
    Update {
        /// OCI image reference for the database (default: rc1405/inspektr-db:latest)
        #[arg(long, default_value = "rc1405/inspektr-db:latest")]
        registry: String,
    },

    /// Build the vulnerability database from OSV and NVD sources.
    #[cfg(feature = "db-admin")]
    Build {
        /// Ecosystem to import (default: all). Values: Go, npm, PyPI, Maven
        #[arg(long)]
        ecosystem: Option<String>,

        /// Write the resulting database to this path.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Push a built database to an OCI registry.
    #[cfg(feature = "db-admin")]
    Push {
        /// OCI registry reference to push the database to.
        registry: String,

        /// Path to the database file to push.
        #[arg(long)]
        db: Option<PathBuf>,
    },

    /// Delete the local vulnerability database.
    Clean,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sbom {
            target,
            output,
            format,
        } => cmd_sbom(&target, output.as_deref(), &format),

        Commands::Vuln {
            target,
            sbom,
            output,
            format,
            fail_on,
            db,
        } => cmd_vuln(
            target.as_deref(),
            sbom.as_deref(),
            output.as_deref(),
            format.as_deref(),
            fail_on.as_deref(),
            db.as_deref(),
        ),

        Commands::Db { subcommand } => match subcommand {
            DbCommands::Update { registry } => cmd_db_update(&registry),

            #[cfg(feature = "db-admin")]
            DbCommands::Build { ecosystem, output } => {
                cmd_db_build(ecosystem.as_deref(), output.as_deref())
            }

            #[cfg(feature = "db-admin")]
            DbCommands::Push { registry, db } => cmd_db_push(&registry, db.as_deref()),

            DbCommands::Clean => cmd_db_clean(),
        },
    }
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

fn cmd_sbom(target: &str, output: Option<&std::path::Path>, format: &str) -> Result<()> {
    let bytes = pipeline::generate_sbom_bytes(target, format)
        .with_context(|| format!("Failed to generate SBOM for '{}'", target))?;

    match output {
        Some(path) => {
            std::fs::write(path, &bytes)
                .with_context(|| format!("Failed to write SBOM to '{}'", path.display()))?;
            eprintln!("SBOM written to {}", path.display());
        }
        None => {
            let text = String::from_utf8(bytes).context("SBOM output is not valid UTF-8")?;
            print!("{}", text);
        }
    }

    Ok(())
}

fn cmd_vuln(
    target: Option<&str>,
    sbom: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
    format: Option<&str>,
    fail_on: Option<&str>,
    db: Option<&std::path::Path>,
) -> Result<()> {
    let db_path = match db {
        Some(p) => p.to_path_buf(),
        None => pipeline::default_db_path(),
    };

    let sbom_str = sbom.map(|p| p.to_string_lossy().into_owned());
    let scan_report = pipeline::scan_and_report(target, sbom_str.as_deref(), &db_path)
        .with_context(|| "Failed to scan for vulnerabilities")?;

    // Determine format: explicit flag > default based on output
    let fmt = match format {
        Some(f) => f,
        None => {
            if output.is_some() {
                "json"
            } else {
                "table"
            }
        }
    };

    let rendered = match fmt {
        "table" => report::render_report_table(&scan_report),
        "json" => report::render_report_json(&scan_report)?,
        other => bail!("Unknown format: '{}'. Supported: table, json", other),
    };

    match output {
        Some(path) => {
            std::fs::write(path, &rendered)
                .with_context(|| format!("Failed to write report to '{}'", path.display()))?;
            eprintln!("Report written to {}", path.display());
        }
        None => {
            print!("{}", rendered);
        }
    }

    if let Some(severity_str) = fail_on {
        let threshold = parse_severity_flag(severity_str)?;
        if report::has_severity_at_or_above_report(&scan_report, threshold) {
            bail!(
                "Found vulnerabilities at or above severity '{}'",
                severity_str
            );
        }
    }

    Ok(())
}

fn cmd_db_update(registry: &str) -> Result<()> {
    let db_path = pipeline::default_db_path();

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory '{}'", parent.display()))?;
    }

    eprintln!("Pulling vulnerability database from {} …", registry);

    inspektr::oci::pull::pull_artifact(registry, &db_path)
        .with_context(|| format!("Failed to pull database from '{}'", registry))?;

    eprintln!("Database updated at {}", db_path.display());
    Ok(())
}

fn cmd_db_clean() -> Result<()> {
    let db_path = pipeline::default_db_path();

    if db_path.exists() {
        std::fs::remove_file(&db_path)
            .with_context(|| format!("Failed to delete database at '{}'", db_path.display()))?;
        eprintln!("Deleted vulnerability database at {}", db_path.display());
    } else {
        eprintln!("No database found at {}", db_path.display());
    }

    Ok(())
}

#[cfg(feature = "db-admin")]
fn cmd_db_build(ecosystem: Option<&str>, output: Option<&std::path::Path>) -> Result<()> {
    use inspektr::db::store::VulnStore;
    use inspektr::db::{normalize_ecosystem, vuln_sources};

    let db_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(pipeline::default_db_path);

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory '{}'", parent.display()))?;
    }

    // Normalize ecosystem if provided
    let ecosystem = match ecosystem {
        Some(eco) => {
            let normalized = normalize_ecosystem(eco).ok_or_else(|| {
                anyhow::anyhow!(
                    "Unknown ecosystem: '{}'. Supported: Go, npm, PyPI, Maven",
                    eco
                )
            })?;
            Some(normalized)
        }
        None => None,
    };

    eprintln!("Building vulnerability database at {} …", db_path.display());

    let db_str = db_path.to_string_lossy();
    let mut store = VulnStore::open(&db_str).context("Failed to open vulnerability database")?;

    let mut total = 0;
    for source in vuln_sources() {
        match source.import(&mut store, ecosystem) {
            Ok(count) => total += count,
            Err(e) => eprintln!("Warning: {} import failed: {}", source.name(), e),
        }
    }

    eprintln!("Built database with {} total vulnerabilities.", total);
    Ok(())
}

#[cfg(feature = "db-admin")]
fn cmd_db_push(registry: &str, db: Option<&std::path::Path>) -> Result<()> {
    use inspektr::oci::push::push_artifact;

    let db_path = db
        .map(|p| p.to_path_buf())
        .unwrap_or_else(pipeline::default_db_path);

    if !db_path.exists() {
        anyhow::bail!(
            "Database not found at {}. Run `inspektr db build` first.",
            db_path.display()
        );
    }

    eprintln!("Pushing database to {}...", registry);

    push_artifact(
        registry,
        &db_path,
        "application/vnd.inspektr.db.v1+sqlite",
    )
    .with_context(|| format!("Failed to push database to '{}'", registry))?;

    eprintln!("Done.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_severity_flag(s: &str) -> Result<Severity> {
    match s.to_lowercase().as_str() {
        "none" => Ok(Severity::None),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => bail!(
            "Invalid severity '{}'. Expected one of: none, low, medium, high, critical",
            other
        ),
    }
}
