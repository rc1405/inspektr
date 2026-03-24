# Adding Ecosystems

## Adding a New Language Ecosystem

### 1. Add the Ecosystem variant

In `inspektr/src/models/mod.rs`:

```rust
pub enum Ecosystem {
    // ... existing variants ...
    MyEcosystem,
}
```

Add `as_osv_ecosystem()` arm:

```rust
Ecosystem::MyEcosystem => "MyOSVName",
```

Add `to_purl()` arm:

```rust
Ecosystem::MyEcosystem => format!("pkg:mytype/{}@{}", self.name, self.version),
```

### 2. Create the cataloger

Create `inspektr/src/cataloger/myecosystem.rs`:

```rust
use std::collections::HashMap;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use super::Cataloger;

pub struct MyEcosystemCataloger;

impl Cataloger for MyEcosystemCataloger {
    fn name(&self) -> &str { "myecosystem" }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            f.path.file_name().and_then(|n| n.to_str()) == Some("my.lock")
        })
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name != "my.lock" { continue; }
            let Some(text) = file.as_text() else { continue; };

            for mut pkg in parse_lockfile(text)? {
                pkg.source_file = Some(file.path.display().to_string());
                pkg.metadata.insert("source".to_string(), file_name.to_string());
                let key = format!("{}@{}", pkg.name, pkg.version);
                if seen.insert(key) {
                    packages.push(pkg);
                }
            }
        }
        Ok(packages)
    }
}

fn parse_lockfile(content: &str) -> Result<Vec<Package>, CatalogerError> {
    // Parse your lockfile format here
    todo!()
}
```

### 3. Register the cataloger

In `inspektr/src/cataloger/mod.rs`:

```rust
pub mod myecosystem;
```

In `inspektr/src/pipeline.rs`, add to `catalogers()`:

```rust
Box::new(myecosystem::MyEcosystemCataloger),
```

### 4. Update SBOM decoders

In both `inspektr/src/sbom/cyclonedx.rs` and `inspektr/src/sbom/spdx.rs`, add PURL detection:

```rust
} else if purl.starts_with("pkg:mytype/") {
    Ecosystem::MyEcosystem
}
```

### 5. Add to ALL_ECOSYSTEMS (if OSV has data)

In `inspektr/src/db/mod.rs`:

```rust
pub const ALL_ECOSYSTEMS: &[&str] = &[
    // ... existing ...
    "MyOSVName",
];
```

Check if OSV has bulk data: `curl -I https://osv-vulnerabilities.storage.googleapis.com/MyOSVName/all.zip`

## Adding a New OS Distribution

Much simpler — just two changes:

### 1. Add distro mapping

In `inspektr/src/cataloger/os/mod.rs`, add to `map_distro_id()`:

```rust
"mynewdistro" => Some((Ecosystem::MyNewDistro, PackageFormat::Dpkg)),
```

### 2. Add Ecosystem variant

In `inspektr/src/models/mod.rs`, add the variant and update `as_osv_ecosystem()` and `to_purl()`.

No new parser code needed if the distro uses dpkg, apk, or rpm.
