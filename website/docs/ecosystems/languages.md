# Language Ecosystems

Inspektr supports 11 language/package manager ecosystems.

## Supported Ecosystems

| Ecosystem | Lockfiles/Manifests | PURL Scheme | OSV Ecosystem |
|-----------|-------------------|-------------|---------------|
| Go | `go.mod`, `go.sum`, Go binaries | `pkg:golang/` | `Go` |
| JavaScript/Node | `package-lock.json`, `yarn.lock` | `pkg:npm/` | `npm` |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock` | `pkg:pypi/` | `PyPI` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts` | `pkg:maven/` | `Maven` |
| .NET | `packages.lock.json`, `*.csproj`, `packages.config` | `pkg:nuget/` | `NuGet` |
| PHP | `composer.lock` | `pkg:composer/` | `Packagist` |
| Rust | `Cargo.lock` | `pkg:cargo/` | `crates.io` |
| Ruby | `Gemfile.lock` | `pkg:gem/` | `RubyGems` |
| Swift | `Package.resolved` (v1, v2) | `pkg:swift/` | `SwiftURL` |
| C/C++ (Conan) | `conan.lock` | `pkg:conan/` | `ConanCenter` |
| C/C++ (vcpkg) | `vcpkg.json` | `pkg:vcpkg/` | — |

## Ecosystem Details

### Go

- Parses `go.mod` for direct and indirect dependencies
- Parses `go.sum` for complete dependency list with checksums
- Inspects compiled Go binaries via the `.go.buildinfo` section — extracts embedded module info without source code

### JavaScript/Node

- Parses `package-lock.json` v2 and v3 formats
- Parses `yarn.lock` v1 format
- Handles scoped packages (`@scope/name`)

### Python

- Parses `requirements.txt` (pinned `==` versions only)
- Parses `Pipfile.lock` (both default and develop sections)
- Parses `poetry.lock` (TOML format)
- PURLs use lowercased package names per PyPI convention

### Java

- Parses `pom.xml` Maven dependency blocks
- Parses `build.gradle` and `build.gradle.kts` dependency declarations
- Skips variable version references (`${version}`)

### .NET

- Parses `packages.lock.json` (NuGet lock format, all framework targets)
- Parses `*.csproj` PackageReference elements
- Parses `packages.config` (legacy NuGet format)

### PHP

- Parses `composer.lock` (both `packages` and `packages-dev` sections)
- Strips leading `v` from versions

### Rust

- Parses `Cargo.lock` (TOML format)
- Skips root project entries (no `source` field)

### Ruby

- Parses `Gemfile.lock`
- Extracts packages from the `GEM/specs` section
- Skips transitive dependency indentation levels

### Swift

- Parses `Package.resolved` v1 and v2 formats
- Uses `identity` (v2) or `package` (v1) as package name

### C/C++ (Conan)

- Parses `conan.lock` (Conan 2.x JSON format)
- Splits `name/version#hash` entries

### C/C++ (vcpkg)

- Parses `vcpkg.json` manifest
- Only includes dependencies with explicit `version>=` fields
- No OSV vulnerability coverage currently
