//! Java source-file cataloger.
//!
//! Discovers Java/Maven packages from `pom.xml`, `build.gradle`, and
//! `build.gradle.kts` files. Compiled JAR/WAR/EAR archives are handled
//! by the sibling `archive` module.

use crate::cataloger::Cataloger;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use std::collections::HashMap;

/// Cataloger for Java packages (Maven).
pub struct JavaCataloger;

impl Cataloger for JavaCataloger {
    fn name(&self) -> &str {
        "java"
    }
    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "pom.xml" || name == "build.gradle" || name == "build.gradle.kts"
        })
    }
    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let source = file_name.to_string();
            let parsed = match file_name {
                "pom.xml" => {
                    if let Some(t) = file.as_text() {
                        parse_pom_xml(t)?
                    } else {
                        continue;
                    }
                }
                "build.gradle" | "build.gradle.kts" => {
                    if let Some(t) = file.as_text() {
                        parse_build_gradle(t)?
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };
            for mut pkg in parsed {
                pkg.metadata.insert("source".to_string(), source.clone());
                pkg.source_file = Some(file.path.display().to_string());
                let key = format!("{}@{}", pkg.name, pkg.version);
                if seen.insert(key) {
                    packages.push(pkg);
                }
            }
        }
        Ok(packages)
    }
}

fn make_java_package(group_id: &str, artifact_id: &str, version: &str) -> Package {
    let name = format!("{}:{}", group_id, artifact_id);
    Package {
        name,
        version: version.to_string(),
        ecosystem: Ecosystem::Java,
        purl: format!("pkg:maven/{}/{}@{}", group_id, artifact_id, version),
        metadata: HashMap::new(),
        source_file: None,
    }
}

/// Parse pom.xml with simple string matching (no XML crate needed).
pub fn parse_pom_xml(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let mut packages = Vec::new();
    let mut search_from = 0;
    while let Some(start) = content[search_from..].find("<dependency>") {
        let abs_start = search_from + start;
        let block_content = &content[abs_start..];
        let end = match block_content.find("</dependency>") {
            Some(e) => e,
            None => break,
        };
        let block = &block_content[..end];
        let group_id = extract_xml_value(block, "groupId");
        let artifact_id = extract_xml_value(block, "artifactId");
        let version = extract_xml_value(block, "version");
        if let (Some(gid), Some(aid), Some(ver)) = (group_id, artifact_id, version)
            && !ver.starts_with('$') {
                packages.push(make_java_package(gid, aid, ver));
            }
        search_from = abs_start + end + "</dependency>".len();
    }
    Ok(packages)
}

fn extract_xml_value<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim())
}

/// Parse build.gradle or build.gradle.kts dependency declarations.
pub fn parse_build_gradle(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let mut packages = Vec::new();
    let dep_configs = [
        "implementation",
        "api",
        "compileOnly",
        "runtimeOnly",
        "testImplementation",
        "testCompileOnly",
        "testRuntimeOnly",
        "annotationProcessor",
    ];
    for line in content.lines() {
        let trimmed = line.trim();
        for config in &dep_configs {
            let rest = if let Some(r) = trimmed.strip_prefix(config) {
                r.trim()
            } else {
                continue;
            };
            if let Some(coord) = extract_quoted_string(rest) {
                let parts: Vec<&str> = coord.splitn(3, ':').collect();
                if parts.len() == 3 && !parts[2].is_empty() {
                    packages.push(make_java_package(parts[0], parts[1], parts[2]));
                }
            }
        }
    }
    Ok(packages)
}

fn extract_quoted_string(s: &str) -> Option<&str> {
    let s = s
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    if (s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"')) {
        Some(&s[1..s.len() - 1])
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FileContents, FileEntry};
    use std::path::PathBuf;

    fn text_file(path: &str, content: &str) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            contents: FileContents::Text(content.to_string()),
        }
    }

    #[test]
    fn test_can_catalog_with_pom() {
        let files = vec![text_file("/project/pom.xml", "<project/>")];
        assert!(JavaCataloger.can_catalog(&files));
    }

    #[test]
    fn test_can_catalog_with_gradle() {
        let files = vec![text_file("/project/build.gradle", "dependencies {}")];
        assert!(JavaCataloger.can_catalog(&files));
    }

    #[test]
    fn test_can_catalog_without_java_files() {
        let files = vec![
            text_file("/project/package.json", "{}"),
            text_file("/project/go.mod", "module example.com/app\n"),
        ];
        assert!(!JavaCataloger.can_catalog(&files));
    }

    #[test]
    fn test_parse_pom_xml() {
        let content = r#"<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.21</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>"#;
        let pkgs = parse_pom_xml(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "org.springframework:spring-core" && p.version == "5.3.21")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "junit:junit" && p.version == "4.13.2")
        );
    }

    #[test]
    fn test_parse_pom_xml_skips_variable_versions() {
        let content = r#"<project>
  <dependencies>
    <dependency>
      <groupId>org.foo</groupId>
      <artifactId>bar</artifactId>
      <version>${foo.version}</version>
    </dependency>
    <dependency>
      <groupId>org.baz</groupId>
      <artifactId>qux</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"#;
        let pkgs = parse_pom_xml(content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "org.baz:qux");
        assert_eq!(pkgs[0].version, "1.0.0");
    }

    #[test]
    fn test_parse_build_gradle() {
        let content = r#"dependencies {
    implementation 'org.springframework:spring-core:5.3.21'
    testImplementation 'junit:junit:4.13.2'
    api 'com.google.guava:guava:31.1-jre'
}"#;
        let pkgs = parse_build_gradle(content).unwrap();
        assert_eq!(pkgs.len(), 3);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "org.springframework:spring-core" && p.version == "5.3.21")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "junit:junit" && p.version == "4.13.2")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "com.google.guava:guava" && p.version == "31.1-jre")
        );
    }

    #[test]
    fn test_parse_build_gradle_kts() {
        let content = r#"dependencies {
    implementation("org.springframework:spring-core:5.3.21")
    testImplementation("junit:junit:4.13.2")
}"#;
        let pkgs = parse_build_gradle(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "org.springframework:spring-core" && p.version == "5.3.21")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "junit:junit" && p.version == "4.13.2")
        );
    }

    #[test]
    fn test_catalog_pom() {
        let content = r#"<project>
  <dependencies>
    <dependency>
      <groupId>org.foo</groupId>
      <artifactId>bar</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"#;
        let files = vec![text_file("/project/pom.xml", content)];
        let pkgs = JavaCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "org.foo:bar");
        assert_eq!(
            pkgs[0].metadata.get("source").map(|s| s.as_str()),
            Some("pom.xml")
        );
    }

    #[test]
    fn test_java_purl_format() {
        let pkg = make_java_package("org.foo", "bar", "1.0");
        assert_eq!(pkg.purl, "pkg:maven/org.foo/bar@1.0");
    }
}
