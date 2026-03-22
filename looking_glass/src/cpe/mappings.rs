use super::ResolvedCpe;
use super::CpeFields;

/// Try to resolve the ecosystem from the `target_sw` field.
/// Recognized mappings:
///   node.js | npm | nodejs  -> npm,   package_name = product
///   python  | pip           -> PyPI,  package_name = product
///   java    | maven         -> Maven, package_name = vendor:product
///   go      | golang        -> Go,    package_name = vendor/product
pub fn resolve_by_target_sw(fields: &CpeFields) -> Option<ResolvedCpe> {
    let target_sw = fields.target_sw.to_ascii_lowercase();
    match target_sw.as_str() {
        "node.js" | "npm" | "nodejs" => Some(ResolvedCpe {
            ecosystem: "npm".to_string(),
            package_name: fields.product.clone(),
        }),
        "python" | "pip" => Some(ResolvedCpe {
            ecosystem: "PyPI".to_string(),
            package_name: fields.product.clone(),
        }),
        "java" | "maven" => Some(ResolvedCpe {
            ecosystem: "Maven".to_string(),
            package_name: format!("{}:{}", fields.vendor, fields.product),
        }),
        "go" | "golang" => Some(ResolvedCpe {
            ecosystem: "Go".to_string(),
            package_name: format!("{}/{}", fields.vendor, fields.product),
        }),
        _ => None,
    }
}

/// Try to resolve the ecosystem from vendor heuristics.
///
/// Rules (applied in order):
/// 1. Vendor ends with `_project`  -> npm, package_name = product
/// 2. `java_vendor_to_group` returns Some -> Maven, package_name = group:product
/// 3. `is_python_vendor` -> PyPI, package_name = product
pub fn resolve_by_vendor(fields: &CpeFields) -> Option<ResolvedCpe> {
    let vendor = fields.vendor.to_ascii_lowercase();

    // Rule 1: vendor ends with "_project" -> npm
    if vendor.ends_with("_project") {
        return Some(ResolvedCpe {
            ecosystem: "npm".to_string(),
            package_name: fields.product.clone(),
        });
    }

    // Rule 2: known Java vendor
    if let Some(group) = java_vendor_to_group(&vendor) {
        return Some(ResolvedCpe {
            ecosystem: "Maven".to_string(),
            package_name: format!("{}:{}", group, fields.product),
        });
    }

    // Rule 3: known Python vendor
    if is_python_vendor(&vendor) {
        return Some(ResolvedCpe {
            ecosystem: "PyPI".to_string(),
            package_name: fields.product.clone(),
        });
    }

    None
}

/// Map a vendor name to a Maven group ID prefix.
/// Returns `None` for unknown vendors.
pub fn java_vendor_to_group(vendor: &str) -> Option<&'static str> {
    match vendor {
        "apache" => Some("org.apache"),
        "fasterxml" => Some("com.fasterxml"),
        "google" => Some("com.google"),
        "springframework" | "spring" | "pivotal" => Some("org.springframework"),
        "eclipse" => Some("org.eclipse"),
        "hibernate" => Some("org.hibernate"),
        "log4j" => Some("org.apache.logging.log4j"),
        "jenkins" => Some("org.jenkins-ci"),
        _ => None,
    }
}

/// Return true when the vendor is a well-known Python ecosystem vendor.
pub fn is_python_vendor(vendor: &str) -> bool {
    matches!(
        vendor,
        "python"
            | "djangoproject"
            | "pallets"
            | "palletsprojects"
            | "pypa"
            | "pypi"
            | "tornadoweb"
            | "pocoo"
            | "celeryproject"
    )
}
