//! Semantic version comparison utilities for SDK version metadata handling.
//!
//! These utilities are used to compare the current SDK version against
//! server-provided version requirements (min, recommended, latest).

/// Parsed semantic version components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

/// Maximum allowed value for version components (defensive limit).
const MAX_VERSION_COMPONENT: u32 = 999_999_999;

/// Parse a semantic version string into numeric components.
/// Returns None if the version is not a valid semver.
///
/// # Examples
///
/// ```
/// use flagkit::utils::version::parse_version;
///
/// let v = parse_version("1.2.3").unwrap();
/// assert_eq!(v.major, 1);
/// assert_eq!(v.minor, 2);
/// assert_eq!(v.patch, 3);
///
/// // Also handles 'v' or 'V' prefix
/// let v = parse_version("v2.0.0").unwrap();
/// assert_eq!(v.major, 2);
///
/// // Handles whitespace
/// let v = parse_version(" 1.0.0 ").unwrap();
/// assert_eq!(v.major, 1);
///
/// // Returns None for invalid versions
/// assert!(parse_version("invalid").is_none());
/// ```
pub fn parse_version(version: &str) -> Option<ParsedVersion> {
    // Trim whitespace
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Strip leading 'v' or 'V' if present
    let normalized = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);

    // Split by '.' and parse first three components
    let parts: Vec<&str> = normalized.split('.').collect();
    if parts.len() < 3 {
        return None;
    }

    // Parse major, minor, patch (ignore pre-release suffix in patch)
    let major = parts[0].parse::<u32>().ok()?;
    if major > MAX_VERSION_COMPONENT {
        return None;
    }

    let minor = parts[1].parse::<u32>().ok()?;
    if minor > MAX_VERSION_COMPONENT {
        return None;
    }

    // Patch might have pre-release suffix like "3-beta.1" or build metadata "+build"
    let patch_str = parts[2]
        .split('-')
        .next()
        .and_then(|s| s.split('+').next())
        .unwrap_or(parts[2]);
    let patch = patch_str.parse::<u32>().ok()?;
    if patch > MAX_VERSION_COMPONENT {
        return None;
    }

    Some(ParsedVersion {
        major,
        minor,
        patch,
    })
}

/// Compare two semantic versions.
/// Returns:
///  - `Ordering::Less` if a < b
///  - `Ordering::Equal` if a == b
///  - `Ordering::Greater` if a > b
///
/// Returns `Ordering::Equal` if either version is invalid.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parsed_a = match parse_version(a) {
        Some(v) => v,
        None => return std::cmp::Ordering::Equal,
    };
    let parsed_b = match parse_version(b) {
        Some(v) => v,
        None => return std::cmp::Ordering::Equal,
    };

    // Compare major
    match parsed_a.major.cmp(&parsed_b.major) {
        std::cmp::Ordering::Equal => {}
        other => return other,
    }

    // Compare minor
    match parsed_a.minor.cmp(&parsed_b.minor) {
        std::cmp::Ordering::Equal => {}
        other => return other,
    }

    // Compare patch
    parsed_a.patch.cmp(&parsed_b.patch)
}

/// Check if version a is less than version b.
///
/// # Examples
///
/// ```
/// use flagkit::utils::version::is_version_less_than;
///
/// assert!(is_version_less_than("1.0.0", "1.1.0"));
/// assert!(is_version_less_than("1.0.0", "2.0.0"));
/// assert!(!is_version_less_than("1.1.0", "1.0.0"));
/// assert!(!is_version_less_than("1.0.0", "1.0.0"));
/// ```
pub fn is_version_less_than(a: &str, b: &str) -> bool {
    compare_versions(a, b) == std::cmp::Ordering::Less
}

/// Check if version a is greater than or equal to version b.
///
/// # Examples
///
/// ```
/// use flagkit::utils::version::is_version_at_least;
///
/// assert!(is_version_at_least("1.1.0", "1.0.0"));
/// assert!(is_version_at_least("1.0.0", "1.0.0"));
/// assert!(!is_version_at_least("1.0.0", "1.1.0"));
/// ```
pub fn is_version_at_least(a: &str, b: &str) -> bool {
    compare_versions(a, b) != std::cmp::Ordering::Less
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_valid() {
        let v = parse_version("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_parse_version_with_v_prefix() {
        let v = parse_version("v1.0.0").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_parse_version_with_prerelease() {
        let v = parse_version("1.0.0-beta.1").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_parse_version_invalid() {
        assert!(parse_version("").is_none());
        assert!(parse_version("invalid").is_none());
        assert!(parse_version("1.2").is_none());
        assert!(parse_version("a.b.c").is_none());
    }

    #[test]
    fn test_parse_version_uppercase_v_prefix() {
        let v = parse_version("V1.0.0").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_parse_version_with_whitespace() {
        let v = parse_version("  1.2.3  ").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_parse_version_whitespace_with_v_prefix() {
        let v = parse_version("  v1.0.0  ").unwrap();
        assert_eq!(v.major, 1);
    }

    #[test]
    fn test_parse_version_whitespace_only() {
        assert!(parse_version("   ").is_none());
    }

    #[test]
    fn test_parse_version_exceeds_max() {
        assert!(parse_version("1000000000.0.0").is_none());
    }

    #[test]
    fn test_parse_version_at_max_boundary() {
        let v = parse_version("999999999.999999999.999999999").unwrap();
        assert_eq!(v.major, 999999999);
        assert_eq!(v.minor, 999999999);
        assert_eq!(v.patch, 999999999);
    }

    #[test]
    fn test_parse_version_with_build_metadata() {
        let v = parse_version("1.0.0+build.123").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_compare_versions_equal() {
        assert_eq!(
            compare_versions("1.0.0", "1.0.0"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn test_compare_versions_less_major() {
        assert_eq!(
            compare_versions("1.0.0", "2.0.0"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_compare_versions_less_minor() {
        assert_eq!(
            compare_versions("1.0.0", "1.1.0"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_compare_versions_less_patch() {
        assert_eq!(
            compare_versions("1.0.0", "1.0.1"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_compare_versions_greater() {
        assert_eq!(
            compare_versions("2.0.0", "1.0.0"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_compare_versions_invalid_returns_equal() {
        assert_eq!(
            compare_versions("invalid", "1.0.0"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_versions("1.0.0", "invalid"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn test_is_version_less_than() {
        assert!(is_version_less_than("1.0.0", "1.0.1"));
        assert!(is_version_less_than("1.0.0", "1.1.0"));
        assert!(is_version_less_than("1.0.0", "2.0.0"));
        assert!(!is_version_less_than("1.0.0", "1.0.0"));
        assert!(!is_version_less_than("1.1.0", "1.0.0"));
    }

    #[test]
    fn test_is_version_at_least() {
        assert!(is_version_at_least("1.0.0", "1.0.0"));
        assert!(is_version_at_least("1.1.0", "1.0.0"));
        assert!(is_version_at_least("2.0.0", "1.0.0"));
        assert!(!is_version_at_least("1.0.0", "1.1.0"));
    }

    #[test]
    fn test_version_with_v_prefix_comparison() {
        assert!(is_version_less_than("v1.0.0", "v1.1.0"));
        assert!(is_version_at_least("v1.1.0", "v1.0.0"));
    }
}
