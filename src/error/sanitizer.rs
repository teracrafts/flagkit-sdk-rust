//! Error message sanitization to prevent information leakage.
//!
//! This module provides functionality to remove sensitive information from error
//! messages before they are logged or returned to users. It sanitizes:
//!
//! - File paths (Unix and Windows)
//! - IP addresses
//! - API keys (sdk_, srv_, cli_ prefixed)
//! - Email addresses
//! - Database connection strings

use lazy_static::lazy_static;
use regex::Regex;

/// Configuration for error message sanitization.
#[derive(Debug, Clone)]
pub struct ErrorSanitizationConfig {
    /// Whether sanitization is enabled. Defaults to true.
    pub enabled: bool,
    /// Whether to preserve the original (unsanitized) message internally.
    /// When true, the original message is stored but sanitized version is displayed.
    /// Defaults to false for maximum security.
    pub preserve_original: bool,
}

impl Default for ErrorSanitizationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            preserve_original: false,
        }
    }
}

impl ErrorSanitizationConfig {
    /// Create a new sanitization config with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a config with sanitization disabled.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            preserve_original: false,
        }
    }

    /// Create a config that preserves original messages internally.
    pub fn with_preservation() -> Self {
        Self {
            enabled: true,
            preserve_original: true,
        }
    }
}

lazy_static! {
    /// Regex patterns for sensitive information detection and replacement.
    static ref PATTERNS: Vec<(Regex, &'static str)> = vec![
        // Unix-style file paths (e.g., /home/user/file.txt)
        (Regex::new(r"/(?:[\w.-]+/)+[\w.-]+").unwrap(), "[PATH]"),
        // Windows-style file paths (e.g., C:\Users\user\file.txt)
        (Regex::new(r"[A-Za-z]:\\(?:[\w.-]+\\)+[\w.-]*").unwrap(), "[PATH]"),
        // IPv4 addresses
        (Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap(), "[IP]"),
        // SDK API keys
        (Regex::new(r"sdk_[a-zA-Z0-9_-]{8,}").unwrap(), "sdk_[REDACTED]"),
        // Server API keys
        (Regex::new(r"srv_[a-zA-Z0-9_-]{8,}").unwrap(), "srv_[REDACTED]"),
        // CLI API keys
        (Regex::new(r"cli_[a-zA-Z0-9_-]{8,}").unwrap(), "cli_[REDACTED]"),
        // Email addresses (including + for plus addressing)
        (Regex::new(r"[\w.+-]+@[\w.-]+\.\w+").unwrap(), "[EMAIL]"),
        // Database connection strings (postgres, mysql, mongodb, redis)
        (Regex::new(r"(?i)(?:postgres|mysql|mongodb|redis)://[^\s]+").unwrap(), "[CONNECTION_STRING]"),
    ];
}

/// Sanitize an error message by removing sensitive information.
///
/// This function applies all sanitization patterns to the input message,
/// replacing matches with safe placeholder values.
///
/// # Arguments
///
/// * `message` - The error message to sanitize
///
/// # Returns
///
/// A sanitized version of the message with sensitive data replaced
///
/// # Examples
///
/// ```
/// use flagkit::error::sanitizer::sanitize_message;
///
/// let message = "Failed to connect to 192.168.1.1 with key sdk_abc123xyz";
/// let sanitized = sanitize_message(message);
/// assert!(!sanitized.contains("192.168.1.1"));
/// assert!(!sanitized.contains("sdk_abc123xyz"));
/// ```
pub fn sanitize_message(message: &str) -> String {
    let mut result = message.to_string();

    for (pattern, replacement) in PATTERNS.iter() {
        result = pattern.replace_all(&result, *replacement).to_string();
    }

    result
}

/// A wrapper that holds both sanitized and optionally original error messages.
#[derive(Debug, Clone)]
pub struct SanitizedMessage {
    /// The sanitized (safe to display) message.
    pub sanitized: String,
    /// The original message, if preservation is enabled.
    pub original: Option<String>,
}

impl SanitizedMessage {
    /// Create a new sanitized message.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message to sanitize
    /// * `config` - The sanitization configuration
    pub fn new(message: &str, config: &ErrorSanitizationConfig) -> Self {
        if config.enabled {
            Self {
                sanitized: sanitize_message(message),
                original: if config.preserve_original {
                    Some(message.to_string())
                } else {
                    None
                },
            }
        } else {
            Self {
                sanitized: message.to_string(),
                original: None,
            }
        }
    }

    /// Get the display message (sanitized if enabled).
    pub fn display(&self) -> &str {
        &self.sanitized
    }

    /// Get the original message if available.
    pub fn original(&self) -> Option<&str> {
        self.original.as_deref()
    }
}

impl std::fmt::Display for SanitizedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.sanitized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === sanitize_message tests ===

    #[test]
    fn test_sanitize_unix_path() {
        let message = "Failed to read /home/user/config/app.conf";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Failed to read [PATH]");
        assert!(!sanitized.contains("/home"));
    }

    #[test]
    fn test_sanitize_windows_path() {
        let message = "Cannot open C:\\Users\\admin\\secrets.txt";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Cannot open [PATH]");
        assert!(!sanitized.contains("C:\\"));
    }

    #[test]
    fn test_sanitize_ipv4_address() {
        let message = "Connection refused by 192.168.1.100";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Connection refused by [IP]");
        assert!(!sanitized.contains("192.168"));
    }

    #[test]
    fn test_sanitize_sdk_api_key() {
        let message = "Authentication failed for sdk_abc123xyz789def";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Authentication failed for sdk_[REDACTED]");
        assert!(!sanitized.contains("abc123xyz"));
    }

    #[test]
    fn test_sanitize_srv_api_key() {
        let message = "Invalid key: srv_server_key_12345678";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Invalid key: srv_[REDACTED]");
        assert!(!sanitized.contains("server_key"));
    }

    #[test]
    fn test_sanitize_cli_api_key() {
        let message = "CLI key expired: cli_command_line_key";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "CLI key expired: cli_[REDACTED]");
        assert!(!sanitized.contains("command_line"));
    }

    #[test]
    fn test_sanitize_email_address() {
        let message = "User not found: admin@example.com";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "User not found: [EMAIL]");
        assert!(!sanitized.contains("admin@"));
    }

    #[test]
    fn test_sanitize_postgres_connection_string() {
        let message = "Database error: postgres://user:pass@localhost:5432/db";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Database error: [CONNECTION_STRING]");
        assert!(!sanitized.contains("user:pass"));
    }

    #[test]
    fn test_sanitize_mysql_connection_string() {
        let message = "Failed: mysql://root:secret@db.example.com/mydb";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Failed: [CONNECTION_STRING]");
        assert!(!sanitized.contains("root:secret"));
    }

    #[test]
    fn test_sanitize_mongodb_connection_string() {
        let message = "Connection failed: mongodb://admin:password@mongo.local:27017";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Connection failed: [CONNECTION_STRING]");
        assert!(!sanitized.contains("admin:password"));
    }

    #[test]
    fn test_sanitize_redis_connection_string() {
        let message = "Redis error: redis://default:mypassword@cache.example.com:6379";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Redis error: [CONNECTION_STRING]");
        assert!(!sanitized.contains("mypassword"));
    }

    #[test]
    fn test_sanitize_multiple_patterns() {
        let message = "Error at 10.0.0.1 with sdk_testkey1234567 for user@domain.com";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Error at [IP] with sdk_[REDACTED] for [EMAIL]");
        assert!(!sanitized.contains("10.0.0.1"));
        assert!(!sanitized.contains("testkey"));
        assert!(!sanitized.contains("user@"));
    }

    #[test]
    fn test_sanitize_no_sensitive_data() {
        let message = "Simple error occurred";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Simple error occurred");
    }

    #[test]
    fn test_sanitize_empty_message() {
        let sanitized = sanitize_message("");
        assert_eq!(sanitized, "");
    }

    #[test]
    fn test_sanitize_short_api_key_not_redacted() {
        // API keys must be at least 8 characters after the prefix
        let message = "Short key: sdk_abc";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Short key: sdk_abc");
    }

    // === ErrorSanitizationConfig tests ===

    #[test]
    fn test_config_default() {
        let config = ErrorSanitizationConfig::default();
        assert!(config.enabled);
        assert!(!config.preserve_original);
    }

    #[test]
    fn test_config_disabled() {
        let config = ErrorSanitizationConfig::disabled();
        assert!(!config.enabled);
        assert!(!config.preserve_original);
    }

    #[test]
    fn test_config_with_preservation() {
        let config = ErrorSanitizationConfig::with_preservation();
        assert!(config.enabled);
        assert!(config.preserve_original);
    }

    // === SanitizedMessage tests ===

    #[test]
    fn test_sanitized_message_enabled() {
        let config = ErrorSanitizationConfig::default();
        let msg = SanitizedMessage::new("Error at 192.168.1.1", &config);
        assert_eq!(msg.display(), "Error at [IP]");
        assert!(msg.original().is_none());
    }

    #[test]
    fn test_sanitized_message_disabled() {
        let config = ErrorSanitizationConfig::disabled();
        let msg = SanitizedMessage::new("Error at 192.168.1.1", &config);
        assert_eq!(msg.display(), "Error at 192.168.1.1");
        assert!(msg.original().is_none());
    }

    #[test]
    fn test_sanitized_message_with_preservation() {
        let config = ErrorSanitizationConfig::with_preservation();
        let original = "Error at 192.168.1.1";
        let msg = SanitizedMessage::new(original, &config);
        assert_eq!(msg.display(), "Error at [IP]");
        assert_eq!(msg.original(), Some(original));
    }

    #[test]
    fn test_sanitized_message_display_trait() {
        let config = ErrorSanitizationConfig::default();
        let msg = SanitizedMessage::new("Key: sdk_secret12345678", &config);
        let displayed = format!("{}", msg);
        assert_eq!(displayed, "Key: sdk_[REDACTED]");
    }

    // === Edge case tests ===

    #[test]
    fn test_sanitize_path_in_middle_of_text() {
        let message = "See file /var/log/app/error.log for details";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "See file [PATH] for details");
    }

    #[test]
    fn test_sanitize_multiple_ips() {
        let message = "Failed to route from 10.0.0.1 to 10.0.0.2";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Failed to route from [IP] to [IP]");
    }

    #[test]
    fn test_sanitize_case_insensitive_connection_string() {
        let message = "Error: POSTGRES://user:pass@host/db";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Error: [CONNECTION_STRING]");
    }

    #[test]
    fn test_sanitize_complex_email() {
        let message = "Contact user.name+tag@sub.domain.example.com";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Contact [EMAIL]");
    }

    #[test]
    fn test_sanitize_api_key_with_hyphens_and_underscores() {
        let message = "Key: sdk_test-key_123-abc_xyz";
        let sanitized = sanitize_message(message);
        assert_eq!(sanitized, "Key: sdk_[REDACTED]");
    }
}
