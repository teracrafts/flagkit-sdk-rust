//! Security utilities for FlagKit SDK
//!
//! This module provides utilities for detecting potential PII in data,
//! validating API key types, and warning about security concerns.

use serde_json::Value;

/// Logger trait for security warnings
///
/// Implement this trait to receive security-related log messages.
pub trait Logger: Send + Sync {
    /// Log a debug message
    fn debug(&self, message: &str);
    /// Log an info message
    fn info(&self, message: &str);
    /// Log a warning message
    fn warn(&self, message: &str);
    /// Log an error message
    fn error(&self, message: &str);
}

/// Common PII field patterns (case-insensitive)
const PII_PATTERNS: &[&str] = &[
    "email",
    "phone",
    "telephone",
    "mobile",
    "ssn",
    "social_security",
    "socialsecurity",
    "credit_card",
    "creditcard",
    "card_number",
    "cardnumber",
    "cvv",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "auth_token",
    "authtoken",
    "address",
    "street",
    "zip_code",
    "zipcode",
    "postal_code",
    "postalcode",
    "date_of_birth",
    "dateofbirth",
    "dob",
    "birth_date",
    "birthdate",
    "passport",
    "driver_license",
    "driverlicense",
    "national_id",
    "nationalid",
    "bank_account",
    "bankaccount",
    "routing_number",
    "routingnumber",
    "iban",
    "swift",
];

/// Security configuration options
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Warn about potential PII in context/events. Default: true in debug builds
    pub warn_on_potential_pii: bool,

    /// Warn when server keys are used in browser-like environments. Default: true
    pub warn_on_server_key_in_browser: bool,

    /// Custom PII patterns to detect (in addition to built-in patterns)
    pub additional_pii_patterns: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            // Default to warning in debug builds
            warn_on_potential_pii: cfg!(debug_assertions),
            warn_on_server_key_in_browser: true,
            additional_pii_patterns: Vec::new(),
        }
    }
}

impl SecurityConfig {
    /// Create a new security configuration with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for security configuration
    pub fn builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder::default()
    }
}

/// Builder for SecurityConfig
#[derive(Debug, Default)]
pub struct SecurityConfigBuilder {
    warn_on_potential_pii: Option<bool>,
    warn_on_server_key_in_browser: Option<bool>,
    additional_pii_patterns: Vec<String>,
}

impl SecurityConfigBuilder {
    /// Set whether to warn on potential PII
    pub fn warn_on_potential_pii(mut self, warn: bool) -> Self {
        self.warn_on_potential_pii = Some(warn);
        self
    }

    /// Set whether to warn on server key in browser
    pub fn warn_on_server_key_in_browser(mut self, warn: bool) -> Self {
        self.warn_on_server_key_in_browser = Some(warn);
        self
    }

    /// Add additional PII patterns to detect
    pub fn additional_pii_patterns(mut self, patterns: Vec<String>) -> Self {
        self.additional_pii_patterns = patterns;
        self
    }

    /// Add a single additional PII pattern
    pub fn add_pii_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.additional_pii_patterns.push(pattern.into());
        self
    }

    /// Build the security configuration
    pub fn build(self) -> SecurityConfig {
        SecurityConfig {
            warn_on_potential_pii: self.warn_on_potential_pii.unwrap_or(cfg!(debug_assertions)),
            warn_on_server_key_in_browser: self.warn_on_server_key_in_browser.unwrap_or(true),
            additional_pii_patterns: self.additional_pii_patterns,
        }
    }
}

/// Check if a field name potentially contains PII
///
/// This function performs a case-insensitive check against common PII field patterns.
///
/// # Arguments
///
/// * `field_name` - The field name to check
///
/// # Returns
///
/// Returns `true` if the field name matches any PII pattern
///
/// # Examples
///
/// ```
/// use flagkit::security::is_potential_pii_field;
///
/// assert!(is_potential_pii_field("email"));
/// assert!(is_potential_pii_field("user_email"));
/// assert!(is_potential_pii_field("EmailAddress"));
/// assert!(!is_potential_pii_field("username"));
/// ```
pub fn is_potential_pii_field(field_name: &str) -> bool {
    is_potential_pii_field_with_config(field_name, None)
}

/// Check if a field name potentially contains PII with custom configuration
///
/// # Arguments
///
/// * `field_name` - The field name to check
/// * `config` - Optional security configuration with additional patterns
///
/// # Returns
///
/// Returns `true` if the field name matches any PII pattern
pub fn is_potential_pii_field_with_config(
    field_name: &str,
    config: Option<&SecurityConfig>,
) -> bool {
    let lower_name = field_name.to_lowercase();

    // Check built-in patterns
    if PII_PATTERNS
        .iter()
        .any(|pattern| lower_name.contains(pattern))
    {
        return true;
    }

    // Check additional patterns from config
    if let Some(cfg) = config {
        if cfg
            .additional_pii_patterns
            .iter()
            .any(|pattern| lower_name.contains(&pattern.to_lowercase()))
        {
            return true;
        }
    }

    false
}

/// Detect potential PII in a JSON value and return the field paths
///
/// This function recursively checks all keys in a JSON object for PII patterns.
///
/// # Arguments
///
/// * `data` - The JSON value to check
/// * `prefix` - The current path prefix (use empty string for root)
///
/// # Returns
///
/// A vector of field paths that potentially contain PII
///
/// # Examples
///
/// ```
/// use flagkit::security::detect_potential_pii;
/// use serde_json::json;
///
/// let data = json!({
///     "user": {
///         "email": "test@example.com",
///         "name": "John"
///     }
/// });
///
/// let pii_fields = detect_potential_pii(&data, "");
/// assert!(pii_fields.contains(&"user.email".to_string()));
/// assert!(!pii_fields.contains(&"user.name".to_string()));
/// ```
pub fn detect_potential_pii(data: &Value, prefix: &str) -> Vec<String> {
    detect_potential_pii_with_config(data, prefix, None)
}

/// Detect potential PII with custom configuration
///
/// # Arguments
///
/// * `data` - The JSON value to check
/// * `prefix` - The current path prefix (use empty string for root)
/// * `config` - Optional security configuration with additional patterns
///
/// # Returns
///
/// A vector of field paths that potentially contain PII
pub fn detect_potential_pii_with_config(
    data: &Value,
    prefix: &str,
    config: Option<&SecurityConfig>,
) -> Vec<String> {
    let mut pii_fields = Vec::new();

    if let Value::Object(map) = data {
        for (key, value) in map {
            let full_path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", prefix, key)
            };

            if is_potential_pii_field_with_config(key, config) {
                pii_fields.push(full_path.clone());
            }

            // Recursively check nested objects
            if value.is_object() {
                let nested_pii = detect_potential_pii_with_config(value, &full_path, config);
                pii_fields.extend(nested_pii);
            }

            // Also check arrays of objects
            if let Value::Array(arr) = value {
                for (i, item) in arr.iter().enumerate() {
                    if item.is_object() {
                        let array_path = format!("{}[{}]", full_path, i);
                        let nested_pii = detect_potential_pii_with_config(item, &array_path, config);
                        pii_fields.extend(nested_pii);
                    }
                }
            }
        }
    }

    pii_fields
}

/// Data type for PII warning messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    /// Evaluation context data
    Context,
    /// Analytics event data
    Event,
}

impl DataType {
    /// Get the display name for this data type
    pub fn as_str(&self) -> &'static str {
        match self {
            DataType::Context => "context",
            DataType::Event => "event",
        }
    }
}

/// Warn if potential PII is detected in data
///
/// This function logs a warning if any field names match PII patterns.
///
/// # Arguments
///
/// * `data` - Optional JSON data to check
/// * `data_type` - The type of data being checked (context or event)
/// * `logger` - Optional logger to use for warnings
///
/// # Examples
///
/// ```
/// use flagkit::security::{warn_if_potential_pii, DataType};
/// use serde_json::json;
///
/// let data = json!({
///     "email": "test@example.com"
/// });
///
/// // Without a logger, this just returns without side effects
/// warn_if_potential_pii(Some(&data), DataType::Context, None);
/// ```
pub fn warn_if_potential_pii(
    data: Option<&Value>,
    data_type: DataType,
    logger: Option<&dyn Logger>,
) {
    warn_if_potential_pii_with_config(data, data_type, logger, None)
}

/// Warn if potential PII is detected with custom configuration
///
/// # Arguments
///
/// * `data` - Optional JSON data to check
/// * `data_type` - The type of data being checked (context or event)
/// * `logger` - Optional logger to use for warnings
/// * `config` - Optional security configuration
pub fn warn_if_potential_pii_with_config(
    data: Option<&Value>,
    data_type: DataType,
    logger: Option<&dyn Logger>,
    config: Option<&SecurityConfig>,
) {
    let Some(data) = data else {
        return;
    };

    let Some(logger) = logger else {
        return;
    };

    // Check if warnings are enabled
    if let Some(cfg) = config {
        if !cfg.warn_on_potential_pii {
            return;
        }
    }

    let pii_fields = detect_potential_pii_with_config(data, "", config);

    if !pii_fields.is_empty() {
        let suggestion = match data_type {
            DataType::Context => "Consider adding these to privateAttributes.",
            DataType::Event => "Consider removing sensitive data from events.",
        };

        logger.warn(&format!(
            "[FlagKit Security] Potential PII detected in {} data: {}. {}",
            data_type.as_str(),
            pii_fields.join(", "),
            suggestion
        ));
    }
}

/// Check if an API key is a server key
///
/// Server keys start with `srv_` and should only be used in server-side code.
///
/// # Arguments
///
/// * `api_key` - The API key to check
///
/// # Returns
///
/// Returns `true` if the key starts with `srv_`
///
/// # Examples
///
/// ```
/// use flagkit::security::is_server_key;
///
/// assert!(is_server_key("srv_abc123"));
/// assert!(!is_server_key("sdk_abc123"));
/// assert!(!is_server_key("cli_abc123"));
/// ```
pub fn is_server_key(api_key: &str) -> bool {
    api_key.starts_with("srv_")
}

/// Check if an API key is a client/SDK key
///
/// Client keys start with `sdk_` or `cli_` and are safe for client-side use.
///
/// # Arguments
///
/// * `api_key` - The API key to check
///
/// # Returns
///
/// Returns `true` if the key starts with `sdk_` or `cli_`
///
/// # Examples
///
/// ```
/// use flagkit::security::is_client_key;
///
/// assert!(is_client_key("sdk_abc123"));
/// assert!(is_client_key("cli_abc123"));
/// assert!(!is_client_key("srv_abc123"));
/// ```
pub fn is_client_key(api_key: &str) -> bool {
    api_key.starts_with("sdk_") || api_key.starts_with("cli_")
}

/// Check if the current environment is browser-like
///
/// In Rust, this is typically determined by target features or configuration.
/// By default, this returns `false` for standard Rust builds.
/// When targeting WebAssembly (wasm32), this returns `true`.
pub fn is_browser_environment() -> bool {
    cfg!(target_arch = "wasm32")
}

/// Warn if a server key is used in a browser-like environment
///
/// This function logs a warning if a server key is detected in an environment
/// where client-side code might be running (e.g., WebAssembly).
///
/// # Arguments
///
/// * `api_key` - The API key to check
/// * `logger` - Optional logger to use for warnings
///
/// # Examples
///
/// ```
/// use flagkit::security::warn_if_server_key_in_browser;
///
/// // This would warn in a WASM environment
/// warn_if_server_key_in_browser("srv_abc123", None);
/// ```
pub fn warn_if_server_key_in_browser(api_key: &str, logger: Option<&dyn Logger>) {
    warn_if_server_key_in_browser_with_config(api_key, logger, None)
}

/// Warn if a server key is used in a browser-like environment with configuration
///
/// # Arguments
///
/// * `api_key` - The API key to check
/// * `logger` - Optional logger to use for warnings
/// * `config` - Optional security configuration
pub fn warn_if_server_key_in_browser_with_config(
    api_key: &str,
    logger: Option<&dyn Logger>,
    config: Option<&SecurityConfig>,
) {
    // Check if warnings are enabled
    if let Some(cfg) = config {
        if !cfg.warn_on_server_key_in_browser {
            return;
        }
    }

    if is_browser_environment() && is_server_key(api_key) {
        let message = concat!(
            "[FlagKit Security] WARNING: Server keys (srv_) should not be used in browser environments. ",
            "This exposes your server key in client-side code, which is a security risk. ",
            "Use SDK keys (sdk_) for client-side applications instead. ",
            "See: https://docs.flagkit.dev/sdk/security#api-keys"
        );

        // Log through the provided logger if available
        if let Some(logger) = logger {
            logger.warn(message);
        }

        // Also print to stderr for visibility in WASM environments
        #[cfg(target_arch = "wasm32")]
        {
            // In WASM, we might want to use web_sys::console::warn
            // For now, we just rely on the logger
            eprintln!("{}", message);
        }
    }
}

/// Validate an API key format and check security implications
///
/// # Arguments
///
/// * `api_key` - The API key to validate
/// * `logger` - Optional logger for warnings
/// * `config` - Optional security configuration
///
/// # Returns
///
/// Returns `Ok(())` if the key format is valid, or an error message if invalid
pub fn validate_api_key_security(
    api_key: &str,
    logger: Option<&dyn Logger>,
    config: Option<&SecurityConfig>,
) -> Result<(), String> {
    if api_key.is_empty() {
        return Err("API key cannot be empty".to_string());
    }

    if !is_server_key(api_key) && !is_client_key(api_key) {
        return Err(format!(
            "Invalid API key format. Keys must start with 'sdk_', 'srv_', or 'cli_'. Got: {}...",
            &api_key[..api_key.len().min(8)]
        ));
    }

    // Warn about server key in browser
    warn_if_server_key_in_browser_with_config(api_key, logger, config);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Test logger that captures messages
    struct TestLogger {
        messages: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl TestLogger {
        fn new() -> Self {
            Self {
                messages: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn get_messages(&self) -> Vec<(String, String)> {
            self.messages.lock().unwrap().clone()
        }
    }

    impl Logger for TestLogger {
        fn debug(&self, message: &str) {
            self.messages
                .lock()
                .unwrap()
                .push(("debug".to_string(), message.to_string()));
        }

        fn info(&self, message: &str) {
            self.messages
                .lock()
                .unwrap()
                .push(("info".to_string(), message.to_string()));
        }

        fn warn(&self, message: &str) {
            self.messages
                .lock()
                .unwrap()
                .push(("warn".to_string(), message.to_string()));
        }

        fn error(&self, message: &str) {
            self.messages
                .lock()
                .unwrap()
                .push(("error".to_string(), message.to_string()));
        }
    }

    #[test]
    fn test_is_potential_pii_field_basic() {
        assert!(is_potential_pii_field("email"));
        assert!(is_potential_pii_field("phone"));
        assert!(is_potential_pii_field("password"));
        assert!(is_potential_pii_field("ssn"));
    }

    #[test]
    fn test_is_potential_pii_field_case_insensitive() {
        assert!(is_potential_pii_field("Email"));
        assert!(is_potential_pii_field("EMAIL"));
        assert!(is_potential_pii_field("eMaIl"));
    }

    #[test]
    fn test_is_potential_pii_field_partial_match() {
        assert!(is_potential_pii_field("user_email"));
        assert!(is_potential_pii_field("email_address"));
        assert!(is_potential_pii_field("primaryEmail"));
    }

    #[test]
    fn test_is_potential_pii_field_non_pii() {
        assert!(!is_potential_pii_field("username"));
        assert!(!is_potential_pii_field("id"));
        assert!(!is_potential_pii_field("name"));
        assert!(!is_potential_pii_field("count"));
    }

    #[test]
    fn test_detect_potential_pii_flat() {
        let data = serde_json::json!({
            "email": "test@example.com",
            "name": "John",
            "phone": "123-456-7890"
        });

        let pii = detect_potential_pii(&data, "");
        assert!(pii.contains(&"email".to_string()));
        assert!(pii.contains(&"phone".to_string()));
        assert!(!pii.contains(&"name".to_string()));
    }

    #[test]
    fn test_detect_potential_pii_nested() {
        let data = serde_json::json!({
            "user": {
                "email": "test@example.com",
                "profile": {
                    "ssn": "123-45-6789"
                }
            }
        });

        let pii = detect_potential_pii(&data, "");
        assert!(pii.contains(&"user.email".to_string()));
        assert!(pii.contains(&"user.profile.ssn".to_string()));
    }

    #[test]
    fn test_detect_potential_pii_with_prefix() {
        let data = serde_json::json!({
            "email": "test@example.com"
        });

        let pii = detect_potential_pii(&data, "context");
        assert!(pii.contains(&"context.email".to_string()));
    }

    #[test]
    fn test_detect_potential_pii_array() {
        let data = serde_json::json!({
            "users": [
                { "email": "a@example.com" },
                { "email": "b@example.com" }
            ]
        });

        let pii = detect_potential_pii(&data, "");
        assert!(pii.contains(&"users[0].email".to_string()));
        assert!(pii.contains(&"users[1].email".to_string()));
    }

    #[test]
    fn test_detect_potential_pii_empty() {
        let data = serde_json::json!({});
        let pii = detect_potential_pii(&data, "");
        assert!(pii.is_empty());
    }

    #[test]
    fn test_detect_potential_pii_non_object() {
        let data = serde_json::json!("string value");
        let pii = detect_potential_pii(&data, "");
        assert!(pii.is_empty());
    }

    #[test]
    fn test_is_server_key() {
        assert!(is_server_key("srv_abc123"));
        assert!(is_server_key("srv_"));
        assert!(!is_server_key("sdk_abc123"));
        assert!(!is_server_key("cli_abc123"));
        assert!(!is_server_key(""));
        assert!(!is_server_key("srv"));
    }

    #[test]
    fn test_is_client_key() {
        assert!(is_client_key("sdk_abc123"));
        assert!(is_client_key("cli_abc123"));
        assert!(is_client_key("sdk_"));
        assert!(is_client_key("cli_"));
        assert!(!is_client_key("srv_abc123"));
        assert!(!is_client_key(""));
        assert!(!is_client_key("sdk"));
    }

    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert!(config.warn_on_server_key_in_browser);
        assert!(config.additional_pii_patterns.is_empty());
    }

    #[test]
    fn test_security_config_builder() {
        let config = SecurityConfig::builder()
            .warn_on_potential_pii(false)
            .warn_on_server_key_in_browser(false)
            .add_pii_pattern("custom_field")
            .build();

        assert!(!config.warn_on_potential_pii);
        assert!(!config.warn_on_server_key_in_browser);
        assert!(config.additional_pii_patterns.contains(&"custom_field".to_string()));
    }

    #[test]
    fn test_additional_pii_patterns() {
        let config = SecurityConfig::builder()
            .add_pii_pattern("custom_secret")
            .build();

        assert!(is_potential_pii_field_with_config("custom_secret", Some(&config)));
        assert!(is_potential_pii_field_with_config("my_custom_secret_field", Some(&config)));
        assert!(!is_potential_pii_field_with_config("other_field", Some(&config)));
    }

    #[test]
    fn test_warn_if_potential_pii_no_data() {
        let logger = TestLogger::new();
        warn_if_potential_pii(None, DataType::Context, Some(&logger));
        assert!(logger.get_messages().is_empty());
    }

    #[test]
    fn test_warn_if_potential_pii_no_logger() {
        let data = serde_json::json!({ "email": "test@example.com" });
        // Should not panic
        warn_if_potential_pii(Some(&data), DataType::Context, None);
    }

    #[test]
    fn test_warn_if_potential_pii_logs_warning() {
        let logger = TestLogger::new();
        let data = serde_json::json!({ "email": "test@example.com" });

        warn_if_potential_pii(Some(&data), DataType::Context, Some(&logger));

        let messages = logger.get_messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].0, "warn");
        assert!(messages[0].1.contains("email"));
        assert!(messages[0].1.contains("context"));
    }

    #[test]
    fn test_warn_if_potential_pii_event_message() {
        let logger = TestLogger::new();
        let data = serde_json::json!({ "phone": "123-456-7890" });

        warn_if_potential_pii(Some(&data), DataType::Event, Some(&logger));

        let messages = logger.get_messages();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].1.contains("event"));
        assert!(messages[0].1.contains("removing sensitive data"));
    }

    #[test]
    fn test_warn_if_potential_pii_disabled() {
        let logger = TestLogger::new();
        let data = serde_json::json!({ "email": "test@example.com" });
        let config = SecurityConfig::builder()
            .warn_on_potential_pii(false)
            .build();

        warn_if_potential_pii_with_config(
            Some(&data),
            DataType::Context,
            Some(&logger),
            Some(&config),
        );

        assert!(logger.get_messages().is_empty());
    }

    #[test]
    fn test_validate_api_key_security_empty() {
        let result = validate_api_key_security("", None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_validate_api_key_security_invalid_format() {
        let result = validate_api_key_security("invalid_key", None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid API key format"));
    }

    #[test]
    fn test_validate_api_key_security_valid() {
        assert!(validate_api_key_security("sdk_abc123", None, None).is_ok());
        assert!(validate_api_key_security("srv_abc123", None, None).is_ok());
        assert!(validate_api_key_security("cli_abc123", None, None).is_ok());
    }

    #[test]
    fn test_data_type_display() {
        assert_eq!(DataType::Context.as_str(), "context");
        assert_eq!(DataType::Event.as_str(), "event");
    }

    #[test]
    fn test_is_browser_environment() {
        // In standard Rust tests, this should return false
        #[cfg(not(target_arch = "wasm32"))]
        assert!(!is_browser_environment());
    }

    #[test]
    fn test_pii_patterns_comprehensive() {
        // Test all PII patterns
        let pii_fields = [
            "email", "phone", "telephone", "mobile", "ssn", "social_security",
            "credit_card", "cvv", "password", "passwd", "secret", "token",
            "api_key", "private_key", "access_token", "refresh_token", "auth_token",
            "address", "street", "zip_code", "postal_code", "date_of_birth",
            "dob", "birth_date", "passport", "driver_license", "national_id",
            "bank_account", "routing_number", "iban", "swift",
        ];

        for field in pii_fields {
            assert!(
                is_potential_pii_field(field),
                "Expected '{}' to be detected as PII",
                field
            );
        }
    }
}
