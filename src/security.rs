//! Security utilities for FlagKit SDK
//!
//! This module provides comprehensive security features including:
//! - PII detection and warnings
//! - Request signing with HMAC-SHA256
//! - API key rotation with automatic failover
//! - Strict PII mode enforcement
//! - Cache encryption using AES-256-GCM

use aes_gcm::{
    aead::{Aead, KeyInit as AesKeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac_array;
use serde_json::Value;
use sha2::Sha256;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{ErrorCode, FlagKitError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Salt for PBKDF2 key derivation
const PBKDF2_SALT: &[u8] = b"flagkit-cache-encryption-salt";

/// Number of PBKDF2 iterations
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Nonce size for AES-256-GCM (96 bits = 12 bytes)
const NONCE_SIZE: usize = 12;

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

    /// Enable strict PII mode - returns SecurityError instead of warning
    pub strict_pii_mode: bool,

    /// Private attributes that are allowed to contain PII
    pub private_attributes: Vec<String>,

    /// Secondary API key for automatic failover on 401 errors
    pub secondary_api_key: Option<String>,

    /// Enable request signing with HMAC-SHA256
    pub enable_request_signing: bool,

    /// Enable cache encryption
    pub enable_cache_encryption: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            // Default to warning in debug builds
            warn_on_potential_pii: cfg!(debug_assertions),
            warn_on_server_key_in_browser: true,
            additional_pii_patterns: Vec::new(),
            strict_pii_mode: false,
            private_attributes: Vec::new(),
            secondary_api_key: None,
            enable_request_signing: false,
            enable_cache_encryption: false,
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
    strict_pii_mode: bool,
    private_attributes: Vec<String>,
    secondary_api_key: Option<String>,
    enable_request_signing: bool,
    enable_cache_encryption: bool,
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

    /// Enable strict PII mode - returns SecurityError instead of warning
    pub fn strict_pii_mode(mut self, strict: bool) -> Self {
        self.strict_pii_mode = strict;
        self
    }

    /// Set private attributes that are allowed to contain PII
    pub fn private_attributes(mut self, attributes: Vec<String>) -> Self {
        self.private_attributes = attributes;
        self
    }

    /// Add a single private attribute
    pub fn add_private_attribute(mut self, attribute: impl Into<String>) -> Self {
        self.private_attributes.push(attribute.into());
        self
    }

    /// Set secondary API key for automatic failover
    pub fn secondary_api_key(mut self, key: impl Into<String>) -> Self {
        self.secondary_api_key = Some(key.into());
        self
    }

    /// Enable request signing with HMAC-SHA256
    pub fn enable_request_signing(mut self, enable: bool) -> Self {
        self.enable_request_signing = enable;
        self
    }

    /// Enable cache encryption
    pub fn enable_cache_encryption(mut self, enable: bool) -> Self {
        self.enable_cache_encryption = enable;
        self
    }

    /// Build the security configuration
    pub fn build(self) -> SecurityConfig {
        SecurityConfig {
            warn_on_potential_pii: self.warn_on_potential_pii.unwrap_or(cfg!(debug_assertions)),
            warn_on_server_key_in_browser: self.warn_on_server_key_in_browser.unwrap_or(true),
            additional_pii_patterns: self.additional_pii_patterns,
            strict_pii_mode: self.strict_pii_mode,
            private_attributes: self.private_attributes,
            secondary_api_key: self.secondary_api_key,
            enable_request_signing: self.enable_request_signing,
            enable_cache_encryption: self.enable_cache_encryption,
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

            // Check if this field is in private_attributes
            let is_private = config
                .map(|cfg| {
                    cfg.private_attributes
                        .iter()
                        .any(|attr| attr == key || full_path.ends_with(attr))
                })
                .unwrap_or(false);

            if !is_private && is_potential_pii_field_with_config(key, config) {
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

/// Check PII in strict mode - returns error if PII detected without private_attributes
///
/// In strict PII mode, if potential PII is detected and the field is not marked
/// as a private attribute, this function returns a SecurityError instead of just
/// warning.
///
/// # Arguments
///
/// * `data` - Optional JSON data to check
/// * `data_type` - The type of data being checked (context or event)
/// * `config` - Security configuration
///
/// # Returns
///
/// * `Ok(())` - No PII detected or all PII fields are in private_attributes
/// * `Err(FlagKitError)` - PII detected in strict mode without private_attributes
pub fn check_pii_strict(
    data: Option<&Value>,
    data_type: DataType,
    config: &SecurityConfig,
) -> Result<()> {
    if !config.strict_pii_mode {
        return Ok(());
    }

    let Some(data) = data else {
        return Ok(());
    };

    let pii_fields = detect_potential_pii_with_config(data, "", Some(config));

    if !pii_fields.is_empty() {
        let suggestion = match data_type {
            DataType::Context => "Add these fields to private_attributes or remove the PII data.",
            DataType::Event => "Remove sensitive data from events.",
        };

        return Err(FlagKitError::new(
            ErrorCode::SecurityPiiDetected,
            format!(
                "[FlagKit Security] Potential PII detected in {} data: {}. {}",
                data_type.as_str(),
                pii_fields.join(", "),
                suggestion
            ),
        ));
    }

    Ok(())
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
) -> std::result::Result<(), String> {
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

// =============================================================================
// Local Port Restriction
// =============================================================================

/// Check if the current environment is production
///
/// Checks RUST_ENV and APP_ENV environment variables.
pub fn is_production_environment() -> bool {
    let rust_env = env::var("RUST_ENV").unwrap_or_default();
    let app_env = env::var("APP_ENV").unwrap_or_default();

    rust_env.eq_ignore_ascii_case("production") || app_env.eq_ignore_ascii_case("production")
}

// =============================================================================
// Request Signing (HMAC-SHA256)
// =============================================================================

/// Request signature headers
#[derive(Debug, Clone)]
pub struct RequestSignature {
    /// HMAC-SHA256 signature of the request body
    pub signature: String,
    /// Unix timestamp when the signature was created
    pub timestamp: u64,
    /// Key ID (first 8 characters of API key hash)
    pub key_id: String,
}

impl RequestSignature {
    /// Get the X-Signature header value
    pub fn x_signature(&self) -> &str {
        &self.signature
    }

    /// Get the X-Timestamp header value
    pub fn x_timestamp(&self) -> String {
        self.timestamp.to_string()
    }

    /// Get the X-Key-Id header value
    pub fn x_key_id(&self) -> &str {
        &self.key_id
    }
}

/// Sign a request body using HMAC-SHA256
///
/// Generates headers for request signing:
/// - X-Signature: HMAC-SHA256 signature of the body
/// - X-Timestamp: Unix timestamp
/// - X-Key-Id: First 8 characters of the API key hash
///
/// # Arguments
///
/// * `body` - The request body to sign (JSON string)
/// * `api_key` - The API key to use for signing
///
/// # Returns
///
/// * `Ok(RequestSignature)` - The signature headers
/// * `Err(FlagKitError)` - If signing fails
///
/// # Examples
///
/// ```
/// use flagkit::security::sign_request;
///
/// let body = r#"{"flag_key": "my-flag"}"#;
/// let signature = sign_request(body, "sdk_my_api_key").unwrap();
///
/// // Use signature headers in HTTP request:
/// // X-Signature: <signature.signature>
/// // X-Timestamp: <signature.timestamp>
/// // X-Key-Id: <signature.key_id>
/// ```
pub fn sign_request(body: &str, api_key: &str) -> Result<RequestSignature> {
    // Get current Unix timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| {
            FlagKitError::with_source(
                ErrorCode::SecuritySignatureError,
                "Failed to get current timestamp",
                e,
            )
        })?
        .as_secs();

    // Create the signing payload: timestamp + body
    let signing_payload = format!("{}.{}", timestamp, body);

    // Create HMAC-SHA256 signature
    let mut mac = <HmacSha256 as Mac>::new_from_slice(api_key.as_bytes()).map_err(|e| {
        FlagKitError::new(
            ErrorCode::SecuritySignatureError,
            format!("Failed to create HMAC: {}", e),
        )
    })?;

    mac.update(signing_payload.as_bytes());
    let result = mac.finalize();
    let signature = hex::encode(result.into_bytes());

    // Create key ID from first 8 chars of API key hash
    let mut key_hasher = <HmacSha256 as Mac>::new_from_slice(b"flagkit-key-id").map_err(|e| {
        FlagKitError::new(
            ErrorCode::SecuritySignatureError,
            format!("Failed to create key ID hash: {}", e),
        )
    })?;
    key_hasher.update(api_key.as_bytes());
    let key_hash = hex::encode(key_hasher.finalize().into_bytes());
    let key_id = key_hash[..8].to_string();

    Ok(RequestSignature {
        signature,
        timestamp,
        key_id,
    })
}

/// Verify a request signature
///
/// # Arguments
///
/// * `body` - The request body that was signed
/// * `signature` - The signature to verify
/// * `timestamp` - The timestamp used in signing
/// * `api_key` - The API key used for signing
///
/// # Returns
///
/// * `Ok(true)` - Signature is valid
/// * `Ok(false)` - Signature is invalid
/// * `Err(FlagKitError)` - If verification fails due to an error
pub fn verify_signature(body: &str, signature: &str, timestamp: u64, api_key: &str) -> Result<bool> {
    let signing_payload = format!("{}.{}", timestamp, body);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(api_key.as_bytes()).map_err(|e| {
        FlagKitError::new(
            ErrorCode::SecuritySignatureError,
            format!("Failed to create HMAC for verification: {}", e),
        )
    })?;

    mac.update(signing_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    Ok(expected == signature)
}

// =============================================================================
// Key Rotation
// =============================================================================

/// API key manager for handling key rotation and failover
#[derive(Debug)]
pub struct ApiKeyManager {
    primary_key: String,
    secondary_key: Option<String>,
    using_secondary: AtomicBool,
}

impl Clone for ApiKeyManager {
    fn clone(&self) -> Self {
        Self {
            primary_key: self.primary_key.clone(),
            secondary_key: self.secondary_key.clone(),
            using_secondary: AtomicBool::new(self.using_secondary.load(Ordering::Relaxed)),
        }
    }
}

impl ApiKeyManager {
    /// Create a new API key manager
    ///
    /// # Arguments
    ///
    /// * `primary_key` - The primary API key
    /// * `secondary_key` - Optional secondary API key for failover
    pub fn new(primary_key: impl Into<String>, secondary_key: Option<String>) -> Self {
        Self {
            primary_key: primary_key.into(),
            secondary_key,
            using_secondary: AtomicBool::new(false),
        }
    }

    /// Get the current active API key
    pub fn current_key(&self) -> &str {
        if self.using_secondary.load(Ordering::Relaxed) {
            self.secondary_key.as_deref().unwrap_or(&self.primary_key)
        } else {
            &self.primary_key
        }
    }

    /// Check if currently using the secondary key
    pub fn is_using_secondary(&self) -> bool {
        self.using_secondary.load(Ordering::Relaxed)
    }

    /// Handle a 401 unauthorized error by switching to secondary key
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Successfully switched to secondary key
    /// * `Ok(false)` - No secondary key available or already using secondary
    /// * `Err(FlagKitError)` - Key rotation failed
    pub fn handle_401_error(&self) -> Result<bool> {
        // If we don't have a secondary key, we can't rotate
        if self.secondary_key.is_none() {
            return Ok(false);
        }

        // If we're already using secondary, we can't rotate further
        if self.is_using_secondary() {
            return Err(FlagKitError::new(
                ErrorCode::SecurityKeyRotationFailed,
                "Both primary and secondary API keys have failed. Please check your API key configuration.",
            ));
        }

        // Switch to secondary key
        self.using_secondary.store(true, Ordering::Relaxed);

        Ok(true)
    }

    /// Reset to using the primary key
    pub fn reset_to_primary(&self) {
        self.using_secondary.store(false, Ordering::Relaxed);
    }

    /// Check if a secondary key is configured
    pub fn has_secondary_key(&self) -> bool {
        self.secondary_key.is_some()
    }
}

// =============================================================================
// Cache Encryption (AES-256-GCM with PBKDF2 key derivation)
// =============================================================================

/// Encrypted cache storage
///
/// Note: This struct does not implement Clone because the underlying cipher
/// cannot be safely cloned. Create a new instance with the same API key if needed.
pub struct EncryptedCache {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for EncryptedCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedCache")
            .field("cipher", &"<AES-256-GCM cipher>")
            .finish()
    }
}

impl EncryptedCache {
    /// Create a new encrypted cache with key derived from API key using PBKDF2
    ///
    /// # Arguments
    ///
    /// * `api_key` - The API key to derive encryption key from
    ///
    /// # Examples
    ///
    /// ```
    /// use flagkit::security::EncryptedCache;
    ///
    /// let cache = EncryptedCache::new("sdk_my_api_key").unwrap();
    ///
    /// // Encrypt some data
    /// let encrypted = cache.encrypt(b"sensitive data").unwrap();
    ///
    /// // Decrypt the data
    /// let decrypted = cache.decrypt(&encrypted).unwrap();
    /// assert_eq!(decrypted, b"sensitive data");
    /// ```
    pub fn new(api_key: &str) -> Result<Self> {
        // Derive a 256-bit key from the API key using PBKDF2
        let key: [u8; 32] =
            pbkdf2_hmac_array::<Sha256, 32>(api_key.as_bytes(), PBKDF2_SALT, PBKDF2_ITERATIONS);

        let cipher = <Aes256Gcm as AesKeyInit>::new_from_slice(&key).map_err(|e| {
            FlagKitError::new(
                ErrorCode::CacheEncryptionError,
                format!("Failed to create cipher: {}", e),
            )
        })?;

        Ok(Self { cipher })
    }

    /// Encrypt data using AES-256-GCM
    ///
    /// The returned bytes contain: nonce (12 bytes) + ciphertext + auth tag
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The encrypted data
    /// * `Err(FlagKitError)` - If encryption fails
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Generate a random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom(&mut nonce_bytes)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let ciphertext = self.cipher.encrypt(nonce, plaintext).map_err(|e| {
            FlagKitError::new(
                ErrorCode::CacheEncryptionError,
                format!("Encryption failed: {}", e),
            )
        })?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Decrypt data using AES-256-GCM
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted data (nonce + ciphertext + auth tag)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The decrypted data
    /// * `Err(FlagKitError)` - If decryption fails
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < NONCE_SIZE {
            return Err(FlagKitError::new(
                ErrorCode::CacheDecryptionError,
                "Encrypted data too short",
            ));
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the data
        self.cipher.decrypt(nonce, ciphertext).map_err(|e| {
            FlagKitError::new(
                ErrorCode::CacheDecryptionError,
                format!("Decryption failed: {}", e),
            )
        })
    }

    /// Encrypt a JSON value
    ///
    /// # Arguments
    ///
    /// * `value` - The JSON value to encrypt
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Base64-encoded encrypted data
    /// * `Err(FlagKitError)` - If encryption fails
    pub fn encrypt_json(&self, value: &Value) -> Result<String> {
        let json_str = serde_json::to_string(value).map_err(|e| {
            FlagKitError::new(
                ErrorCode::CacheEncryptionError,
                format!("Failed to serialize JSON: {}", e),
            )
        })?;

        let encrypted = self.encrypt(json_str.as_bytes())?;
        Ok(BASE64.encode(encrypted))
    }

    /// Decrypt to a JSON value
    ///
    /// # Arguments
    ///
    /// * `encrypted_base64` - Base64-encoded encrypted data
    ///
    /// # Returns
    ///
    /// * `Ok(Value)` - The decrypted JSON value
    /// * `Err(FlagKitError)` - If decryption fails
    pub fn decrypt_json(&self, encrypted_base64: &str) -> Result<Value> {
        let encrypted = BASE64.decode(encrypted_base64).map_err(|e| {
            FlagKitError::new(
                ErrorCode::CacheDecryptionError,
                format!("Failed to decode base64: {}", e),
            )
        })?;

        let decrypted = self.decrypt(&encrypted)?;

        serde_json::from_slice(&decrypted).map_err(|e| {
            FlagKitError::new(
                ErrorCode::CacheDecryptionError,
                format!("Failed to parse JSON: {}", e),
            )
        })
    }
}

/// Generate random bytes for nonce
fn getrandom(dest: &mut [u8]) -> Result<()> {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(dest);
    Ok(())
}

// =============================================================================
// Bootstrap Value Verification
// =============================================================================

use crate::core::{BootstrapConfig, BootstrapVerificationConfig};
use std::collections::HashMap;

/// Canonicalize a JSON object for signing.
///
/// Creates a deterministic string representation of the object by:
/// 1. Sorting keys alphabetically
/// 2. Converting to compact JSON format
///
/// # Arguments
///
/// * `obj` - The HashMap to canonicalize
///
/// # Returns
///
/// * `Ok(String)` - The canonical JSON string
/// * `Err(String)` - If serialization fails
///
/// # Examples
///
/// ```
/// use flagkit::security::canonicalize_object;
/// use std::collections::HashMap;
///
/// let mut obj = HashMap::new();
/// obj.insert("b".to_string(), serde_json::json!(2));
/// obj.insert("a".to_string(), serde_json::json!(1));
///
/// let canonical = canonicalize_object(&obj).unwrap();
/// assert_eq!(canonical, r#"{"a":1,"b":2}"#);
/// ```
pub fn canonicalize_object(obj: &HashMap<String, serde_json::Value>) -> std::result::Result<String, String> {
    // Create a sorted BTreeMap for deterministic key ordering
    let sorted: std::collections::BTreeMap<_, _> = obj.iter().collect();

    // Serialize with compact formatting
    serde_json::to_string(&sorted)
        .map_err(|e| format!("Failed to canonicalize object: {}", e))
}

/// Verify the HMAC-SHA256 signature of bootstrap values.
///
/// This function verifies that:
/// 1. The signature is valid (matches the expected HMAC-SHA256)
/// 2. The timestamp is not too old (if max_age is configured)
///
/// # Arguments
///
/// * `bootstrap` - The bootstrap configuration with flags, signature, and timestamp
/// * `api_key` - The API key used for HMAC signing
/// * `config` - The verification configuration
///
/// # Returns
///
/// * `Ok(())` - Verification passed
/// * `Err(String)` - Verification failed with error message
///
/// # Examples
///
/// ```no_run
/// use flagkit::security::verify_bootstrap_signature;
/// use flagkit::{BootstrapConfig, BootstrapVerificationConfig};
/// use std::collections::HashMap;
///
/// let flags = HashMap::new();
/// let bootstrap = BootstrapConfig::with_signature(
///     flags,
///     "valid_signature".to_string(),
///     chrono::Utc::now().timestamp_millis(),
/// );
/// let config = BootstrapVerificationConfig::default();
///
/// match verify_bootstrap_signature(&bootstrap, "sdk_api_key", &config) {
///     Ok(()) => println!("Bootstrap verified!"),
///     Err(msg) => println!("Verification failed: {}", msg),
/// }
/// ```
pub fn verify_bootstrap_signature(
    bootstrap: &BootstrapConfig,
    api_key: &str,
    config: &BootstrapVerificationConfig,
) -> std::result::Result<(), String> {
    // If verification is disabled, always pass
    if !config.enabled {
        return Ok(());
    }

    // Get the signature - if no signature present, skip verification
    let signature = match &bootstrap.signature {
        Some(sig) => sig,
        None => return Ok(()), // No signature means legacy format, skip verification
    };

    // Check timestamp expiration if timestamp is provided
    if let Some(timestamp) = bootstrap.timestamp {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Failed to get current time: {}", e))?
            .as_millis() as i64;

        let age = now - timestamp;
        if age < 0 {
            return Err("Bootstrap timestamp is in the future".to_string());
        }

        if age > config.max_age as i64 {
            return Err(format!(
                "Bootstrap values have expired (age: {}ms, max: {}ms)",
                age, config.max_age
            ));
        }
    }

    // Canonicalize the flags for signing
    let canonical = canonicalize_object(&bootstrap.flags)?;

    // Create the signing payload: timestamp.canonical_flags (if timestamp present)
    // or just canonical_flags (if no timestamp)
    let signing_payload = match bootstrap.timestamp {
        Some(ts) => format!("{}.{}", ts, canonical),
        None => canonical,
    };

    // Compute expected HMAC-SHA256
    let mut mac = <HmacSha256 as Mac>::new_from_slice(api_key.as_bytes())
        .map_err(|e| format!("Failed to create HMAC: {}", e))?;

    mac.update(signing_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Constant-time comparison to prevent timing attacks
    if !constant_time_compare(&expected, signature) {
        return Err("Invalid bootstrap signature".to_string());
    }

    Ok(())
}

/// Generate an HMAC-SHA256 signature for bootstrap values.
///
/// This function creates a signature that can be verified with `verify_bootstrap_signature`.
///
/// # Arguments
///
/// * `flags` - The bootstrap flag values
/// * `api_key` - The API key used for HMAC signing
/// * `timestamp` - The timestamp (milliseconds since epoch)
///
/// # Returns
///
/// The hex-encoded HMAC-SHA256 signature
///
/// # Examples
///
/// ```
/// use flagkit::security::sign_bootstrap;
/// use std::collections::HashMap;
///
/// let mut flags = HashMap::new();
/// flags.insert("feature".to_string(), serde_json::json!(true));
///
/// let timestamp = chrono::Utc::now().timestamp_millis();
/// let signature = sign_bootstrap(&flags, "sdk_api_key", timestamp).unwrap();
/// ```
pub fn sign_bootstrap(
    flags: &HashMap<String, serde_json::Value>,
    api_key: &str,
    timestamp: i64,
) -> std::result::Result<String, String> {
    // Canonicalize the flags
    let canonical = canonicalize_object(flags)?;

    // Create the signing payload: timestamp.canonical_flags
    let signing_payload = format!("{}.{}", timestamp, canonical);

    // Compute HMAC-SHA256
    let mut mac = <HmacSha256 as Mac>::new_from_slice(api_key.as_bytes())
        .map_err(|e| format!("Failed to create HMAC: {}", e))?;

    mac.update(signing_payload.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let mut result = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Result of bootstrap verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapVerificationResult {
    /// Verification passed successfully.
    Success,
    /// Verification was skipped (disabled or no signature).
    Skipped,
    /// Verification failed with an error message.
    Failed(String),
}

impl BootstrapVerificationResult {
    /// Returns true if verification passed or was skipped.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Success | Self::Skipped)
    }

    /// Returns true if verification failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    /// Returns the error message if verification failed.
    pub fn error_message(&self) -> Option<&str> {
        match self {
            Self::Failed(msg) => Some(msg),
            _ => None,
        }
    }
}

/// Verify bootstrap and handle failures according to configuration.
///
/// This function verifies bootstrap values and handles failures according to
/// the `on_failure` setting in the configuration:
/// - "error": Returns an error result
/// - "warn": Logs a warning and returns success
/// - "ignore": Silently returns success
///
/// # Arguments
///
/// * `bootstrap` - The bootstrap configuration
/// * `api_key` - The API key used for verification
/// * `config` - The verification configuration
///
/// # Returns
///
/// A `BootstrapVerificationResult` indicating the outcome
pub fn verify_bootstrap_with_policy(
    bootstrap: &BootstrapConfig,
    api_key: &str,
    config: &BootstrapVerificationConfig,
) -> BootstrapVerificationResult {
    match verify_bootstrap_signature(bootstrap, api_key, config) {
        Ok(()) => {
            if bootstrap.signature.is_some() {
                BootstrapVerificationResult::Success
            } else {
                BootstrapVerificationResult::Skipped
            }
        }
        Err(msg) => {
            match config.on_failure.as_str() {
                "ignore" => BootstrapVerificationResult::Skipped,
                "error" => BootstrapVerificationResult::Failed(msg),
                _ => {
                    // "warn" or any other value - log warning (using tracing)
                    tracing::warn!("[FlagKit Security] Bootstrap verification failed: {}", msg);
                    BootstrapVerificationResult::Skipped
                }
            }
        }
    }
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
        assert!(!config.strict_pii_mode);
        assert!(config.private_attributes.is_empty());
        assert!(config.secondary_api_key.is_none());
    }

    #[test]
    fn test_security_config_builder() {
        let config = SecurityConfig::builder()
            .warn_on_potential_pii(false)
            .warn_on_server_key_in_browser(false)
            .add_pii_pattern("custom_field")
            .strict_pii_mode(true)
            .add_private_attribute("email")
            .secondary_api_key("sdk_secondary_key")
            .enable_request_signing(true)
            .enable_cache_encryption(true)
            .build();

        assert!(!config.warn_on_potential_pii);
        assert!(!config.warn_on_server_key_in_browser);
        assert!(config.additional_pii_patterns.contains(&"custom_field".to_string()));
        assert!(config.strict_pii_mode);
        assert!(config.private_attributes.contains(&"email".to_string()));
        assert_eq!(
            config.secondary_api_key,
            Some("sdk_secondary_key".to_string())
        );
        assert!(config.enable_request_signing);
        assert!(config.enable_cache_encryption);
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
    fn test_private_attributes_excludes_pii() {
        let config = SecurityConfig::builder()
            .add_private_attribute("email")
            .add_private_attribute("ssn")
            .build();

        let data = serde_json::json!({
            "email": "test@example.com",
            "ssn": "123-45-6789",
            "phone": "555-1234"
        });

        let pii = detect_potential_pii_with_config(&data, "", Some(&config));
        assert!(!pii.contains(&"email".to_string()));
        assert!(!pii.contains(&"ssn".to_string()));
        assert!(pii.contains(&"phone".to_string()));
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

    // =============================================================================
    // Strict PII Mode Tests
    // =============================================================================

    #[test]
    fn test_check_pii_strict_disabled() {
        let config = SecurityConfig::builder().strict_pii_mode(false).build();

        let data = serde_json::json!({ "email": "test@example.com" });
        let result = check_pii_strict(Some(&data), DataType::Context, &config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_check_pii_strict_enabled_with_pii() {
        let config = SecurityConfig::builder().strict_pii_mode(true).build();

        let data = serde_json::json!({ "email": "test@example.com" });
        let result = check_pii_strict(Some(&data), DataType::Context, &config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::SecurityPiiDetected);
        assert!(err.message.contains("email"));
    }

    #[test]
    fn test_check_pii_strict_with_private_attributes() {
        let config = SecurityConfig::builder()
            .strict_pii_mode(true)
            .add_private_attribute("email")
            .build();

        let data = serde_json::json!({ "email": "test@example.com" });
        let result = check_pii_strict(Some(&data), DataType::Context, &config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_check_pii_strict_no_data() {
        let config = SecurityConfig::builder().strict_pii_mode(true).build();

        let result = check_pii_strict(None, DataType::Context, &config);
        assert!(result.is_ok());
    }

    // =============================================================================
    // Request Signing Tests
    // =============================================================================

    #[test]
    fn test_sign_request() {
        let body = r#"{"flag_key": "my-flag"}"#;
        let result = sign_request(body, "sdk_test_key");

        assert!(result.is_ok());
        let signature = result.unwrap();

        assert!(!signature.signature.is_empty());
        assert!(signature.timestamp > 0);
        assert_eq!(signature.key_id.len(), 8);
    }

    #[test]
    fn test_verify_signature() {
        let body = r#"{"flag_key": "my-flag"}"#;
        let api_key = "sdk_test_key";

        let signature = sign_request(body, api_key).unwrap();

        let is_valid =
            verify_signature(body, &signature.signature, signature.timestamp, api_key).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_verify_signature_wrong_body() {
        let body = r#"{"flag_key": "my-flag"}"#;
        let api_key = "sdk_test_key";

        let signature = sign_request(body, api_key).unwrap();

        let wrong_body = r#"{"flag_key": "other-flag"}"#;
        let is_valid =
            verify_signature(wrong_body, &signature.signature, signature.timestamp, api_key)
                .unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_verify_signature_wrong_key() {
        let body = r#"{"flag_key": "my-flag"}"#;
        let api_key = "sdk_test_key";

        let signature = sign_request(body, api_key).unwrap();

        let wrong_key = "sdk_wrong_key";
        let is_valid =
            verify_signature(body, &signature.signature, signature.timestamp, wrong_key).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_signature_headers() {
        let body = r#"{"test": true}"#;
        let signature = sign_request(body, "sdk_key").unwrap();

        assert_eq!(signature.x_signature(), signature.signature);
        assert_eq!(signature.x_timestamp(), signature.timestamp.to_string());
        assert_eq!(signature.x_key_id(), signature.key_id);
    }

    // =============================================================================
    // Key Rotation Tests
    // =============================================================================

    #[test]
    fn test_api_key_manager_no_secondary() {
        let manager = ApiKeyManager::new("sdk_primary", None);

        assert_eq!(manager.current_key(), "sdk_primary");
        assert!(!manager.is_using_secondary());
        assert!(!manager.has_secondary_key());

        let rotated = manager.handle_401_error().unwrap();
        assert!(!rotated);
    }

    #[test]
    fn test_api_key_manager_with_secondary() {
        let manager = ApiKeyManager::new("sdk_primary", Some("sdk_secondary".to_string()));

        assert_eq!(manager.current_key(), "sdk_primary");
        assert!(!manager.is_using_secondary());
        assert!(manager.has_secondary_key());

        let rotated = manager.handle_401_error().unwrap();
        assert!(rotated);
        assert!(manager.is_using_secondary());
        assert_eq!(manager.current_key(), "sdk_secondary");
    }

    #[test]
    fn test_api_key_manager_double_rotation_fails() {
        let manager = ApiKeyManager::new("sdk_primary", Some("sdk_secondary".to_string()));

        // First rotation succeeds
        let rotated = manager.handle_401_error().unwrap();
        assert!(rotated);

        // Second rotation fails
        let result = manager.handle_401_error();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::SecurityKeyRotationFailed);
    }

    #[test]
    fn test_api_key_manager_reset() {
        let manager = ApiKeyManager::new("sdk_primary", Some("sdk_secondary".to_string()));

        manager.handle_401_error().unwrap();
        assert!(manager.is_using_secondary());

        manager.reset_to_primary();
        assert!(!manager.is_using_secondary());
        assert_eq!(manager.current_key(), "sdk_primary");
    }

    // =============================================================================
    // Cache Encryption Tests
    // =============================================================================

    #[test]
    fn test_encrypted_cache_roundtrip() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();

        let plaintext = b"Hello, World!";
        let encrypted = cache.encrypt(plaintext).unwrap();

        assert_ne!(encrypted.as_slice(), plaintext);
        assert!(encrypted.len() > NONCE_SIZE);

        let decrypted = cache.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_cache_json_roundtrip() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();

        let value = serde_json::json!({
            "flags": {
                "feature-a": true,
                "feature-b": "enabled"
            }
        });

        let encrypted = cache.encrypt_json(&value).unwrap();
        let decrypted = cache.decrypt_json(&encrypted).unwrap();

        assert_eq!(decrypted, value);
    }

    #[test]
    fn test_encrypted_cache_different_keys() {
        let cache1 = EncryptedCache::new("sdk_key_1").unwrap();
        let cache2 = EncryptedCache::new("sdk_key_2").unwrap();

        let plaintext = b"Secret data";
        let encrypted = cache1.encrypt(plaintext).unwrap();

        // Should fail to decrypt with wrong key
        let result = cache2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_cache_tampered_data() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();

        let plaintext = b"Secret data";
        let mut encrypted = cache.encrypt(plaintext).unwrap();

        // Tamper with the ciphertext
        if let Some(last) = encrypted.last_mut() {
            *last ^= 0xFF;
        }

        let result = cache.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_cache_too_short() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();

        let result = cache.decrypt(&[0u8; 5]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::CacheDecryptionError);
    }

    #[test]
    fn test_encrypted_cache_unique_nonces() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();
        let plaintext = b"Same data";

        // Encrypt the same data multiple times
        let encrypted1 = cache.encrypt(plaintext).unwrap();
        let encrypted2 = cache.encrypt(plaintext).unwrap();
        let encrypted3 = cache.encrypt(plaintext).unwrap();

        // Each encryption should produce different ciphertext due to random nonce
        assert_ne!(encrypted1, encrypted2);
        assert_ne!(encrypted2, encrypted3);
        assert_ne!(encrypted1, encrypted3);

        // But all should decrypt to the same plaintext
        assert_eq!(cache.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(cache.decrypt(&encrypted2).unwrap(), plaintext);
        assert_eq!(cache.decrypt(&encrypted3).unwrap(), plaintext);
    }

    // =============================================================================
    // Bootstrap Verification Tests
    // =============================================================================

    #[test]
    fn test_canonicalize_object_empty() {
        let obj: HashMap<String, serde_json::Value> = HashMap::new();
        let canonical = canonicalize_object(&obj).unwrap();
        assert_eq!(canonical, "{}");
    }

    #[test]
    fn test_canonicalize_object_sorted_keys() {
        let mut obj = HashMap::new();
        obj.insert("z".to_string(), serde_json::json!(3));
        obj.insert("a".to_string(), serde_json::json!(1));
        obj.insert("m".to_string(), serde_json::json!(2));

        let canonical = canonicalize_object(&obj).unwrap();
        assert_eq!(canonical, r#"{"a":1,"m":2,"z":3}"#);
    }

    #[test]
    fn test_canonicalize_object_nested() {
        let mut obj = HashMap::new();
        obj.insert("feature".to_string(), serde_json::json!(true));
        obj.insert("config".to_string(), serde_json::json!({"nested": "value"}));

        let canonical = canonicalize_object(&obj).unwrap();
        // Keys should be sorted alphabetically
        assert!(canonical.starts_with(r#"{"config":"#));
    }

    #[test]
    fn test_sign_bootstrap() {
        let mut flags = HashMap::new();
        flags.insert("feature-a".to_string(), serde_json::json!(true));
        flags.insert("feature-b".to_string(), serde_json::json!("enabled"));

        let timestamp = 1700000000000i64;
        let signature = sign_bootstrap(&flags, "sdk_test_key", timestamp).unwrap();

        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 64); // SHA256 hex is 64 characters
    }

    #[test]
    fn test_verify_bootstrap_valid_signature() {
        let mut flags = HashMap::new();
        flags.insert("feature-a".to_string(), serde_json::json!(true));
        flags.insert("feature-b".to_string(), serde_json::json!(false));

        let api_key = "sdk_test_key";
        let timestamp = chrono::Utc::now().timestamp_millis();
        let signature = sign_bootstrap(&flags, api_key, timestamp).unwrap();

        let bootstrap = BootstrapConfig::with_signature(flags, signature, timestamp);
        let config = BootstrapVerificationConfig::default();

        let result = verify_bootstrap_signature(&bootstrap, api_key, &config);
        assert!(result.is_ok(), "Expected valid signature to pass: {:?}", result);
    }

    #[test]
    fn test_verify_bootstrap_invalid_signature() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let timestamp = chrono::Utc::now().timestamp_millis();
        let bootstrap = BootstrapConfig::with_signature(
            flags,
            "invalid_signature_that_does_not_match".to_string(),
            timestamp,
        );
        let config = BootstrapVerificationConfig::default();

        let result = verify_bootstrap_signature(&bootstrap, "sdk_test_key", &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid bootstrap signature"));
    }

    #[test]
    fn test_verify_bootstrap_expired_timestamp() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let api_key = "sdk_test_key";
        // Timestamp from 2 days ago
        let timestamp = chrono::Utc::now().timestamp_millis() - (2 * 24 * 60 * 60 * 1000);
        let signature = sign_bootstrap(&flags, api_key, timestamp).unwrap();

        let bootstrap = BootstrapConfig::with_signature(flags, signature, timestamp);
        let config = BootstrapVerificationConfig::default(); // default max_age is 24 hours

        let result = verify_bootstrap_signature(&bootstrap, api_key, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn test_verify_bootstrap_future_timestamp() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let api_key = "sdk_test_key";
        // Timestamp 1 hour in the future
        let timestamp = chrono::Utc::now().timestamp_millis() + (60 * 60 * 1000);
        let signature = sign_bootstrap(&flags, api_key, timestamp).unwrap();

        let bootstrap = BootstrapConfig::with_signature(flags, signature, timestamp);
        let config = BootstrapVerificationConfig::default();

        let result = verify_bootstrap_signature(&bootstrap, api_key, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("future"));
    }

    #[test]
    fn test_verify_bootstrap_legacy_format() {
        // Legacy format: no signature, no timestamp
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let bootstrap = BootstrapConfig::new(flags);
        let config = BootstrapVerificationConfig::default();

        // Should pass because there's no signature to verify
        let result = verify_bootstrap_signature(&bootstrap, "sdk_test_key", &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_bootstrap_verification_disabled() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let bootstrap = BootstrapConfig::with_signature(
            flags,
            "completely_invalid_signature".to_string(),
            chrono::Utc::now().timestamp_millis(),
        );
        let config = BootstrapVerificationConfig {
            enabled: false,
            max_age: 86400000,
            on_failure: "error".to_string(),
        };

        // Should pass because verification is disabled
        let result = verify_bootstrap_signature(&bootstrap, "sdk_test_key", &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_bootstrap_wrong_api_key() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let timestamp = chrono::Utc::now().timestamp_millis();
        let signature = sign_bootstrap(&flags, "sdk_correct_key", timestamp).unwrap();

        let bootstrap = BootstrapConfig::with_signature(flags, signature, timestamp);
        let config = BootstrapVerificationConfig::default();

        // Verify with wrong key should fail
        let result = verify_bootstrap_signature(&bootstrap, "sdk_wrong_key", &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid bootstrap signature"));
    }

    #[test]
    fn test_verify_bootstrap_with_policy_error() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let bootstrap = BootstrapConfig::with_signature(
            flags,
            "invalid_signature".to_string(),
            chrono::Utc::now().timestamp_millis(),
        );
        let config = BootstrapVerificationConfig::custom(true, 86400000, "error");

        let result = verify_bootstrap_with_policy(&bootstrap, "sdk_test_key", &config);
        assert!(result.is_failed());
        assert!(result.error_message().unwrap().contains("Invalid"));
    }

    #[test]
    fn test_verify_bootstrap_with_policy_warn() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let bootstrap = BootstrapConfig::with_signature(
            flags,
            "invalid_signature".to_string(),
            chrono::Utc::now().timestamp_millis(),
        );
        let config = BootstrapVerificationConfig::custom(true, 86400000, "warn");

        let result = verify_bootstrap_with_policy(&bootstrap, "sdk_test_key", &config);
        // With "warn" policy, failure is logged but returns Skipped
        assert_eq!(result, BootstrapVerificationResult::Skipped);
    }

    #[test]
    fn test_verify_bootstrap_with_policy_ignore() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let bootstrap = BootstrapConfig::with_signature(
            flags,
            "invalid_signature".to_string(),
            chrono::Utc::now().timestamp_millis(),
        );
        let config = BootstrapVerificationConfig::custom(true, 86400000, "ignore");

        let result = verify_bootstrap_with_policy(&bootstrap, "sdk_test_key", &config);
        assert_eq!(result, BootstrapVerificationResult::Skipped);
    }

    #[test]
    fn test_verify_bootstrap_with_policy_success() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let api_key = "sdk_test_key";
        let timestamp = chrono::Utc::now().timestamp_millis();
        let signature = sign_bootstrap(&flags, api_key, timestamp).unwrap();

        let bootstrap = BootstrapConfig::with_signature(flags, signature, timestamp);
        let config = BootstrapVerificationConfig::default();

        let result = verify_bootstrap_with_policy(&bootstrap, api_key, &config);
        assert_eq!(result, BootstrapVerificationResult::Success);
    }

    #[test]
    fn test_bootstrap_verification_result_methods() {
        assert!(BootstrapVerificationResult::Success.is_ok());
        assert!(BootstrapVerificationResult::Skipped.is_ok());
        assert!(!BootstrapVerificationResult::Failed("error".to_string()).is_ok());

        assert!(!BootstrapVerificationResult::Success.is_failed());
        assert!(!BootstrapVerificationResult::Skipped.is_failed());
        assert!(BootstrapVerificationResult::Failed("error".to_string()).is_failed());

        assert!(BootstrapVerificationResult::Success.error_message().is_none());
        assert!(BootstrapVerificationResult::Skipped.error_message().is_none());
        assert_eq!(
            BootstrapVerificationResult::Failed("test error".to_string()).error_message(),
            Some("test error")
        );
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hell"));
        assert!(!constant_time_compare("abc", "abcd"));
    }

    #[test]
    fn test_bootstrap_verification_config_builders() {
        let strict = BootstrapVerificationConfig::strict();
        assert!(strict.enabled);
        assert_eq!(strict.on_failure, "error");

        let permissive = BootstrapVerificationConfig::permissive();
        assert!(!permissive.enabled);
        assert_eq!(permissive.on_failure, "ignore");

        let custom = BootstrapVerificationConfig::custom(true, 3600000, "warn");
        assert!(custom.enabled);
        assert_eq!(custom.max_age, 3600000);
        assert_eq!(custom.on_failure, "warn");
    }
}
