use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::sanitizer::ErrorSanitizationConfig;
use crate::error::{ErrorCode, FlagKitError, Result};
use crate::event_persistence::{DEFAULT_FLUSH_INTERVAL_MS, DEFAULT_MAX_PERSISTED_EVENTS};

pub const DEFAULT_POLLING_INTERVAL: Duration = Duration::from_secs(30);
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);
pub const DEFAULT_MAX_CACHE_SIZE: usize = 1000;
pub const DEFAULT_EVENT_BATCH_SIZE: usize = 10;
pub const DEFAULT_EVENT_FLUSH_INTERVAL: Duration = Duration::from_secs(30);
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 3;
pub const DEFAULT_CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
pub const DEFAULT_CIRCUIT_BREAKER_RESET_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for evaluation jitter to protect against cache timing attacks.
///
/// When enabled, a random delay is added before each flag evaluation to prevent
/// attackers from inferring information about flag values based on response times.
#[derive(Debug, Clone)]
pub struct EvaluationJitterConfig {
    /// Whether evaluation jitter is enabled. Defaults to false.
    pub enabled: bool,
    /// Minimum jitter delay in milliseconds. Defaults to 5ms.
    pub min_ms: u64,
    /// Maximum jitter delay in milliseconds. Defaults to 15ms.
    pub max_ms: u64,
}

impl Default for EvaluationJitterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_ms: 5,
            max_ms: 15,
        }
    }
}

impl EvaluationJitterConfig {
    /// Create a new jitter config with specified values.
    pub fn new(enabled: bool, min_ms: u64, max_ms: u64) -> Self {
        Self {
            enabled,
            min_ms,
            max_ms,
        }
    }

    /// Create an enabled jitter config with default timing values.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }
}

/// Bootstrap configuration with optional signature verification.
///
/// This struct supports loading bootstrap flag values with HMAC-SHA256 signature
/// verification to ensure the values have not been tampered with.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// The bootstrap flag values.
    pub flags: HashMap<String, serde_json::Value>,
    /// Optional HMAC-SHA256 signature of the flags.
    pub signature: Option<String>,
    /// Optional timestamp (milliseconds since epoch) when the bootstrap was created.
    pub timestamp: Option<i64>,
}

impl BootstrapConfig {
    /// Create a new bootstrap config with flags only (legacy format).
    pub fn new(flags: HashMap<String, serde_json::Value>) -> Self {
        Self {
            flags,
            signature: None,
            timestamp: None,
        }
    }

    /// Create a bootstrap config with signature and timestamp for verification.
    pub fn with_signature(
        flags: HashMap<String, serde_json::Value>,
        signature: String,
        timestamp: i64,
    ) -> Self {
        Self {
            flags,
            signature: Some(signature),
            timestamp: Some(timestamp),
        }
    }
}

impl From<HashMap<String, serde_json::Value>> for BootstrapConfig {
    fn from(flags: HashMap<String, serde_json::Value>) -> Self {
        Self::new(flags)
    }
}

/// Configuration for bootstrap value verification.
///
/// When enabled, the SDK will verify the HMAC-SHA256 signature of bootstrap
/// values to ensure they have not been tampered with.
#[derive(Debug, Clone)]
pub struct BootstrapVerificationConfig {
    /// Whether bootstrap signature verification is enabled. Defaults to true.
    pub enabled: bool,
    /// Maximum age of bootstrap values in milliseconds. Defaults to 24 hours (86400000ms).
    pub max_age: u64,
    /// Action to take on verification failure: "warn", "error", or "ignore". Defaults to "warn".
    pub on_failure: String,
}

impl Default for BootstrapVerificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_age: 86400000, // 24 hours in milliseconds
            on_failure: "warn".to_string(),
        }
    }
}

impl BootstrapVerificationConfig {
    /// Create a new verification config with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a verification config with custom values.
    pub fn custom(enabled: bool, max_age: u64, on_failure: impl Into<String>) -> Self {
        Self {
            enabled,
            max_age,
            on_failure: on_failure.into(),
        }
    }

    /// Create a config that errors on verification failure.
    pub fn strict() -> Self {
        Self {
            enabled: true,
            max_age: 86400000,
            on_failure: "error".to_string(),
        }
    }

    /// Create a config that ignores verification failures.
    pub fn permissive() -> Self {
        Self {
            enabled: false,
            max_age: 86400000,
            on_failure: "ignore".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlagKitOptions {
    pub api_key: String,
    pub polling_interval: Duration,
    pub cache_ttl: Duration,
    pub max_cache_size: usize,
    pub cache_enabled: bool,
    pub event_batch_size: usize,
    pub event_flush_interval: Duration,
    pub events_enabled: bool,
    pub timeout: Duration,
    pub retry_attempts: u32,
    pub circuit_breaker_threshold: u32,
    pub circuit_breaker_reset_timeout: Duration,
    pub bootstrap: Option<HashMap<String, serde_json::Value>>,
    /// Bootstrap configuration with optional signature for verification.
    pub bootstrap_config: Option<BootstrapConfig>,
    pub local_port: Option<u16>,
    /// Enable crash-resilient event persistence.
    pub persist_events: bool,
    /// Directory path for event storage.
    pub event_storage_path: Option<PathBuf>,
    /// Maximum number of events to persist.
    pub max_persisted_events: usize,
    /// Interval between persistence flushes to disk.
    pub persistence_flush_interval: Duration,
    /// Configuration for evaluation jitter (timing attack protection).
    pub evaluation_jitter: EvaluationJitterConfig,
    /// Configuration for bootstrap value verification.
    pub bootstrap_verification: BootstrapVerificationConfig,
    /// Configuration for error message sanitization.
    pub error_sanitization: ErrorSanitizationConfig,
}

impl FlagKitOptions {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            polling_interval: DEFAULT_POLLING_INTERVAL,
            cache_ttl: DEFAULT_CACHE_TTL,
            max_cache_size: DEFAULT_MAX_CACHE_SIZE,
            cache_enabled: true,
            event_batch_size: DEFAULT_EVENT_BATCH_SIZE,
            event_flush_interval: DEFAULT_EVENT_FLUSH_INTERVAL,
            events_enabled: true,
            timeout: DEFAULT_TIMEOUT,
            retry_attempts: DEFAULT_RETRY_ATTEMPTS,
            circuit_breaker_threshold: DEFAULT_CIRCUIT_BREAKER_THRESHOLD,
            circuit_breaker_reset_timeout: DEFAULT_CIRCUIT_BREAKER_RESET_TIMEOUT,
            bootstrap: None,
            bootstrap_config: None,
            local_port: None,
            persist_events: false,
            event_storage_path: None,
            max_persisted_events: DEFAULT_MAX_PERSISTED_EVENTS,
            persistence_flush_interval: Duration::from_millis(DEFAULT_FLUSH_INTERVAL_MS),
            evaluation_jitter: EvaluationJitterConfig::default(),
            bootstrap_verification: BootstrapVerificationConfig::default(),
            error_sanitization: ErrorSanitizationConfig::default(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.api_key.is_empty() {
            return Err(FlagKitError::config_error(
                ErrorCode::ConfigInvalidApiKey,
                "API key is required",
            ));
        }

        let valid_prefixes = ["sdk_", "srv_", "cli_"];
        if !valid_prefixes.iter().any(|p| self.api_key.starts_with(p)) {
            return Err(FlagKitError::config_error(
                ErrorCode::ConfigInvalidApiKey,
                "Invalid API key format",
            ));
        }

        if self.polling_interval.is_zero() {
            return Err(FlagKitError::config_error(
                ErrorCode::ConfigInvalidPollingInterval,
                "Polling interval must be positive",
            ));
        }

        if self.cache_ttl.is_zero() {
            return Err(FlagKitError::config_error(
                ErrorCode::ConfigInvalidCacheTtl,
                "Cache TTL must be positive",
            ));
        }

        Ok(())
    }

    pub fn builder(api_key: impl Into<String>) -> FlagKitOptionsBuilder {
        FlagKitOptionsBuilder::new(api_key)
    }
}

pub struct FlagKitOptionsBuilder {
    api_key: String,
    polling_interval: Duration,
    cache_ttl: Duration,
    max_cache_size: usize,
    cache_enabled: bool,
    event_batch_size: usize,
    event_flush_interval: Duration,
    events_enabled: bool,
    timeout: Duration,
    retry_attempts: u32,
    circuit_breaker_threshold: u32,
    circuit_breaker_reset_timeout: Duration,
    bootstrap: Option<HashMap<String, serde_json::Value>>,
    bootstrap_config: Option<BootstrapConfig>,
    local_port: Option<u16>,
    persist_events: bool,
    event_storage_path: Option<PathBuf>,
    max_persisted_events: usize,
    persistence_flush_interval: Duration,
    evaluation_jitter: EvaluationJitterConfig,
    bootstrap_verification: BootstrapVerificationConfig,
    error_sanitization: ErrorSanitizationConfig,
}

impl FlagKitOptionsBuilder {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            polling_interval: DEFAULT_POLLING_INTERVAL,
            cache_ttl: DEFAULT_CACHE_TTL,
            max_cache_size: DEFAULT_MAX_CACHE_SIZE,
            cache_enabled: true,
            event_batch_size: DEFAULT_EVENT_BATCH_SIZE,
            event_flush_interval: DEFAULT_EVENT_FLUSH_INTERVAL,
            events_enabled: true,
            timeout: DEFAULT_TIMEOUT,
            retry_attempts: DEFAULT_RETRY_ATTEMPTS,
            circuit_breaker_threshold: DEFAULT_CIRCUIT_BREAKER_THRESHOLD,
            circuit_breaker_reset_timeout: DEFAULT_CIRCUIT_BREAKER_RESET_TIMEOUT,
            bootstrap: None,
            bootstrap_config: None,
            local_port: None,
            persist_events: false,
            event_storage_path: None,
            max_persisted_events: DEFAULT_MAX_PERSISTED_EVENTS,
            persistence_flush_interval: Duration::from_millis(DEFAULT_FLUSH_INTERVAL_MS),
            evaluation_jitter: EvaluationJitterConfig::default(),
            bootstrap_verification: BootstrapVerificationConfig::default(),
            error_sanitization: ErrorSanitizationConfig::default(),
        }
    }

    pub fn polling_interval(mut self, interval: Duration) -> Self {
        self.polling_interval = interval;
        self
    }

    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    pub fn max_cache_size(mut self, size: usize) -> Self {
        self.max_cache_size = size;
        self
    }

    pub fn cache_enabled(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    pub fn event_batch_size(mut self, size: usize) -> Self {
        self.event_batch_size = size;
        self
    }

    pub fn event_flush_interval(mut self, interval: Duration) -> Self {
        self.event_flush_interval = interval;
        self
    }

    pub fn events_enabled(mut self, enabled: bool) -> Self {
        self.events_enabled = enabled;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn retry_attempts(mut self, attempts: u32) -> Self {
        self.retry_attempts = attempts;
        self
    }

    pub fn circuit_breaker_threshold(mut self, threshold: u32) -> Self {
        self.circuit_breaker_threshold = threshold;
        self
    }

    pub fn circuit_breaker_reset_timeout(mut self, timeout: Duration) -> Self {
        self.circuit_breaker_reset_timeout = timeout;
        self
    }

    pub fn bootstrap(mut self, data: HashMap<String, serde_json::Value>) -> Self {
        self.bootstrap = Some(data);
        self
    }

    /// Set the bootstrap configuration with optional signature verification.
    pub fn bootstrap_config(mut self, config: BootstrapConfig) -> Self {
        self.bootstrap_config = Some(config);
        self
    }

    /// Set bootstrap data with signature for verification.
    pub fn bootstrap_with_signature(
        mut self,
        flags: HashMap<String, serde_json::Value>,
        signature: String,
        timestamp: i64,
    ) -> Self {
        self.bootstrap_config = Some(BootstrapConfig::with_signature(flags, signature, timestamp));
        self
    }

    /// Set the bootstrap verification configuration.
    pub fn bootstrap_verification(mut self, config: BootstrapVerificationConfig) -> Self {
        self.bootstrap_verification = config;
        self
    }

    pub fn local_port(mut self, port: u16) -> Self {
        self.local_port = Some(port);
        self
    }

    /// Enable crash-resilient event persistence.
    pub fn persist_events(mut self, enabled: bool) -> Self {
        self.persist_events = enabled;
        self
    }

    /// Set the directory path for event storage.
    pub fn event_storage_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.event_storage_path = Some(path.into());
        self
    }

    /// Set the maximum number of events to persist.
    pub fn max_persisted_events(mut self, max: usize) -> Self {
        self.max_persisted_events = max;
        self
    }

    /// Set the interval between persistence flushes to disk.
    pub fn persistence_flush_interval(mut self, interval: Duration) -> Self {
        self.persistence_flush_interval = interval;
        self
    }

    /// Set the evaluation jitter configuration for timing attack protection.
    pub fn evaluation_jitter(mut self, config: EvaluationJitterConfig) -> Self {
        self.evaluation_jitter = config;
        self
    }

    /// Enable evaluation jitter with default timing values.
    pub fn enable_evaluation_jitter(mut self) -> Self {
        self.evaluation_jitter = EvaluationJitterConfig::enabled();
        self
    }

    /// Set the error sanitization configuration.
    pub fn error_sanitization(mut self, config: ErrorSanitizationConfig) -> Self {
        self.error_sanitization = config;
        self
    }

    /// Disable error message sanitization.
    pub fn disable_error_sanitization(mut self) -> Self {
        self.error_sanitization = ErrorSanitizationConfig::disabled();
        self
    }

    /// Enable error sanitization with original message preservation.
    pub fn error_sanitization_with_preservation(mut self) -> Self {
        self.error_sanitization = ErrorSanitizationConfig::with_preservation();
        self
    }

    pub fn build(self) -> FlagKitOptions {
        FlagKitOptions {
            api_key: self.api_key,
            polling_interval: self.polling_interval,
            cache_ttl: self.cache_ttl,
            max_cache_size: self.max_cache_size,
            cache_enabled: self.cache_enabled,
            event_batch_size: self.event_batch_size,
            event_flush_interval: self.event_flush_interval,
            events_enabled: self.events_enabled,
            timeout: self.timeout,
            retry_attempts: self.retry_attempts,
            circuit_breaker_threshold: self.circuit_breaker_threshold,
            circuit_breaker_reset_timeout: self.circuit_breaker_reset_timeout,
            bootstrap: self.bootstrap,
            bootstrap_config: self.bootstrap_config,
            local_port: self.local_port,
            persist_events: self.persist_events,
            event_storage_path: self.event_storage_path,
            max_persisted_events: self.max_persisted_events,
            persistence_flush_interval: self.persistence_flush_interval,
            evaluation_jitter: self.evaluation_jitter,
            bootstrap_verification: self.bootstrap_verification,
            error_sanitization: self.error_sanitization,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_port_defaults_to_none() {
        let options = FlagKitOptions::new("sdk_test_key");
        assert!(options.local_port.is_none());
    }

    #[test]
    fn test_local_port_builder_defaults_to_none() {
        let options = FlagKitOptions::builder("sdk_test_key").build();
        assert!(options.local_port.is_none());
    }

    #[test]
    fn test_local_port_can_be_set() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .build();
        assert_eq!(options.local_port, Some(8200));
    }

    // === Evaluation Jitter Config Tests ===

    #[test]
    fn test_evaluation_jitter_default() {
        let config = EvaluationJitterConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.min_ms, 5);
        assert_eq!(config.max_ms, 15);
    }

    #[test]
    fn test_evaluation_jitter_enabled() {
        let config = EvaluationJitterConfig::enabled();
        assert!(config.enabled);
        assert_eq!(config.min_ms, 5);
        assert_eq!(config.max_ms, 15);
    }

    #[test]
    fn test_evaluation_jitter_new() {
        let config = EvaluationJitterConfig::new(true, 10, 20);
        assert!(config.enabled);
        assert_eq!(config.min_ms, 10);
        assert_eq!(config.max_ms, 20);
    }

    #[test]
    fn test_options_evaluation_jitter_default() {
        let options = FlagKitOptions::new("sdk_test_key");
        assert!(!options.evaluation_jitter.enabled);
        assert_eq!(options.evaluation_jitter.min_ms, 5);
        assert_eq!(options.evaluation_jitter.max_ms, 15);
    }

    #[test]
    fn test_options_builder_evaluation_jitter_default() {
        let options = FlagKitOptions::builder("sdk_test_key").build();
        assert!(!options.evaluation_jitter.enabled);
    }

    #[test]
    fn test_options_builder_evaluation_jitter_custom() {
        let jitter_config = EvaluationJitterConfig::new(true, 20, 50);
        let options = FlagKitOptions::builder("sdk_test_key")
            .evaluation_jitter(jitter_config)
            .build();
        assert!(options.evaluation_jitter.enabled);
        assert_eq!(options.evaluation_jitter.min_ms, 20);
        assert_eq!(options.evaluation_jitter.max_ms, 50);
    }

    #[test]
    fn test_options_builder_enable_evaluation_jitter() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .enable_evaluation_jitter()
            .build();
        assert!(options.evaluation_jitter.enabled);
        assert_eq!(options.evaluation_jitter.min_ms, 5);
        assert_eq!(options.evaluation_jitter.max_ms, 15);
    }

    // === Bootstrap Config Tests ===

    #[test]
    fn test_bootstrap_config_new() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let config = BootstrapConfig::new(flags.clone());
        assert_eq!(config.flags.len(), 1);
        assert!(config.signature.is_none());
        assert!(config.timestamp.is_none());
    }

    #[test]
    fn test_bootstrap_config_with_signature() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let config = BootstrapConfig::with_signature(
            flags.clone(),
            "test_signature".to_string(),
            1700000000000,
        );
        assert_eq!(config.flags.len(), 1);
        assert_eq!(config.signature, Some("test_signature".to_string()));
        assert_eq!(config.timestamp, Some(1700000000000));
    }

    #[test]
    fn test_bootstrap_config_from_hashmap() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let config: BootstrapConfig = flags.into();
        assert_eq!(config.flags.len(), 1);
        assert!(config.signature.is_none());
    }

    // === Bootstrap Verification Config Tests ===

    #[test]
    fn test_bootstrap_verification_config_default() {
        let config = BootstrapVerificationConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_age, 86400000);
        assert_eq!(config.on_failure, "warn");
    }

    #[test]
    fn test_bootstrap_verification_config_strict() {
        let config = BootstrapVerificationConfig::strict();
        assert!(config.enabled);
        assert_eq!(config.on_failure, "error");
    }

    #[test]
    fn test_bootstrap_verification_config_permissive() {
        let config = BootstrapVerificationConfig::permissive();
        assert!(!config.enabled);
        assert_eq!(config.on_failure, "ignore");
    }

    #[test]
    fn test_bootstrap_verification_config_custom() {
        let config = BootstrapVerificationConfig::custom(true, 3600000, "error");
        assert!(config.enabled);
        assert_eq!(config.max_age, 3600000);
        assert_eq!(config.on_failure, "error");
    }

    #[test]
    fn test_options_bootstrap_verification_default() {
        let options = FlagKitOptions::new("sdk_test_key");
        assert!(options.bootstrap_verification.enabled);
        assert_eq!(options.bootstrap_verification.on_failure, "warn");
    }

    #[test]
    fn test_options_builder_bootstrap_config() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let bootstrap_config = BootstrapConfig::new(flags);

        let options = FlagKitOptions::builder("sdk_test_key")
            .bootstrap_config(bootstrap_config)
            .build();

        assert!(options.bootstrap_config.is_some());
        let config = options.bootstrap_config.unwrap();
        assert_eq!(config.flags.len(), 1);
    }

    #[test]
    fn test_options_builder_bootstrap_with_signature() {
        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let options = FlagKitOptions::builder("sdk_test_key")
            .bootstrap_with_signature(flags, "sig".to_string(), 12345)
            .build();

        assert!(options.bootstrap_config.is_some());
        let config = options.bootstrap_config.unwrap();
        assert_eq!(config.signature, Some("sig".to_string()));
        assert_eq!(config.timestamp, Some(12345));
    }

    #[test]
    fn test_options_builder_bootstrap_verification() {
        let verification = BootstrapVerificationConfig::strict();

        let options = FlagKitOptions::builder("sdk_test_key")
            .bootstrap_verification(verification)
            .build();

        assert!(options.bootstrap_verification.enabled);
        assert_eq!(options.bootstrap_verification.on_failure, "error");
    }

    // === Error Sanitization Config Tests ===

    #[test]
    fn test_options_error_sanitization_default() {
        let options = FlagKitOptions::new("sdk_test_key");
        assert!(options.error_sanitization.enabled);
        assert!(!options.error_sanitization.preserve_original);
    }

    #[test]
    fn test_options_builder_error_sanitization_default() {
        let options = FlagKitOptions::builder("sdk_test_key").build();
        assert!(options.error_sanitization.enabled);
        assert!(!options.error_sanitization.preserve_original);
    }

    #[test]
    fn test_options_builder_disable_error_sanitization() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .disable_error_sanitization()
            .build();
        assert!(!options.error_sanitization.enabled);
    }

    #[test]
    fn test_options_builder_error_sanitization_with_preservation() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .error_sanitization_with_preservation()
            .build();
        assert!(options.error_sanitization.enabled);
        assert!(options.error_sanitization.preserve_original);
    }

    #[test]
    fn test_options_builder_error_sanitization_custom() {
        let config = ErrorSanitizationConfig {
            enabled: true,
            preserve_original: true,
        };
        let options = FlagKitOptions::builder("sdk_test_key")
            .error_sanitization(config)
            .build();
        assert!(options.error_sanitization.enabled);
        assert!(options.error_sanitization.preserve_original);
    }
}
