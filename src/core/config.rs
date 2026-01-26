use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

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
            local_port: None,
            persist_events: false,
            event_storage_path: None,
            max_persisted_events: DEFAULT_MAX_PERSISTED_EVENTS,
            persistence_flush_interval: Duration::from_millis(DEFAULT_FLUSH_INTERVAL_MS),
            evaluation_jitter: EvaluationJitterConfig::default(),
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
    local_port: Option<u16>,
    persist_events: bool,
    event_storage_path: Option<PathBuf>,
    max_persisted_events: usize,
    persistence_flush_interval: Duration,
    evaluation_jitter: EvaluationJitterConfig,
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
            local_port: None,
            persist_events: false,
            event_storage_path: None,
            max_persisted_events: DEFAULT_MAX_PERSISTED_EVENTS,
            persistence_flush_interval: Duration::from_millis(DEFAULT_FLUSH_INTERVAL_MS),
            evaluation_jitter: EvaluationJitterConfig::default(),
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
            local_port: self.local_port,
            persist_events: self.persist_events,
            event_storage_path: self.event_storage_path,
            max_persisted_events: self.max_persisted_events,
            persistence_flush_interval: self.persistence_flush_interval,
            evaluation_jitter: self.evaluation_jitter,
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
}
