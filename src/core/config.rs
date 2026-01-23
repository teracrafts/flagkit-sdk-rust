use std::collections::HashMap;
use std::time::Duration;

use crate::error::{ErrorCode, FlagKitError, Result};

pub const DEFAULT_POLLING_INTERVAL: Duration = Duration::from_secs(30);
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);
pub const DEFAULT_MAX_CACHE_SIZE: usize = 1000;
pub const DEFAULT_EVENT_BATCH_SIZE: usize = 10;
pub const DEFAULT_EVENT_FLUSH_INTERVAL: Duration = Duration::from_secs(30);
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 3;
pub const DEFAULT_CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
pub const DEFAULT_CIRCUIT_BREAKER_RESET_TIMEOUT: Duration = Duration::from_secs(30);

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
        }
    }
}
