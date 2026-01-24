//! Retry logic with exponential backoff and jitter.
//!
//! This module provides retry functionality for HTTP operations with configurable
//! exponential backoff and jitter to prevent thundering herd problems.

use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

use crate::error::{ErrorCode, FlagKitError, Result};

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts. Default: 3
    pub max_attempts: u32,

    /// Base delay in milliseconds. Default: 1000
    pub base_delay_ms: u64,

    /// Maximum delay in milliseconds. Default: 30000
    pub max_delay_ms: u64,

    /// Backoff multiplier. Default: 2.0
    pub backoff_multiplier: f64,

    /// Maximum jitter in milliseconds (random 0-jitter added). Default: 100
    pub jitter_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            jitter_ms: 100,
        }
    }
}

impl RetryConfig {
    /// Create a new retry configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for custom configuration.
    pub fn builder() -> RetryConfigBuilder {
        RetryConfigBuilder::default()
    }

    /// Calculate the backoff delay for a given attempt number.
    ///
    /// Uses exponential backoff: base_delay * (multiplier ^ (attempt - 1))
    /// Adds random jitter to prevent thundering herd.
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        // Exponential backoff
        let exponential = self.base_delay_ms as f64
            * self.backoff_multiplier.powi((attempt - 1) as i32);

        // Cap at max delay
        let capped = exponential.min(self.max_delay_ms as f64);

        // Add jitter (0 to jitter_ms)
        let jitter = rand::random::<f64>() * self.jitter_ms as f64;

        Duration::from_millis((capped + jitter) as u64)
    }
}

/// Builder for RetryConfig.
#[derive(Debug, Default)]
pub struct RetryConfigBuilder {
    max_attempts: Option<u32>,
    base_delay_ms: Option<u64>,
    max_delay_ms: Option<u64>,
    backoff_multiplier: Option<f64>,
    jitter_ms: Option<u64>,
}

impl RetryConfigBuilder {
    /// Set maximum retry attempts.
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = Some(attempts);
        self
    }

    /// Set base delay in milliseconds.
    pub fn base_delay_ms(mut self, delay: u64) -> Self {
        self.base_delay_ms = Some(delay);
        self
    }

    /// Set maximum delay in milliseconds.
    pub fn max_delay_ms(mut self, delay: u64) -> Self {
        self.max_delay_ms = Some(delay);
        self
    }

    /// Set backoff multiplier.
    pub fn backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = Some(multiplier);
        self
    }

    /// Set jitter in milliseconds.
    pub fn jitter_ms(mut self, jitter: u64) -> Self {
        self.jitter_ms = Some(jitter);
        self
    }

    /// Build the configuration.
    pub fn build(self) -> RetryConfig {
        RetryConfig {
            max_attempts: self.max_attempts.unwrap_or(3),
            base_delay_ms: self.base_delay_ms.unwrap_or(1000),
            max_delay_ms: self.max_delay_ms.unwrap_or(30000),
            backoff_multiplier: self.backoff_multiplier.unwrap_or(2.0),
            jitter_ms: self.jitter_ms.unwrap_or(100),
        }
    }
}

/// Determine if an error is retryable.
pub fn is_retryable(error: &FlagKitError) -> bool {
    matches!(
        error.code,
        ErrorCode::HttpTimeout
            | ErrorCode::HttpNetworkError
            | ErrorCode::HttpServerError
            | ErrorCode::NetworkError
            | ErrorCode::NetworkTimeout
            | ErrorCode::HttpRateLimited
    )
}

/// Execute an async operation with retry logic.
///
/// # Arguments
///
/// * `operation` - The async operation to execute
/// * `config` - Retry configuration
///
/// # Returns
///
/// The result of the operation, or the last error if all retries fail.
///
/// # Example
///
/// ```rust,ignore
/// use flagkit::http::retry::{with_retry, RetryConfig};
///
/// let config = RetryConfig::default();
/// let result = with_retry(
///     || async { do_http_request().await },
///     &config,
/// ).await;
/// ```
pub async fn with_retry<T, F, Fut>(operation: F, config: &RetryConfig) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    with_retry_predicate(operation, config, is_retryable).await
}

/// Execute an async operation with retry logic and custom retry predicate.
///
/// # Arguments
///
/// * `operation` - The async operation to execute
/// * `config` - Retry configuration
/// * `should_retry` - Function to determine if an error is retryable
///
/// # Returns
///
/// The result of the operation, or the last error if all retries fail.
pub async fn with_retry_predicate<T, F, Fut, P>(
    operation: F,
    config: &RetryConfig,
    should_retry: P,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T>>,
    P: Fn(&FlagKitError) -> bool,
{
    let mut last_error: Option<FlagKitError> = None;

    for attempt in 1..=config.max_attempts {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                // Check if we should retry
                if !should_retry(&e) {
                    return Err(e);
                }

                // Store the error
                last_error = Some(e);

                // Don't sleep after the last attempt
                if attempt < config.max_attempts {
                    let delay = config.calculate_delay(attempt);
                    tracing::debug!(
                        "Retry attempt {} of {}, waiting {:?}",
                        attempt,
                        config.max_attempts,
                        delay
                    );
                    sleep(delay).await;
                }
            }
        }
    }

    // Return the last error or a generic retry failed error
    Err(last_error.unwrap_or_else(|| {
        FlagKitError::network_error(
            ErrorCode::NetworkRetryLimit,
            "Maximum retry attempts exceeded",
        )
    }))
}

/// Result of a retry operation with metadata.
#[derive(Debug)]
pub struct RetryResult<T> {
    /// The result value if successful.
    pub value: Option<T>,
    /// The error if failed.
    pub error: Option<FlagKitError>,
    /// Number of attempts made.
    pub attempts: u32,
    /// Whether the operation succeeded.
    pub success: bool,
}

impl<T> RetryResult<T> {
    /// Create a successful result.
    pub fn ok(value: T, attempts: u32) -> Self {
        Self {
            value: Some(value),
            error: None,
            attempts,
            success: true,
        }
    }

    /// Create a failed result.
    pub fn err(error: FlagKitError, attempts: u32) -> Self {
        Self {
            value: None,
            error: Some(error),
            attempts,
            success: false,
        }
    }

    /// Convert to a standard Result.
    pub fn into_result(self) -> Result<T> {
        if self.success {
            Ok(self.value.expect("Success result must have a value"))
        } else {
            Err(self.error.expect("Failed result must have an error"))
        }
    }
}

/// Execute an async operation with retry logic and return detailed result.
///
/// Unlike `with_retry`, this function returns metadata about the retry process.
pub async fn with_retry_detailed<T, F, Fut>(
    operation: F,
    config: &RetryConfig,
) -> RetryResult<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut last_error: Option<FlagKitError> = None;

    for attempt in 1..=config.max_attempts {
        match operation().await {
            Ok(result) => return RetryResult::ok(result, attempt),
            Err(e) => {
                if !is_retryable(&e) {
                    return RetryResult::err(e, attempt);
                }

                last_error = Some(e);

                if attempt < config.max_attempts {
                    let delay = config.calculate_delay(attempt);
                    sleep(delay).await;
                }
            }
        }
    }

    RetryResult::err(
        last_error.unwrap_or_else(|| {
            FlagKitError::network_error(
                ErrorCode::NetworkRetryLimit,
                "Maximum retry attempts exceeded",
            )
        }),
        config.max_attempts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_default_config() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.base_delay_ms, 1000);
        assert_eq!(config.max_delay_ms, 30000);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert_eq!(config.jitter_ms, 100);
    }

    #[test]
    fn test_builder() {
        let config = RetryConfig::builder()
            .max_attempts(5)
            .base_delay_ms(500)
            .max_delay_ms(10000)
            .backoff_multiplier(1.5)
            .jitter_ms(50)
            .build();

        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.base_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 10000);
        assert_eq!(config.backoff_multiplier, 1.5);
        assert_eq!(config.jitter_ms, 50);
    }

    #[test]
    fn test_calculate_delay_exponential() {
        let config = RetryConfig::builder()
            .base_delay_ms(1000)
            .backoff_multiplier(2.0)
            .jitter_ms(0) // No jitter for predictable tests
            .build();

        // Attempt 1: 1000 * 2^0 = 1000
        let delay1 = config.calculate_delay(1);
        assert_eq!(delay1.as_millis(), 1000);

        // Attempt 2: 1000 * 2^1 = 2000
        let delay2 = config.calculate_delay(2);
        assert_eq!(delay2.as_millis(), 2000);

        // Attempt 3: 1000 * 2^2 = 4000
        let delay3 = config.calculate_delay(3);
        assert_eq!(delay3.as_millis(), 4000);
    }

    #[test]
    fn test_calculate_delay_max_cap() {
        let config = RetryConfig::builder()
            .base_delay_ms(1000)
            .max_delay_ms(5000)
            .backoff_multiplier(10.0)
            .jitter_ms(0)
            .build();

        // Attempt 2: 1000 * 10^1 = 10000, but capped at 5000
        let delay = config.calculate_delay(2);
        assert_eq!(delay.as_millis(), 5000);
    }

    #[test]
    fn test_calculate_delay_with_jitter() {
        let config = RetryConfig::builder()
            .base_delay_ms(1000)
            .jitter_ms(100)
            .build();

        let delay = config.calculate_delay(1);
        // Should be between 1000 and 1100
        assert!(delay.as_millis() >= 1000);
        assert!(delay.as_millis() < 1100);
    }

    #[test]
    fn test_is_retryable() {
        let retryable_errors = [
            ErrorCode::HttpTimeout,
            ErrorCode::HttpNetworkError,
            ErrorCode::HttpServerError,
            ErrorCode::NetworkError,
            ErrorCode::NetworkTimeout,
            ErrorCode::HttpRateLimited,
        ];

        for code in retryable_errors {
            let error = FlagKitError::new(code, "Test error");
            assert!(is_retryable(&error), "Expected {:?} to be retryable", code);
        }

        // Non-retryable errors
        let non_retryable = [
            ErrorCode::HttpBadRequest,
            ErrorCode::HttpUnauthorized,
            ErrorCode::HttpForbidden,
            ErrorCode::ConfigInvalidApiKey,
        ];

        for code in non_retryable {
            let error = FlagKitError::new(code, "Test error");
            assert!(!is_retryable(&error), "Expected {:?} to not be retryable", code);
        }
    }

    #[tokio::test]
    async fn test_with_retry_success_first_attempt() {
        let config = RetryConfig::default();
        let attempt_count = AtomicU32::new(0);

        let result = with_retry(
            || {
                attempt_count.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, FlagKitError>("success") }
            },
            &config,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_with_retry_success_after_retries() {
        let config = RetryConfig::builder()
            .max_attempts(3)
            .base_delay_ms(10) // Short delay for tests
            .jitter_ms(0)
            .build();
        let attempt_count = AtomicU32::new(0);

        let result = with_retry(
            || {
                let count = attempt_count.fetch_add(1, Ordering::SeqCst);
                async move {
                    if count < 2 {
                        Err(FlagKitError::network_error(
                            ErrorCode::NetworkTimeout,
                            "Timeout",
                        ))
                    } else {
                        Ok("success")
                    }
                }
            },
            &config,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_retry_all_fail() {
        let config = RetryConfig::builder()
            .max_attempts(3)
            .base_delay_ms(10)
            .jitter_ms(0)
            .build();
        let attempt_count = AtomicU32::new(0);

        let result: Result<&str> = with_retry(
            || {
                attempt_count.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(FlagKitError::network_error(
                        ErrorCode::NetworkTimeout,
                        "Timeout",
                    ))
                }
            },
            &config,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_retry_non_retryable_error() {
        let config = RetryConfig::builder()
            .max_attempts(3)
            .base_delay_ms(10)
            .build();
        let attempt_count = AtomicU32::new(0);

        let result: Result<&str> = with_retry(
            || {
                attempt_count.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(FlagKitError::new(
                        ErrorCode::HttpUnauthorized,
                        "Unauthorized",
                    ))
                }
            },
            &config,
        )
        .await;

        assert!(result.is_err());
        // Should fail immediately without retrying
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_with_retry_detailed() {
        let config = RetryConfig::builder()
            .max_attempts(3)
            .base_delay_ms(10)
            .jitter_ms(0)
            .build();
        let attempt_count = AtomicU32::new(0);

        let result = with_retry_detailed(
            || {
                let count = attempt_count.fetch_add(1, Ordering::SeqCst);
                async move {
                    if count < 1 {
                        Err(FlagKitError::network_error(
                            ErrorCode::NetworkTimeout,
                            "Timeout",
                        ))
                    } else {
                        Ok("success")
                    }
                }
            },
            &config,
        )
        .await;

        assert!(result.success);
        assert_eq!(result.attempts, 2);
        assert_eq!(result.value, Some("success"));
        assert!(result.error.is_none());
    }
}
