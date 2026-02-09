use reqwest::{Client, Response, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::Duration;

use super::circuit_breaker::CircuitBreaker;
use crate::core::FlagKitOptions;
use crate::error::{ErrorCode, FlagKitError, Result};
use crate::security::sign_request;

const DEFAULT_BASE_URL: &str = "https://api.flagkit.dev/api/v1";

/// Subscription status values from the API
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionStatus {
    Active,
    Trial,
    PastDue,
    Suspended,
    Cancelled,
}

impl SubscriptionStatus {
    /// Parse subscription status from header value
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "active" => Some(SubscriptionStatus::Active),
            "trial" => Some(SubscriptionStatus::Trial),
            "past_due" => Some(SubscriptionStatus::PastDue),
            "suspended" => Some(SubscriptionStatus::Suspended),
            "cancelled" => Some(SubscriptionStatus::Cancelled),
            _ => None,
        }
    }
}

/// Usage metrics extracted from response headers.
///
/// These metrics are returned by the FlagKit API to help SDKs monitor
/// usage levels and subscription status.
#[derive(Debug, Clone, Default)]
pub struct UsageMetrics {
    /// Percentage of API call limit used this period (0-150+)
    pub api_usage_percent: Option<f64>,

    /// Percentage of evaluation limit used (0-150+)
    pub evaluation_usage_percent: Option<f64>,

    /// Whether approaching rate limit threshold
    pub rate_limit_warning: bool,

    /// Current subscription status
    pub subscription_status: Option<SubscriptionStatus>,
}

/// Callback type for usage metrics updates
pub type UsageUpdateCallback = Arc<dyn Fn(UsageMetrics) + Send + Sync>;

/// Extract usage metrics from response headers.
///
/// Reads the following headers:
/// - `X-API-Usage-Percent`: Percentage of API call limit used
/// - `X-Evaluation-Usage-Percent`: Percentage of evaluation limit used
/// - `X-Rate-Limit-Warning`: Whether approaching rate limit ("true" or "false")
/// - `X-Subscription-Status`: Current subscription status
pub fn extract_usage_metrics(response: &Response) -> Option<UsageMetrics> {
    let headers = response.headers();

    let api_usage = headers
        .get("x-api-usage-percent")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok());

    let eval_usage = headers
        .get("x-evaluation-usage-percent")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok());

    let rate_limit_warning = headers
        .get("x-rate-limit-warning")
        .and_then(|v| v.to_str().ok())
        .map(|s| s == "true")
        .unwrap_or(false);

    let subscription_status = headers
        .get("x-subscription-status")
        .and_then(|v| v.to_str().ok())
        .and_then(SubscriptionStatus::from_str);

    // Return None if no usage headers present
    if api_usage.is_none() && eval_usage.is_none() && !rate_limit_warning && subscription_status.is_none() {
        return None;
    }

    Some(UsageMetrics {
        api_usage_percent: api_usage,
        evaluation_usage_percent: eval_usage,
        rate_limit_warning,
        subscription_status,
    })
}

pub fn get_base_url(local_port: Option<u16>) -> String {
    match local_port {
        Some(port) => format!("http://localhost:{}/api/v1", port),
        None => DEFAULT_BASE_URL.to_string(),
    }
}

/// HTTP client for FlagKit API communication.
///
/// This client handles API requests with retry logic and circuit breaker.
/// It is cloneable and uses `Arc` internally for shared state.
///
/// Features:
/// - Automatic retry with exponential backoff
/// - Circuit breaker for failure protection
/// - Request timeout handling
/// - Usage metrics extraction from response headers
/// - Subscription status monitoring
#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    circuit_breaker: Arc<CircuitBreaker>,
    options: FlagKitOptions,
    on_usage_update: Option<UsageUpdateCallback>,
}

impl HttpClient {
    /// Create a new HTTP client with the given options.
    pub fn new(options: FlagKitOptions) -> Result<Self> {
        Self::with_usage_callback(options, None)
    }

    /// Create a new HTTP client with a usage update callback.
    pub fn with_usage_callback(
        options: FlagKitOptions,
        on_usage_update: Option<UsageUpdateCallback>,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(options.timeout)
            .build()
            .map_err(|e| {
                FlagKitError::with_source(ErrorCode::NetworkError, "Failed to create HTTP client", e)
            })?;

        let circuit_breaker = Arc::new(CircuitBreaker::new(
            options.circuit_breaker_threshold,
            options.circuit_breaker_reset_timeout,
        ));

        Ok(Self {
            client,
            circuit_breaker,
            options,
            on_usage_update,
        })
    }

    /// Set the usage update callback.
    pub fn set_usage_callback(&mut self, callback: UsageUpdateCallback) {
        self.on_usage_update = Some(callback);
    }

    fn base_url(&self) -> String {
        get_base_url(self.options.local_port)
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.execute_with_retry(|| async { self.do_get(path).await })
            .await
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        self.execute_with_retry(|| async { self.do_post(path, body).await })
            .await
    }

    async fn do_get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url(), path);

        let response = self
            .client
            .get(&url)
            .header("X-API-Key", &self.options.api_key)
            .header("User-Agent", "FlagKit-Rust/1.0.3")
            .header("X-FlagKit-SDK-Version", "1.0.3")
            .header("X-FlagKit-SDK-Language", "rust")
            .send()
            .await
            .map_err(|e| self.convert_error(e))?;

        self.handle_response(response).await
    }

    async fn do_post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.base_url(), path);

        // Serialize body to JSON for signing
        let body_json = serde_json::to_string(body).map_err(|e| {
            FlagKitError::with_source(
                ErrorCode::HttpInvalidResponse,
                "Failed to serialize request body",
                e,
            )
        })?;

        let mut request_builder = self
            .client
            .post(&url)
            .header("X-API-Key", &self.options.api_key)
            .header("User-Agent", "FlagKit-Rust/1.0.3")
            .header("X-FlagKit-SDK-Version", "1.0.3")
            .header("X-FlagKit-SDK-Language", "rust")
            .header("Content-Type", "application/json");

        // Add request signing headers if enabled
        if self.options.enable_request_signing {
            let signature = sign_request(&body_json, &self.options.api_key)?;
            request_builder = request_builder
                .header("X-Signature", signature.x_signature())
                .header("X-Timestamp", signature.x_timestamp())
                .header("X-Key-Id", signature.x_key_id());
        }

        let response = request_builder
            .body(body_json)
            .send()
            .await
            .map_err(|e| self.convert_error(e))?;

        self.handle_response(response).await
    }

    async fn execute_with_retry<T, F, Fut>(&self, action: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        self.circuit_breaker
            .execute_async(|| async {
                let mut last_error = None;

                for attempt in 0..=self.options.retry_attempts {
                    match action().await {
                        Ok(result) => return Ok(result),
                        Err(e) => {
                            if !self.is_retryable(&e) || attempt >= self.options.retry_attempts {
                                return Err(e);
                            }
                            last_error = Some(e);
                            let delay = self.calculate_backoff(attempt);
                            tokio::time::sleep(delay).await;
                        }
                    }
                }

                Err(last_error.unwrap_or_else(|| {
                    FlagKitError::network_error(ErrorCode::NetworkError, "Retry failed")
                }))
            })
            .await
    }

    fn is_retryable(&self, error: &FlagKitError) -> bool {
        matches!(
            error.code,
            ErrorCode::HttpTimeout
                | ErrorCode::HttpNetworkError
                | ErrorCode::HttpServerError
                | ErrorCode::NetworkError
                | ErrorCode::NetworkTimeout
        )
    }

    fn calculate_backoff(&self, attempt: u32) -> Duration {
        let base_delay = 1000.0_f64;
        let max_delay = 30000.0_f64;
        let multiplier = 2.0_f64;

        let delay = (base_delay * multiplier.powi(attempt as i32)).min(max_delay);

        // Add jitter (0-25%)
        let jitter = delay * 0.25 * rand::random::<f64>();
        Duration::from_millis((delay + jitter) as u64)
    }

    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        let status = response.status();

        // Extract usage metrics before consuming the response
        if let Some(metrics) = extract_usage_metrics(&response) {
            // Log warnings for high usage
            self.log_usage_warnings(&metrics);

            // Call the usage update callback if set
            if let Some(ref callback) = self.on_usage_update {
                callback(metrics);
            }
        }

        if status.is_success() {
            let body = response.text().await.map_err(|e| {
                FlagKitError::with_source(ErrorCode::HttpInvalidResponse, "Failed to read response", e)
            })?;

            serde_json::from_str(&body).map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::HttpInvalidResponse,
                    format!("Failed to parse response: {}", e),
                    e,
                )
            })
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(self.status_to_error(status, &body))
        }
    }

    /// Log warnings when usage metrics indicate high usage.
    fn log_usage_warnings(&self, metrics: &UsageMetrics) {
        if let Some(api_usage) = metrics.api_usage_percent {
            if api_usage >= 80.0 {
                eprintln!("[FlagKit] Warning: API usage at {}%", api_usage);
            }
        }

        if let Some(eval_usage) = metrics.evaluation_usage_percent {
            if eval_usage >= 80.0 {
                eprintln!("[FlagKit] Warning: Evaluation usage at {}%", eval_usage);
            }
        }

        if let Some(ref status) = metrics.subscription_status {
            if *status == SubscriptionStatus::Suspended {
                eprintln!("[FlagKit] Error: Subscription suspended - service degraded");
            }
        }
    }

    fn status_to_error(&self, status: StatusCode, body: &str) -> FlagKitError {
        let (code, category) = match status {
            StatusCode::BAD_REQUEST => (ErrorCode::HttpBadRequest, "Client Error"),
            StatusCode::UNAUTHORIZED => (ErrorCode::HttpUnauthorized, "Authentication Error"),
            StatusCode::FORBIDDEN => (ErrorCode::HttpForbidden, "Authorization Error"),
            StatusCode::NOT_FOUND => (ErrorCode::HttpNotFound, "Not Found"),
            StatusCode::TOO_MANY_REQUESTS => (ErrorCode::HttpRateLimited, "Rate Limited"),
            s if s.is_server_error() => (ErrorCode::HttpServerError, "Server Error"),
            s if s.is_client_error() => (ErrorCode::HttpBadRequest, "Client Error"),
            _ => (ErrorCode::HttpServerError, "Server Error"),
        };

        FlagKitError::network_error(code, format!("{}: {} - {}", category, status.as_u16(), body))
    }

    fn convert_error(&self, error: reqwest::Error) -> FlagKitError {
        if error.is_timeout() {
            FlagKitError::with_source(ErrorCode::HttpTimeout, "Request timed out", error)
        } else if error.is_connect() {
            FlagKitError::with_source(ErrorCode::HttpNetworkError, "Connection failed", error)
        } else {
            FlagKitError::with_source(ErrorCode::NetworkError, error.to_string(), error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_url_default() {
        let options = FlagKitOptions::builder("sdk_test_key").build();
        let client = HttpClient::new(options).unwrap();
        assert_eq!(client.base_url(), DEFAULT_BASE_URL);
    }

    #[test]
    fn test_base_url_with_local_port() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .build();
        let client = HttpClient::new(options).unwrap();
        assert_eq!(client.base_url(), "http://localhost:8200/api/v1");
    }

    #[test]
    fn test_get_base_url_none() {
        assert_eq!(get_base_url(None), DEFAULT_BASE_URL);
    }

    #[test]
    fn test_get_base_url_with_port() {
        assert_eq!(get_base_url(Some(3000)), "http://localhost:3000/api/v1");
    }

    // === Usage Metrics Tests ===

    #[test]
    fn test_subscription_status_from_str() {
        assert_eq!(SubscriptionStatus::from_str("active"), Some(SubscriptionStatus::Active));
        assert_eq!(SubscriptionStatus::from_str("trial"), Some(SubscriptionStatus::Trial));
        assert_eq!(SubscriptionStatus::from_str("past_due"), Some(SubscriptionStatus::PastDue));
        assert_eq!(SubscriptionStatus::from_str("suspended"), Some(SubscriptionStatus::Suspended));
        assert_eq!(SubscriptionStatus::from_str("cancelled"), Some(SubscriptionStatus::Cancelled));
        assert_eq!(SubscriptionStatus::from_str("unknown"), None);
    }

    #[test]
    fn test_subscription_status_case_insensitive() {
        assert_eq!(SubscriptionStatus::from_str("ACTIVE"), Some(SubscriptionStatus::Active));
        assert_eq!(SubscriptionStatus::from_str("Active"), Some(SubscriptionStatus::Active));
        assert_eq!(SubscriptionStatus::from_str("PAST_DUE"), Some(SubscriptionStatus::PastDue));
    }

    #[test]
    fn test_usage_metrics_default() {
        let metrics = UsageMetrics::default();
        assert!(metrics.api_usage_percent.is_none());
        assert!(metrics.evaluation_usage_percent.is_none());
        assert!(!metrics.rate_limit_warning);
        assert!(metrics.subscription_status.is_none());
    }

    #[test]
    fn test_usage_callback_can_be_set() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let callback: UsageUpdateCallback = Arc::new(move |_metrics| {
            called_clone.store(true, Ordering::SeqCst);
        });

        let options = FlagKitOptions::builder("sdk_test_key").build();
        let client = HttpClient::with_usage_callback(options, Some(callback)).unwrap();

        assert!(client.on_usage_update.is_some());
    }

    #[test]
    fn test_request_signing_default_disabled() {
        let options = FlagKitOptions::builder("sdk_test_key").build();
        assert!(!options.enable_request_signing);
    }

    #[test]
    fn test_request_signing_can_be_enabled() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .enable_request_signing(true)
            .build();
        assert!(options.enable_request_signing);

        let client = HttpClient::new(options).unwrap();
        assert!(client.options.enable_request_signing);
    }
}
