use reqwest::{Client, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

use crate::circuit_breaker::CircuitBreaker;
use crate::config::FlagKitOptions;
use crate::error::{ErrorCode, FlagKitError, Result};

pub struct HttpClient {
    client: Client,
    circuit_breaker: CircuitBreaker,
    options: FlagKitOptions,
}

impl HttpClient {
    pub fn new(options: FlagKitOptions) -> Result<Self> {
        let client = Client::builder()
            .timeout(options.timeout)
            .build()
            .map_err(|e| {
                FlagKitError::with_source(ErrorCode::NetworkError, "Failed to create HTTP client", e)
            })?;

        let circuit_breaker = CircuitBreaker::new(
            options.circuit_breaker_threshold,
            options.circuit_breaker_reset_timeout,
        );

        Ok(Self {
            client,
            circuit_breaker,
            options,
        })
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
        let url = format!("{}{}", self.options.base_url, path);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.options.api_key))
            .header("X-API-Key", &self.options.api_key)
            .header("User-Agent", "FlagKit-Rust/1.0.0")
            .send()
            .await
            .map_err(|e| self.convert_error(e))?;

        self.handle_response(response).await
    }

    async fn do_post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.options.base_url, path);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.options.api_key))
            .header("X-API-Key", &self.options.api_key)
            .header("User-Agent", "FlagKit-Rust/1.0.0")
            .header("Content-Type", "application/json")
            .json(body)
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
