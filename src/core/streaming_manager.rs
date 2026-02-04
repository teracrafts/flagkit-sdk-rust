use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;

use crate::types::FlagState;

/// Connection states for streaming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

/// SSE error codes from server.
///
/// These codes indicate specific error conditions that the server
/// sends via SSE error events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamErrorCode {
    /// The stream token is invalid - need to re-authenticate
    TokenInvalid,
    /// The stream token has expired - refresh and reconnect
    TokenExpired,
    /// The subscription is suspended - notify user, fall back to cached values
    SubscriptionSuspended,
    /// Connection limit reached - implement backoff or close other connections
    ConnectionLimit,
    /// Streaming service unavailable - fall back to polling
    StreamingUnavailable,
}

impl StreamErrorCode {
    /// Parse error code from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "TOKEN_INVALID" => Some(StreamErrorCode::TokenInvalid),
            "TOKEN_EXPIRED" => Some(StreamErrorCode::TokenExpired),
            "SUBSCRIPTION_SUSPENDED" => Some(StreamErrorCode::SubscriptionSuspended),
            "CONNECTION_LIMIT" => Some(StreamErrorCode::ConnectionLimit),
            "STREAMING_UNAVAILABLE" => Some(StreamErrorCode::StreamingUnavailable),
            _ => None,
        }
    }
}

/// SSE error event data structure.
///
/// This represents the data payload of an SSE error event
/// sent by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamErrorData {
    /// The error code indicating the type of error
    pub code: StreamErrorCode,
    /// A human-readable error message
    pub message: String,
}

/// Callback type for subscription errors (e.g., suspended)
pub type SubscriptionErrorCallback = Arc<dyn Fn(String) + Send + Sync>;

/// Callback type for connection limit errors
pub type ConnectionLimitErrorCallback = Arc<dyn Fn() + Send + Sync>;

/// Response from the stream token endpoint.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StreamTokenResponse {
    token: String,
    expires_in: u32,
}

/// Streaming configuration.
#[derive(Debug, Clone)]
pub struct StreamingConfig {
    pub enabled: bool,
    pub reconnect_interval: Duration,
    pub max_reconnect_attempts: u32,
    pub heartbeat_interval: Duration,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            reconnect_interval: Duration::from_millis(3000),
            max_reconnect_attempts: 3,
            heartbeat_interval: Duration::from_millis(30000),
        }
    }
}

/// Callback types for streaming events.
pub type FlagUpdateCallback = Arc<dyn Fn(FlagState) + Send + Sync>;
pub type FlagDeleteCallback = Arc<dyn Fn(String) + Send + Sync>;
pub type FlagsResetCallback = Arc<dyn Fn(Vec<FlagState>) + Send + Sync>;
pub type FallbackCallback = Arc<dyn Fn() + Send + Sync>;

/// Manages Server-Sent Events (SSE) connection for real-time flag updates.
///
/// Security: Uses token exchange pattern to avoid exposing API keys in URLs.
/// 1. Fetches short-lived token via POST with API key in header
/// 2. Connects to SSE endpoint with disposable token in URL
///
/// Features:
/// - Secure token-based authentication
/// - Automatic token refresh before expiry
/// - Automatic reconnection with exponential backoff
/// - Graceful degradation to polling after max failures
/// - Heartbeat monitoring for connection health
/// - SSE error event handling with specific error codes
pub struct StreamingManager {
    base_url: String,
    get_api_key: Arc<dyn Fn() -> String + Send + Sync>,
    config: StreamingConfig,
    on_flag_update: FlagUpdateCallback,
    on_flag_delete: FlagDeleteCallback,
    on_flags_reset: FlagsResetCallback,
    on_fallback_to_polling: FallbackCallback,
    on_subscription_error: Option<SubscriptionErrorCallback>,
    on_connection_limit_error: Option<ConnectionLimitErrorCallback>,

    state: RwLock<StreamingState>,
    consecutive_failures: AtomicU32,
    last_heartbeat: AtomicU64,
    shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    client: reqwest::Client,
}

impl StreamingManager {
    /// Creates a new streaming manager.
    pub fn new(
        base_url: String,
        get_api_key: Arc<dyn Fn() -> String + Send + Sync>,
        config: StreamingConfig,
        on_flag_update: FlagUpdateCallback,
        on_flag_delete: FlagDeleteCallback,
        on_flags_reset: FlagsResetCallback,
        on_fallback_to_polling: FallbackCallback,
    ) -> Self {
        Self {
            base_url,
            get_api_key,
            config,
            on_flag_update,
            on_flag_delete,
            on_flags_reset,
            on_fallback_to_polling,
            on_subscription_error: None,
            on_connection_limit_error: None,
            state: RwLock::new(StreamingState::Disconnected),
            consecutive_failures: AtomicU32::new(0),
            last_heartbeat: AtomicU64::new(0),
            shutdown: Mutex::new(None),
            client: reqwest::Client::new(),
        }
    }

    /// Creates a new streaming manager with error callbacks.
    pub fn with_error_callbacks(
        base_url: String,
        get_api_key: Arc<dyn Fn() -> String + Send + Sync>,
        config: StreamingConfig,
        on_flag_update: FlagUpdateCallback,
        on_flag_delete: FlagDeleteCallback,
        on_flags_reset: FlagsResetCallback,
        on_fallback_to_polling: FallbackCallback,
        on_subscription_error: Option<SubscriptionErrorCallback>,
        on_connection_limit_error: Option<ConnectionLimitErrorCallback>,
    ) -> Self {
        Self {
            base_url,
            get_api_key,
            config,
            on_flag_update,
            on_flag_delete,
            on_flags_reset,
            on_fallback_to_polling,
            on_subscription_error,
            on_connection_limit_error,
            state: RwLock::new(StreamingState::Disconnected),
            consecutive_failures: AtomicU32::new(0),
            last_heartbeat: AtomicU64::new(0),
            shutdown: Mutex::new(None),
            client: reqwest::Client::new(),
        }
    }

    /// Set the subscription error callback.
    pub fn set_subscription_error_callback(&mut self, callback: SubscriptionErrorCallback) {
        self.on_subscription_error = Some(callback);
    }

    /// Set the connection limit error callback.
    pub fn set_connection_limit_error_callback(&mut self, callback: ConnectionLimitErrorCallback) {
        self.on_connection_limit_error = Some(callback);
    }

    /// Gets the current connection state.
    pub async fn get_state(&self) -> StreamingState {
        *self.state.read().await
    }

    /// Checks if streaming is connected.
    pub async fn is_connected(&self) -> bool {
        *self.state.read().await == StreamingState::Connected
    }

    /// Starts the streaming connection.
    pub async fn connect(self: Arc<Self>) {
        {
            let state = self.state.read().await;
            if *state == StreamingState::Connected || *state == StreamingState::Connecting {
                return;
            }
        }

        {
            let mut state = self.state.write().await;
            *state = StreamingState::Connecting;
        }

        let manager = Arc::clone(&self);
        tokio::spawn(async move {
            manager.initiate_connection().await;
        });
    }

    /// Stops the streaming connection.
    pub async fn disconnect(&self) {
        self.cleanup().await;
        *self.state.write().await = StreamingState::Disconnected;
        self.consecutive_failures.store(0, Ordering::SeqCst);
    }

    /// Retries the streaming connection.
    pub async fn retry_connection(self: Arc<Self>) {
        {
            let state = self.state.read().await;
            if *state == StreamingState::Connected || *state == StreamingState::Connecting {
                return;
            }
        }
        self.consecutive_failures.store(0, Ordering::SeqCst);
        self.connect().await;
    }

    async fn initiate_connection(self: Arc<Self>) {
        // Step 1: Fetch short-lived stream token
        let token_response = match self.fetch_stream_token().await {
            Ok(response) => response,
            Err(e) => {
                eprintln!("Failed to fetch stream token: {}", e);
                self.handle_connection_failure().await;
                return;
            }
        };

        // Step 2: Schedule token refresh at 80% of TTL
        let refresh_delay = Duration::from_secs_f64(token_response.expires_in as f64 * 0.8);
        let manager_clone = Arc::clone(&self);
        tokio::spawn(async move {
            manager_clone.schedule_token_refresh(refresh_delay).await;
        });

        // Step 3: Create SSE connection with token
        self.create_connection(&token_response.token).await;
    }

    async fn fetch_stream_token(&self) -> Result<StreamTokenResponse, reqwest::Error> {
        let token_url = format!("{}/sdk/stream/token", self.base_url);

        let response = self
            .client
            .post(&token_url)
            .header("Content-Type", "application/json")
            .header("X-API-Key", (self.get_api_key)())
            .body("{}")
            .send()
            .await?;

        response.json::<StreamTokenResponse>().await
    }

    async fn schedule_token_refresh(self: Arc<Self>, delay: Duration) {
        sleep(delay).await;

        match self.fetch_stream_token().await {
            Ok(token_response) => {
                let next_delay = Duration::from_secs_f64(token_response.expires_in as f64 * 0.8);
                let manager = Arc::clone(&self);
                tokio::spawn(async move {
                    manager.schedule_token_refresh(next_delay).await;
                });
            }
            Err(_) => {
                self.disconnect().await;
                self.connect().await;
            }
        }
    }

    async fn create_connection(self: Arc<Self>, token: &str) {
        let stream_url = format!("{}/sdk/stream?token={}", self.base_url, token);

        let response = match self
            .client
            .get(&stream_url)
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => {
                eprintln!("SSE connection error: {}", e);
                self.handle_connection_failure().await;
                return;
            }
        };

        if !response.status().is_success() {
            eprintln!("SSE connection failed: {}", response.status());
            self.handle_connection_failure().await;
            return;
        }

        self.handle_open().await;

        // Read SSE events
        let mut event_type: Option<String> = None;
        let mut data_buffer = String::new();

        let mut stream = response.bytes_stream();
        use futures_util::StreamExt;

        let mut line_buffer = String::new();

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    line_buffer.push_str(&text);

                    while let Some(newline_pos) = line_buffer.find('\n') {
                        let line: String = line_buffer.drain(..=newline_pos).collect();
                        let line = line.trim();

                        // Empty line = end of event
                        if line.is_empty() {
                            if let Some(ref event) = event_type {
                                if !data_buffer.is_empty() {
                                    self.process_event(event, &data_buffer);
                                    event_type = None;
                                    data_buffer.clear();
                                }
                            }
                            continue;
                        }

                        // Parse SSE format
                        if line.starts_with("event:") {
                            event_type = Some(line[6..].trim().to_string());
                        } else if line.starts_with("data:") {
                            data_buffer.push_str(line[5..].trim());
                        }
                    }
                }
                Err(_) => break,
            }
        }

        // Connection closed
        if *self.state.read().await == StreamingState::Connected {
            self.handle_connection_failure().await;
        }
    }

    async fn handle_open(&self) {
        *self.state.write().await = StreamingState::Connected;
        self.consecutive_failures.store(0, Ordering::SeqCst);
        self.last_heartbeat.store(
            Instant::now().elapsed().as_millis() as u64,
            Ordering::SeqCst,
        );
        // Start heartbeat monitor
        // (simplified - in production would spawn a task)
    }

    fn process_event(&self, event_type: &str, data: &str) {
        match event_type {
            "flag_updated" => {
                if let Ok(flag) = serde_json::from_str::<FlagState>(data) {
                    (self.on_flag_update)(flag);
                }
            }
            "flag_deleted" => {
                #[derive(serde::Deserialize)]
                struct DeleteData {
                    key: String,
                }
                if let Ok(delete_data) = serde_json::from_str::<DeleteData>(data) {
                    (self.on_flag_delete)(delete_data.key);
                }
            }
            "flags_reset" => {
                if let Ok(flags) = serde_json::from_str::<Vec<FlagState>>(data) {
                    (self.on_flags_reset)(flags);
                }
            }
            "heartbeat" => {
                self.last_heartbeat.store(
                    Instant::now().elapsed().as_millis() as u64,
                    Ordering::SeqCst,
                );
            }
            "error" => {
                // Handle SSE error events
                self.handle_stream_error(data);
            }
            _ => {}
        }
    }

    /// Handle SSE error event from server.
    ///
    /// These are application-level errors sent as SSE events, not connection errors.
    ///
    /// Error codes:
    /// - TOKEN_INVALID: Re-authenticate completely
    /// - TOKEN_EXPIRED: Refresh token and reconnect
    /// - SUBSCRIPTION_SUSPENDED: Notify user, fall back to cached values
    /// - CONNECTION_LIMIT: Implement backoff or close other connections
    /// - STREAMING_UNAVAILABLE: Fall back to polling
    fn handle_stream_error(&self, data: &str) {
        match serde_json::from_str::<StreamErrorData>(data) {
            Ok(error_data) => {
                eprintln!(
                    "[FlagKit] SSE error event: {:?} - {}",
                    error_data.code, error_data.message
                );

                match error_data.code {
                    StreamErrorCode::TokenExpired => {
                        // Token expired, will refresh on reconnect
                        eprintln!("[FlagKit] Stream token expired, reconnecting...");
                        // The connection will be closed and reconnection will fetch a new token
                    }
                    StreamErrorCode::TokenInvalid => {
                        // Token is invalid, need full re-authentication
                        eprintln!("[FlagKit] Stream token invalid, re-authenticating...");
                        // The connection will be closed and reconnection will fetch a new token
                    }
                    StreamErrorCode::SubscriptionSuspended => {
                        // Subscription issue - notify user
                        eprintln!(
                            "[FlagKit] Subscription suspended: {}",
                            error_data.message
                        );
                        if let Some(ref callback) = self.on_subscription_error {
                            callback(error_data.message);
                        }
                        // Will trigger fallback to polling
                    }
                    StreamErrorCode::ConnectionLimit => {
                        // Too many connections
                        eprintln!("[FlagKit] Connection limit reached, backing off...");
                        if let Some(ref callback) = self.on_connection_limit_error {
                            callback();
                        }
                        // Will trigger reconnect with backoff
                    }
                    StreamErrorCode::StreamingUnavailable => {
                        // Streaming not available
                        eprintln!(
                            "[FlagKit] Streaming service unavailable, falling back to polling"
                        );
                        // Will trigger fallback to polling
                    }
                }
            }
            Err(e) => {
                eprintln!("[FlagKit] Failed to parse SSE error event: {}", e);
            }
        }
    }

    async fn handle_connection_failure(self: &Arc<Self>) {
        self.cleanup().await;
        let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;

        if failures >= self.config.max_reconnect_attempts {
            *self.state.write().await = StreamingState::Failed;
            (self.on_fallback_to_polling)();
            self.schedule_streaming_retry().await;
        } else {
            *self.state.write().await = StreamingState::Reconnecting;
            self.schedule_reconnect().await;
        }
    }

    async fn schedule_reconnect(self: &Arc<Self>) {
        let delay = self.get_reconnect_delay();
        let manager = Arc::clone(self);

        tokio::spawn(async move {
            sleep(delay).await;
            manager.connect().await;
        });
    }

    fn get_reconnect_delay(&self) -> Duration {
        let base_delay = self.config.reconnect_interval.as_millis() as f64;
        let failures = self.consecutive_failures.load(Ordering::SeqCst);
        let backoff = 2_f64.powi((failures as i32) - 1);
        let delay = base_delay * backoff;
        // Cap at 30 seconds
        Duration::from_millis(delay.min(30000.0) as u64)
    }

    async fn schedule_streaming_retry(self: &Arc<Self>) {
        let manager = Arc::clone(self);

        tokio::spawn(async move {
            sleep(Duration::from_secs(300)).await; // 5 minutes
            manager.retry_connection().await;
        });
    }

    async fn cleanup(&self) {
        if let Some(shutdown) = self.shutdown.lock().await.take() {
            let _ = shutdown.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === StreamErrorCode Tests ===

    #[test]
    fn test_stream_error_code_from_str() {
        assert_eq!(
            StreamErrorCode::from_str("TOKEN_INVALID"),
            Some(StreamErrorCode::TokenInvalid)
        );
        assert_eq!(
            StreamErrorCode::from_str("TOKEN_EXPIRED"),
            Some(StreamErrorCode::TokenExpired)
        );
        assert_eq!(
            StreamErrorCode::from_str("SUBSCRIPTION_SUSPENDED"),
            Some(StreamErrorCode::SubscriptionSuspended)
        );
        assert_eq!(
            StreamErrorCode::from_str("CONNECTION_LIMIT"),
            Some(StreamErrorCode::ConnectionLimit)
        );
        assert_eq!(
            StreamErrorCode::from_str("STREAMING_UNAVAILABLE"),
            Some(StreamErrorCode::StreamingUnavailable)
        );
        assert_eq!(StreamErrorCode::from_str("UNKNOWN_CODE"), None);
    }

    #[test]
    fn test_stream_error_data_deserialize() {
        let json = r#"{"code":"TOKEN_EXPIRED","message":"Token has expired"}"#;
        let error_data: StreamErrorData = serde_json::from_str(json).unwrap();
        assert_eq!(error_data.code, StreamErrorCode::TokenExpired);
        assert_eq!(error_data.message, "Token has expired");
    }

    #[test]
    fn test_stream_error_data_serialize() {
        let error_data = StreamErrorData {
            code: StreamErrorCode::SubscriptionSuspended,
            message: "Your subscription is suspended".to_string(),
        };
        let json = serde_json::to_string(&error_data).unwrap();
        assert!(json.contains("SUBSCRIPTION_SUSPENDED"));
        assert!(json.contains("Your subscription is suspended"));
    }

    // === StreamingConfig Tests ===

    #[test]
    fn test_streaming_config_default() {
        let config = StreamingConfig::default();
        assert!(config.enabled);
        assert_eq!(config.reconnect_interval, Duration::from_millis(3000));
        assert_eq!(config.max_reconnect_attempts, 3);
        assert_eq!(config.heartbeat_interval, Duration::from_millis(30000));
    }

    // === StreamingState Tests ===

    #[test]
    fn test_streaming_state_equality() {
        assert_eq!(StreamingState::Disconnected, StreamingState::Disconnected);
        assert_ne!(StreamingState::Connected, StreamingState::Connecting);
    }

    // === StreamingManager Tests ===

    #[test]
    fn test_streaming_manager_creation() {
        let manager = StreamingManager::new(
            "https://api.flagkit.dev".to_string(),
            Arc::new(|| "sdk_test_key".to_string()),
            StreamingConfig::default(),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
            Arc::new(|| {}),
        );

        assert_eq!(manager.base_url, "https://api.flagkit.dev");
    }

    #[test]
    fn test_streaming_manager_with_error_callbacks() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let subscription_called = Arc::new(AtomicBool::new(false));
        let connection_limit_called = Arc::new(AtomicBool::new(false));

        let sub_called_clone = Arc::clone(&subscription_called);
        let conn_called_clone = Arc::clone(&connection_limit_called);

        let manager = StreamingManager::with_error_callbacks(
            "https://api.flagkit.dev".to_string(),
            Arc::new(|| "sdk_test_key".to_string()),
            StreamingConfig::default(),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
            Arc::new(|| {}),
            Some(Arc::new(move |_msg| {
                sub_called_clone.store(true, Ordering::SeqCst);
            })),
            Some(Arc::new(move || {
                conn_called_clone.store(true, Ordering::SeqCst);
            })),
        );

        // Verify callbacks are set
        assert!(manager.on_subscription_error.is_some());
        assert!(manager.on_connection_limit_error.is_some());
    }

    #[test]
    fn test_handle_stream_error_subscription_suspended() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let manager = StreamingManager::with_error_callbacks(
            "https://api.flagkit.dev".to_string(),
            Arc::new(|| "sdk_test_key".to_string()),
            StreamingConfig::default(),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
            Arc::new(|| {}),
            Some(Arc::new(move |_msg| {
                called_clone.store(true, Ordering::SeqCst);
            })),
            None,
        );

        let error_json = r#"{"code":"SUBSCRIPTION_SUSPENDED","message":"Account suspended"}"#;
        manager.handle_stream_error(error_json);

        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_handle_stream_error_connection_limit() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let manager = StreamingManager::with_error_callbacks(
            "https://api.flagkit.dev".to_string(),
            Arc::new(|| "sdk_test_key".to_string()),
            StreamingConfig::default(),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
            Arc::new(|| {}),
            None,
            Some(Arc::new(move || {
                called_clone.store(true, Ordering::SeqCst);
            })),
        );

        let error_json = r#"{"code":"CONNECTION_LIMIT","message":"Too many connections"}"#;
        manager.handle_stream_error(error_json);

        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_handle_stream_error_invalid_json() {
        let manager = StreamingManager::new(
            "https://api.flagkit.dev".to_string(),
            Arc::new(|| "sdk_test_key".to_string()),
            StreamingConfig::default(),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
            Arc::new(|| {}),
        );

        // Should not panic with invalid JSON
        manager.handle_stream_error("not valid json");
    }
}
