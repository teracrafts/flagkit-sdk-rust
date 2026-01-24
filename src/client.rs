//! FlagKit client implementation.
//!
//! This module contains the main client implementation for the FlagKit SDK.

use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::{
    ContextManager, EventQueue, EventQueueConfig, FlagCache, FlagKitOptions, PollCallback,
    PollingConfig, PollingManager,
};
use crate::error::Result;
use crate::http::HttpClient;
use crate::types::{EvaluationContext, EvaluationReason, EvaluationResult, FlagState, FlagValue};

/// Response from the SDK init endpoint.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitResponse {
    /// List of flag configurations.
    pub flags: Vec<FlagState>,
    /// Server timestamp.
    pub server_time: Option<String>,
    /// Environment name.
    pub environment: Option<String>,
    /// Environment ID.
    pub environment_id: Option<String>,
    /// Recommended polling interval in seconds.
    pub polling_interval_seconds: Option<u64>,
}

/// Response from the SDK updates endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatesResponse {
    /// Updated flags (if any).
    pub flags: Option<Vec<FlagState>>,
    /// Whether there are updates.
    pub has_updates: bool,
    /// Timestamp when checked.
    pub checked_at: Option<String>,
}

/// Request body for flag evaluation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluateRequest {
    /// The flag key to evaluate.
    pub flag_key: String,
    /// Optional evaluation context.
    pub context: Option<HashMap<String, serde_json::Value>>,
}

/// Response from flag evaluation.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluateResponse {
    /// The flag key.
    pub flag_key: String,
    /// The evaluated value.
    pub value: FlagValue,
    /// Whether the flag is enabled.
    pub enabled: bool,
    /// The evaluation reason.
    pub reason: EvaluationReason,
    /// Flag version.
    pub version: i32,
}

/// Request body for batch evaluation.
#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchEvaluateRequest {
    /// List of flag keys to evaluate.
    pub flag_keys: Vec<String>,
    /// Optional evaluation context.
    pub context: Option<HashMap<String, serde_json::Value>>,
}

/// Response from batch evaluation.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchEvaluateResponse {
    /// Map of flag keys to evaluation results.
    pub flags: HashMap<String, EvaluateResponse>,
    /// Timestamp when evaluated.
    pub evaluated_at: Option<String>,
}

/// Response from evaluate all endpoint.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluateAllResponse {
    /// Map of flag keys to evaluation results.
    pub flags: HashMap<String, EvaluateResponse>,
    /// Timestamp when evaluated.
    pub evaluated_at: Option<String>,
}

/// The main FlagKit client.
///
/// This client provides methods for flag evaluation, context management,
/// event tracking, and SDK lifecycle management.
///
/// # Example
///
/// ```no_run
/// use flagkit::{FlagKitClient, FlagKitOptions};
///
/// #[tokio::main]
/// async fn main() -> flagkit::Result<()> {
///     let options = FlagKitOptions::new("sdk_your_api_key");
///     let client = FlagKitClient::new(options)?;
///
///     // Initialize the client
///     client.initialize().await?;
///
///     // Evaluate a flag
///     let value = client.get_boolean_value("my-flag", false, None);
///     println!("Flag value: {}", value);
///
///     // Close the client
///     client.close().await;
///
///     Ok(())
/// }
/// ```
pub struct FlagKitClient {
    options: FlagKitOptions,
    http_client: HttpClient,
    cache: FlagCache,
    context_manager: ContextManager,
    event_queue: Arc<RwLock<EventQueue>>,
    polling_manager: Arc<RwLock<Option<PollingManager>>>,
    initialized: AtomicBool,
    ready: AtomicBool,
    closed: AtomicBool,
    last_update_time: RwLock<Option<String>>,
    environment_id: RwLock<Option<String>>,
    session_id: String,
}

impl FlagKitClient {
    /// Create a new FlagKit client with the given options.
    ///
    /// # Arguments
    ///
    /// * `options` - Configuration options for the client
    ///
    /// # Errors
    ///
    /// Returns an error if the options are invalid.
    pub fn new(options: FlagKitOptions) -> Result<Self> {
        options.validate()?;

        let http_client = HttpClient::new(options.clone())?;
        let cache = FlagCache::new(options.max_cache_size, options.cache_ttl);

        // Configure event queue
        let event_config = EventQueueConfig::builder()
            .batch_size(options.event_batch_size)
            .flush_interval(options.event_flush_interval)
            .enabled(options.events_enabled)
            .build();
        let event_queue = EventQueue::new(event_config);

        let session_id = uuid::Uuid::new_v4().to_string();

        let client = Self {
            options: options.clone(),
            http_client,
            cache,
            context_manager: ContextManager::new(),
            event_queue: Arc::new(RwLock::new(event_queue)),
            polling_manager: Arc::new(RwLock::new(None)),
            initialized: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            last_update_time: RwLock::new(None),
            environment_id: RwLock::new(None),
            session_id,
        };

        // Load bootstrap data if provided
        if let Some(ref bootstrap) = options.bootstrap {
            for (key, value) in bootstrap {
                let flag = FlagState::new(key.clone(), FlagValue::from(value.clone()));
                client.cache.set(key.clone(), flag);
            }
        }

        Ok(client)
    }

    /// Check if the client has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Check if the client is ready for use.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Check if the client has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Initialize the client by fetching flag configurations from the server.
    ///
    /// This should be called before evaluating any flags.
    ///
    /// # Errors
    ///
    /// Returns an error if the initialization fails.
    pub async fn initialize(&self) -> Result<()> {
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }

        let response: InitResponse = self.http_client.get("/sdk/init").await?;

        // Update cache with flags
        for flag in response.flags {
            self.cache.set(flag.key.clone(), flag);
        }

        // Store environment ID
        if let Some(env_id) = response.environment_id {
            *self.environment_id.write() = Some(env_id.clone());
            self.event_queue.read().set_environment_id(env_id);
        }

        // Store session ID
        self.event_queue.read().set_session_id(&self.session_id);

        // Store last update time
        if let Some(server_time) = response.server_time {
            *self.last_update_time.write() = Some(server_time);
        }

        self.initialized.store(true, Ordering::SeqCst);
        self.ready.store(true, Ordering::SeqCst);

        tracing::info!(
            "FlagKit initialized with {} flags",
            self.cache.len()
        );

        // Start polling if enabled
        if self.options.polling_interval.as_secs() > 0 {
            self.start_polling();
        }

        Ok(())
    }

    /// Wait for the client to be ready.
    ///
    /// If the client is already ready, this returns immediately.
    pub async fn wait_for_ready(&self) {
        while !self.ready.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    // === Context Management ===

    /// Identify a user with optional attributes.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user identifier
    /// * `attributes` - Optional attributes to associate with the user
    pub fn identify(&self, user_id: impl Into<String>, attributes: Option<HashMap<String, FlagValue>>) {
        let user_id = user_id.into();
        self.context_manager.identify(&user_id, attributes);
        self.event_queue.read().set_user_id(Some(user_id.clone()));

        // Track identify event
        let mut data = HashMap::new();
        data.insert("userId".to_string(), serde_json::json!(user_id));
        self.event_queue.read().track("context.identified", Some(data));
    }

    /// Set the global evaluation context.
    pub fn set_context(&self, context: EvaluationContext) {
        self.context_manager.set_context(context);
    }

    /// Get the current global context.
    pub fn get_context(&self) -> Option<EvaluationContext> {
        self.context_manager.get_context()
    }

    /// Clear the global evaluation context.
    pub fn clear_context(&self) {
        self.context_manager.clear_context();
        self.event_queue.read().set_user_id(None);
    }

    /// Reset to anonymous state.
    pub fn reset(&self) {
        self.context_manager.reset();
        self.event_queue.read().set_user_id(None);
        self.event_queue.read().track("context.reset", None);
    }

    // === Flag Evaluation ===

    /// Evaluate a flag and return the full result.
    pub fn evaluate(&self, flag_key: &str, context: Option<&EvaluationContext>) -> EvaluationResult {
        let _merged_context = self.context_manager.get_merged_context(context);
        let flag = self.cache.get(flag_key);

        match flag {
            None => EvaluationResult::default_result(
                flag_key,
                FlagValue::Null,
                EvaluationReason::FlagNotFound,
            ),
            Some(flag) => EvaluationResult {
                flag_key: flag_key.to_string(),
                value: flag.value.clone(),
                enabled: flag.enabled,
                reason: EvaluationReason::Cached,
                version: flag.version,
                timestamp: Utc::now(),
            },
        }
    }

    /// Evaluate a flag asynchronously with server-side evaluation.
    pub async fn evaluate_async(
        &self,
        flag_key: &str,
        context: Option<&EvaluationContext>,
    ) -> EvaluationResult {
        let merged_context = self.context_manager.resolve_context(context);

        let request = EvaluateRequest {
            flag_key: flag_key.to_string(),
            context: merged_context.map(|c| c.to_map()),
        };

        match self
            .http_client
            .post::<_, EvaluateResponse>("/sdk/evaluate", &request)
            .await
        {
            Ok(response) => EvaluationResult {
                flag_key: response.flag_key,
                value: response.value,
                enabled: response.enabled,
                reason: response.reason,
                version: response.version,
                timestamp: Utc::now(),
            },
            Err(_) => self.evaluate(flag_key, context),
        }
    }

    /// Get a boolean flag value.
    pub fn get_boolean_value(
        &self,
        flag_key: &str,
        default_value: bool,
        context: Option<&EvaluationContext>,
    ) -> bool {
        let result = self.evaluate(flag_key, context);
        if result.reason == EvaluationReason::FlagNotFound {
            default_value
        } else {
            result.bool_value()
        }
    }

    /// Get a string flag value.
    pub fn get_string_value(
        &self,
        flag_key: &str,
        default_value: &str,
        context: Option<&EvaluationContext>,
    ) -> String {
        let result = self.evaluate(flag_key, context);
        if result.reason == EvaluationReason::FlagNotFound {
            default_value.to_string()
        } else {
            result
                .string_value()
                .map(|s| s.to_string())
                .unwrap_or_else(|| default_value.to_string())
        }
    }

    /// Get a numeric flag value.
    pub fn get_number_value(
        &self,
        flag_key: &str,
        default_value: f64,
        context: Option<&EvaluationContext>,
    ) -> f64 {
        let result = self.evaluate(flag_key, context);
        if result.reason == EvaluationReason::FlagNotFound {
            default_value
        } else {
            result.number_value()
        }
    }

    /// Get an integer flag value.
    pub fn get_int_value(
        &self,
        flag_key: &str,
        default_value: i64,
        context: Option<&EvaluationContext>,
    ) -> i64 {
        let result = self.evaluate(flag_key, context);
        if result.reason == EvaluationReason::FlagNotFound {
            default_value
        } else {
            result.int_value()
        }
    }

    /// Get a JSON flag value.
    pub fn get_json_value(
        &self,
        flag_key: &str,
        default_value: Option<serde_json::Value>,
        context: Option<&EvaluationContext>,
    ) -> Option<serde_json::Value> {
        let result = self.evaluate(flag_key, context);
        if result.reason == EvaluationReason::FlagNotFound {
            default_value
        } else {
            result.json_value().cloned().or(default_value)
        }
    }

    /// Evaluate all flags and return a map of results.
    pub fn evaluate_all(
        &self,
        context: Option<&EvaluationContext>,
    ) -> HashMap<String, EvaluationResult> {
        let all_flags = self.cache.get_all();
        let mut results = HashMap::new();

        for (key, _) in all_flags {
            results.insert(key.clone(), self.evaluate(&key, context));
        }

        results
    }

    /// Evaluate all flags asynchronously using the server.
    pub async fn evaluate_all_async(
        &self,
        context: Option<&EvaluationContext>,
    ) -> Result<HashMap<String, EvaluationResult>> {
        let merged_context = self.context_manager.resolve_context(context);

        #[derive(Serialize)]
        struct Request {
            context: Option<HashMap<String, serde_json::Value>>,
        }

        let request = Request {
            context: merged_context.map(|c| c.to_map()),
        };

        let response: EvaluateAllResponse = self
            .http_client
            .post("/sdk/evaluate/all", &request)
            .await?;

        let mut results = HashMap::new();
        for (key, eval) in response.flags {
            results.insert(
                key,
                EvaluationResult {
                    flag_key: eval.flag_key,
                    value: eval.value,
                    enabled: eval.enabled,
                    reason: eval.reason,
                    version: eval.version,
                    timestamp: Utc::now(),
                },
            );
        }

        Ok(results)
    }

    /// Check if a flag exists.
    pub fn has_flag(&self, flag_key: &str) -> bool {
        self.cache.has(flag_key)
    }

    /// Get all flag keys.
    pub fn get_all_flag_keys(&self) -> Vec<String> {
        self.cache.get_all().keys().cloned().collect()
    }

    /// Get all cached flags.
    pub fn get_all_flags(&self) -> HashMap<String, FlagState> {
        self.cache.get_all()
    }

    // === Event Tracking ===

    /// Track a custom analytics event.
    ///
    /// # Arguments
    ///
    /// * `event_type` - The event type (e.g., "purchase", "page_view")
    /// * `event_data` - Optional event data
    pub fn track(
        &self,
        event_type: impl Into<String>,
        event_data: Option<HashMap<String, serde_json::Value>>,
    ) {
        self.event_queue.read().track(event_type, event_data);
    }

    /// Flush pending events immediately.
    #[allow(clippy::await_holding_lock)]
    pub async fn flush(&self) -> Result<()> {
        let queue = self.event_queue.read();
        queue.flush().await
    }

    // === Polling and Refresh ===

    /// Force refresh flags from the server.
    pub async fn refresh(&self) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(());
        }

        let since = self.last_update_time.read().clone();
        let path = match since {
            Some(s) => format!("/sdk/updates?since={}", urlencoding::encode(&s)),
            None => "/sdk/updates".to_string(),
        };

        let response: UpdatesResponse = self.http_client.get(&path).await?;

        if response.has_updates {
            if let Some(flags) = response.flags {
                for flag in flags {
                    self.cache.set(flag.key.clone(), flag);
                }
            }
        }

        if let Some(checked_at) = response.checked_at {
            *self.last_update_time.write() = Some(checked_at);
        }

        tracing::debug!("Flags refreshed, has_updates: {}", response.has_updates);

        Ok(())
    }

    /// Poll for updates.
    pub async fn poll_for_updates(&self, since: Option<&str>) -> Result<()> {
        let path = match since {
            Some(s) => format!("/sdk/updates?since={}", urlencoding::encode(s)),
            None => "/sdk/updates".to_string(),
        };

        let response: UpdatesResponse = self.http_client.get(&path).await?;

        if response.has_updates {
            if let Some(flags) = response.flags {
                for flag in flags {
                    self.cache.set(flag.key.clone(), flag);
                }
            }
        }

        Ok(())
    }

    /// Start background polling.
    fn start_polling(&self) {
        let mut polling_guard = self.polling_manager.write();
        if polling_guard.is_some() {
            return;
        }

        let config = PollingConfig::builder()
            .interval(self.options.polling_interval)
            .build();

        let mut manager = PollingManager::new(config);

        // Create a weak reference to avoid circular reference
        let http_client = self.http_client.clone();
        let cache = self.cache.clone();
        let last_update_time = Arc::new(RwLock::new(self.last_update_time.read().clone()));

        let callback: PollCallback = Arc::new(move || {
            let http = http_client.clone();
            let cache = cache.clone();
            let update_time = Arc::clone(&last_update_time);

            Box::pin(async move {
                let since = update_time.read().clone();
                let path = match since {
                    Some(s) => format!("/sdk/updates?since={}", urlencoding::encode(&s)),
                    None => "/sdk/updates".to_string(),
                };

                match http.get::<UpdatesResponse>(&path).await {
                    Ok(response) => {
                        if response.has_updates {
                            if let Some(flags) = response.flags {
                                for flag in flags {
                                    cache.set(flag.key.clone(), flag);
                                }
                            }
                        }
                        if let Some(checked_at) = response.checked_at {
                            *update_time.write() = Some(checked_at);
                        }
                        Ok(())
                    }
                    Err(e) => {
                        tracing::warn!("Polling failed: {}", e);
                        Err(())
                    }
                }
            })
        });

        manager.start(callback);
        *polling_guard = Some(manager);

        tracing::debug!("Background polling started");
    }

    /// Stop background polling.
    #[allow(clippy::await_holding_lock)]
    pub async fn stop_polling(&self) {
        let mut guard = self.polling_manager.write();
        if let Some(ref mut manager) = *guard {
            manager.stop().await;
        }
        *guard = None;
        tracing::debug!("Background polling stopped");
    }

    // === Lifecycle ===

    /// Close the client and release resources.
    ///
    /// This will flush any pending events and stop polling.
    #[allow(clippy::await_holding_lock)]
    pub async fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return; // Already closed
        }

        // Stop polling
        self.stop_polling().await;

        // Flush events
        let mut queue = self.event_queue.write();
        let _ = queue.stop().await;

        tracing::info!("FlagKit client closed");
    }

}

impl Clone for FlagKitClient {
    fn clone(&self) -> Self {
        // This is a shallow clone - the internal state is shared
        Self {
            options: self.options.clone(),
            http_client: self.http_client.clone(),
            cache: self.cache.clone(),
            context_manager: self.context_manager.clone(),
            event_queue: Arc::clone(&self.event_queue),
            polling_manager: Arc::clone(&self.polling_manager),
            initialized: AtomicBool::new(self.initialized.load(Ordering::SeqCst)),
            ready: AtomicBool::new(self.ready.load(Ordering::SeqCst)),
            closed: AtomicBool::new(self.closed.load(Ordering::SeqCst)),
            last_update_time: RwLock::new(self.last_update_time.read().clone()),
            environment_id: RwLock::new(self.environment_id.read().clone()),
            session_id: self.session_id.clone(),
        }
    }
}

/// Shared client type alias.
pub type SharedClient = Arc<FlagKitClient>;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_options() -> FlagKitOptions {
        FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .build()
    }

    #[test]
    fn test_client_creation() {
        let options = create_test_options();
        let client = FlagKitClient::new(options);
        assert!(client.is_ok());

        let client = client.unwrap();
        assert!(!client.is_initialized());
        assert!(!client.is_ready());
        assert!(!client.is_closed());
    }

    #[test]
    fn test_context_management() {
        let options = create_test_options();
        let client = FlagKitClient::new(options).unwrap();

        // Initially no context
        assert!(client.get_context().is_none());

        // Identify user
        client.identify("user-123", None);
        assert!(client.context_manager.is_identified());

        // Set context
        let ctx = EvaluationContext::with_user_id("user-456")
            .attribute("plan", "premium");
        client.set_context(ctx);

        let retrieved = client.get_context().unwrap();
        assert_eq!(retrieved.user_id, Some("user-456".to_string()));

        // Clear context
        client.clear_context();
        assert!(client.get_context().is_none());

        // Reset
        client.identify("user-789", None);
        client.reset();
        assert!(client.context_manager.is_anonymous());
    }

    #[test]
    fn test_flag_evaluation_not_found() {
        let options = create_test_options();
        let client = FlagKitClient::new(options).unwrap();

        let result = client.evaluate("nonexistent-flag", None);
        assert_eq!(result.reason, EvaluationReason::FlagNotFound);
    }

    #[test]
    fn test_flag_evaluation_with_bootstrap() {
        let mut bootstrap = HashMap::new();
        bootstrap.insert("test-flag".to_string(), serde_json::json!(true));

        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .bootstrap(bootstrap)
            .build();
        let client = FlagKitClient::new(options).unwrap();

        let value = client.get_boolean_value("test-flag", false, None);
        assert!(value);

        assert!(client.has_flag("test-flag"));
        assert!(!client.has_flag("other-flag"));
    }

    #[test]
    fn test_get_all_flag_keys() {
        let mut bootstrap = HashMap::new();
        bootstrap.insert("flag-1".to_string(), serde_json::json!(true));
        bootstrap.insert("flag-2".to_string(), serde_json::json!("value"));
        bootstrap.insert("flag-3".to_string(), serde_json::json!(42));

        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .bootstrap(bootstrap)
            .build();
        let client = FlagKitClient::new(options).unwrap();

        let keys = client.get_all_flag_keys();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&"flag-1".to_string()));
        assert!(keys.contains(&"flag-2".to_string()));
        assert!(keys.contains(&"flag-3".to_string()));
    }

    #[test]
    fn test_evaluate_all() {
        let mut bootstrap = HashMap::new();
        bootstrap.insert("flag-a".to_string(), serde_json::json!(true));
        bootstrap.insert("flag-b".to_string(), serde_json::json!(false));

        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .bootstrap(bootstrap)
            .build();
        let client = FlagKitClient::new(options).unwrap();

        let results = client.evaluate_all(None);
        assert_eq!(results.len(), 2);
        assert!(results.contains_key("flag-a"));
        assert!(results.contains_key("flag-b"));
    }

    #[test]
    fn test_event_tracking() {
        let options = create_test_options();
        let client = FlagKitClient::new(options).unwrap();

        // Track some events
        client.track("test_event", None);

        let mut data = HashMap::new();
        data.insert("key".to_string(), serde_json::json!("value"));
        client.track("event_with_data", Some(data));

        // Events should be queued
        let queue_size = client.event_queue.read().queue_size();
        assert!(queue_size >= 2);
    }
}
