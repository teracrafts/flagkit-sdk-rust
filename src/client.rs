//! FlagKit client implementation.
//!
//! This module contains the main client implementation for the FlagKit SDK.

use chrono::Utc;
use parking_lot::RwLock;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::core::{
    ContextManager, EventQueue, EventQueueConfig, FlagCache, FlagKitOptions, PollCallback,
    PollingConfig, PollingManager,
};
use crate::error::{ErrorCode, FlagKitError, Result};
use crate::http::HttpClient;
use crate::security::{verify_bootstrap_with_policy, BootstrapVerificationResult};
use crate::types::{EvaluationContext, EvaluationReason, EvaluationResult, FlagState, FlagValue};
use crate::utils::is_version_less_than;

/// The current SDK version, matching Cargo.toml
pub const SDK_VERSION: &str = "1.0.7";

/// SDK feature flags metadata from the server.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitMetadataFeatures {
    /// Whether streaming is enabled.
    #[serde(default)]
    pub streaming: bool,
    /// Whether local evaluation is enabled.
    #[serde(default)]
    pub local_eval: bool,
    /// Whether experiments are enabled.
    #[serde(default)]
    pub experiments: bool,
    /// Whether segments are enabled.
    #[serde(default)]
    pub segments: bool,
}

/// SDK version and feature metadata from the init response.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitMetadata {
    /// Minimum SDK version required (older versions may not work).
    pub sdk_version_min: Option<String>,
    /// Recommended SDK version for optimal experience.
    pub sdk_version_recommended: Option<String>,
    /// Latest available SDK version.
    pub sdk_version_latest: Option<String>,
    /// Deprecation warning message from server.
    pub deprecation_warning: Option<String>,
    /// Feature flags.
    #[serde(default)]
    pub features: InitMetadataFeatures,
}

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
    /// SDK metadata including version requirements.
    #[serde(default)]
    pub metadata: Option<InitMetadata>,
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

        // Load bootstrap data with verification
        client.load_bootstrap(&options)?;

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

    /// Load bootstrap data into the cache.
    ///
    /// Supports both legacy format (raw HashMap) and new format (BootstrapConfig with signature).
    /// When a signature is provided, it is verified according to the bootstrap_verification config.
    fn load_bootstrap(&self, options: &FlagKitOptions) -> Result<()> {
        // Prefer BootstrapConfig if provided, otherwise use legacy bootstrap HashMap
        if let Some(ref bootstrap_config) = options.bootstrap_config {
            // Verify signature if present
            let verification_result = verify_bootstrap_with_policy(
                bootstrap_config,
                &options.api_key,
                &options.bootstrap_verification,
            );

            match verification_result {
                BootstrapVerificationResult::Failed(msg) => {
                    return Err(FlagKitError::new(
                        ErrorCode::SecurityBootstrapVerificationFailed,
                        format!("Bootstrap verification failed: {}", msg),
                    ));
                }
                BootstrapVerificationResult::Success => {
                    tracing::info!("Bootstrap signature verified successfully");
                }
                BootstrapVerificationResult::Skipped => {
                    tracing::debug!("Bootstrap verification skipped");
                }
            }

            // Load the flags into cache
            for (key, value) in &bootstrap_config.flags {
                let flag = FlagState::new(key.clone(), FlagValue::from(value.clone()));
                self.cache.set(key.clone(), flag);
            }

            tracing::debug!(
                "Loaded {} bootstrap flags from BootstrapConfig",
                bootstrap_config.flags.len()
            );
        } else if let Some(ref bootstrap) = options.bootstrap {
            // Legacy format: raw HashMap without signature
            for (key, value) in bootstrap {
                let flag = FlagState::new(key.clone(), FlagValue::from(value.clone()));
                self.cache.set(key.clone(), flag);
            }

            tracing::debug!("Loaded {} bootstrap flags (legacy format)", bootstrap.len());
        }

        Ok(())
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

        // Check SDK version metadata and emit warnings
        self.check_version_metadata(&response);

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

    // === Evaluation Jitter (Timing Attack Protection) ===

    /// Apply evaluation jitter to protect against cache timing attacks.
    ///
    /// When enabled, this adds a random delay before flag evaluation to prevent
    /// attackers from inferring information about flag values based on response times.
    fn apply_evaluation_jitter(&self) {
        let jitter_config = &self.options.evaluation_jitter;
        if !jitter_config.enabled {
            return;
        }

        let jitter_ms = rand::thread_rng().gen_range(jitter_config.min_ms..=jitter_config.max_ms);
        std::thread::sleep(Duration::from_millis(jitter_ms));
    }

    // === Flag Evaluation ===

    /// Evaluate a flag and return the full result.
    pub fn evaluate(&self, flag_key: &str, context: Option<&EvaluationContext>) -> EvaluationResult {
        // Apply jitter to protect against timing attacks
        self.apply_evaluation_jitter();

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

    // === Version Metadata ===

    /// Check SDK version metadata from init response and emit appropriate warnings.
    ///
    /// Per spec, the SDK should parse and surface:
    /// - sdkVersionMin: Minimum required version (older may not work)
    /// - sdkVersionRecommended: Recommended version for optimal experience
    /// - sdkVersionLatest: Latest available version
    /// - deprecationWarning: Server-provided deprecation message
    fn check_version_metadata(&self, response: &InitResponse) {
        let metadata = match &response.metadata {
            Some(m) => m,
            None => return,
        };

        // Check for server-provided deprecation warning first
        if let Some(ref warning) = metadata.deprecation_warning {
            eprintln!("[FlagKit] Deprecation Warning: {}", warning);
            tracing::warn!("[FlagKit] Deprecation Warning: {}", warning);
        }

        // Check minimum version requirement
        if let Some(ref min_version) = metadata.sdk_version_min {
            if is_version_less_than(SDK_VERSION, min_version) {
                eprintln!(
                    "[FlagKit] SDK version {} is below minimum required version {}. \
                    Some features may not work correctly. Please upgrade the SDK.",
                    SDK_VERSION, min_version
                );
                tracing::error!(
                    "[FlagKit] SDK version {} is below minimum required version {}. \
                    Some features may not work correctly. Please upgrade the SDK.",
                    SDK_VERSION, min_version
                );
            }
        }

        // Track if we warned about recommended version
        let mut warned_about_recommended = false;

        // Check recommended version
        if let Some(ref recommended_version) = metadata.sdk_version_recommended {
            if is_version_less_than(SDK_VERSION, recommended_version) {
                eprintln!(
                    "[FlagKit] SDK version {} is below recommended version {}. \
                    Consider upgrading for the best experience.",
                    SDK_VERSION, recommended_version
                );
                tracing::warn!(
                    "[FlagKit] SDK version {} is below recommended version {}. \
                    Consider upgrading for the best experience.",
                    SDK_VERSION, recommended_version
                );
                warned_about_recommended = true;
            }
        }

        // Log if a newer version is available (info level, not a warning)
        // Only log if we haven't already warned about recommended
        if let Some(ref latest_version) = metadata.sdk_version_latest {
            if is_version_less_than(SDK_VERSION, latest_version) && !warned_about_recommended {
                eprintln!(
                    "[FlagKit] SDK version {} - a newer version {} is available.",
                    SDK_VERSION, latest_version
                );
                tracing::info!(
                    "[FlagKit] SDK version {} - a newer version {} is available.",
                    SDK_VERSION, latest_version
                );
            }
        }
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

    // === Evaluation Jitter Tests ===

    #[test]
    fn test_jitter_disabled_by_default() {
        use std::time::Instant;

        let mut bootstrap = HashMap::new();
        bootstrap.insert("test-flag".to_string(), serde_json::json!(true));

        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .bootstrap(bootstrap)
            .build();

        // Verify jitter is disabled by default
        assert!(!options.evaluation_jitter.enabled);

        let client = FlagKitClient::new(options).unwrap();

        // Measure evaluation time - should be very fast without jitter
        let start = Instant::now();
        let _ = client.get_boolean_value("test-flag", false, None);
        let elapsed = start.elapsed();

        // Without jitter, evaluation should complete in well under 5ms
        // Using 3ms as a conservative upper bound for cache lookup
        assert!(
            elapsed.as_millis() < 3,
            "Evaluation took {}ms, expected < 3ms without jitter",
            elapsed.as_millis()
        );
    }

    #[test]
    fn test_jitter_applied_when_enabled() {
        use crate::core::EvaluationJitterConfig;
        use std::time::Instant;

        let mut bootstrap = HashMap::new();
        bootstrap.insert("test-flag".to_string(), serde_json::json!(true));

        let jitter_config = EvaluationJitterConfig {
            enabled: true,
            min_ms: 10,
            max_ms: 20,
        };

        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .bootstrap(bootstrap)
            .evaluation_jitter(jitter_config)
            .build();

        let client = FlagKitClient::new(options).unwrap();

        // Measure evaluation time - should include jitter delay
        let start = Instant::now();
        let _ = client.get_boolean_value("test-flag", false, None);
        let elapsed = start.elapsed();

        // With jitter enabled (min 10ms), evaluation should take at least 10ms
        assert!(
            elapsed.as_millis() >= 10,
            "Evaluation took {}ms, expected >= 10ms with jitter enabled",
            elapsed.as_millis()
        );
    }

    #[test]
    fn test_jitter_timing_within_range() {
        use crate::core::EvaluationJitterConfig;
        use std::time::Instant;

        let mut bootstrap = HashMap::new();
        bootstrap.insert("test-flag".to_string(), serde_json::json!(true));

        let min_ms = 15;
        let max_ms = 25;
        let jitter_config = EvaluationJitterConfig {
            enabled: true,
            min_ms,
            max_ms,
        };

        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .bootstrap(bootstrap)
            .evaluation_jitter(jitter_config)
            .build();

        let client = FlagKitClient::new(options).unwrap();

        // Run multiple evaluations to test the range
        for _ in 0..5 {
            let start = Instant::now();
            let _ = client.get_boolean_value("test-flag", false, None);
            let elapsed = start.elapsed();

            // Allow some tolerance for sleep inaccuracy (OS scheduling, etc.)
            // The timing should be at least min_ms and reasonably close to max_ms
            assert!(
                elapsed.as_millis() >= min_ms as u128,
                "Evaluation took {}ms, expected >= {}ms",
                elapsed.as_millis(),
                min_ms
            );
            // Upper bound with some tolerance for OS scheduling jitter
            assert!(
                elapsed.as_millis() <= (max_ms + 10) as u128,
                "Evaluation took {}ms, expected <= {}ms (with 10ms tolerance)",
                elapsed.as_millis(),
                max_ms + 10
            );
        }
    }

    #[test]
    fn test_enable_evaluation_jitter_builder() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .enable_evaluation_jitter()
            .build();

        assert!(options.evaluation_jitter.enabled);
        assert_eq!(options.evaluation_jitter.min_ms, 5);
        assert_eq!(options.evaluation_jitter.max_ms, 15);
    }

    // === Bootstrap Verification Tests ===

    #[test]
    fn test_bootstrap_config_with_valid_signature() {
        use crate::core::BootstrapConfig;
        use crate::security::sign_bootstrap;

        let mut flags = HashMap::new();
        flags.insert("feature-a".to_string(), serde_json::json!(true));
        flags.insert("feature-b".to_string(), serde_json::json!("enabled"));

        let api_key = "sdk_test_key";
        let timestamp = chrono::Utc::now().timestamp_millis();
        let signature = sign_bootstrap(&flags, api_key, timestamp).unwrap();

        let bootstrap_config = BootstrapConfig::with_signature(flags, signature, timestamp);

        let options = FlagKitOptions::builder(api_key)
            .local_port(8200)
            .bootstrap_config(bootstrap_config)
            .build();

        let client = FlagKitClient::new(options);
        assert!(client.is_ok(), "Client creation should succeed with valid signature");

        let client = client.unwrap();
        assert!(client.has_flag("feature-a"));
        assert!(client.has_flag("feature-b"));
        assert!(client.get_boolean_value("feature-a", false, None));
    }

    #[test]
    fn test_bootstrap_config_with_invalid_signature_error_mode() {
        use crate::core::BootstrapConfig;
        use crate::core::BootstrapVerificationConfig;

        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let bootstrap_config = BootstrapConfig::with_signature(
            flags,
            "invalid_signature".to_string(),
            chrono::Utc::now().timestamp_millis(),
        );

        let verification_config = BootstrapVerificationConfig::strict();

        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .bootstrap_config(bootstrap_config)
            .bootstrap_verification(verification_config)
            .build();

        let client = FlagKitClient::new(options);
        assert!(client.is_err(), "Client creation should fail with invalid signature in error mode");

        match client {
            Ok(_) => panic!("Expected error but got Ok"),
            Err(err) => {
                assert_eq!(err.code, crate::error::ErrorCode::SecurityBootstrapVerificationFailed);
            }
        }
    }

    #[test]
    fn test_bootstrap_config_with_invalid_signature_warn_mode() {
        use crate::core::BootstrapConfig;
        use crate::core::BootstrapVerificationConfig;

        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let bootstrap_config = BootstrapConfig::with_signature(
            flags,
            "invalid_signature".to_string(),
            chrono::Utc::now().timestamp_millis(),
        );

        // Default mode is "warn" - should log warning but succeed
        let verification_config = BootstrapVerificationConfig::default();
        assert_eq!(verification_config.on_failure, "warn");

        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .bootstrap_config(bootstrap_config)
            .bootstrap_verification(verification_config)
            .build();

        let client = FlagKitClient::new(options);
        assert!(client.is_ok(), "Client creation should succeed with invalid signature in warn mode");

        // Flags should still be loaded
        let client = client.unwrap();
        assert!(client.has_flag("feature"));
    }

    #[test]
    fn test_bootstrap_config_with_expired_timestamp() {
        use crate::core::{BootstrapConfig, BootstrapVerificationConfig};
        use crate::security::sign_bootstrap;

        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let api_key = "sdk_test_key";
        // 2 days ago (exceeds default 24h max_age)
        let timestamp = chrono::Utc::now().timestamp_millis() - (2 * 24 * 60 * 60 * 1000);
        let signature = sign_bootstrap(&flags, api_key, timestamp).unwrap();

        let bootstrap_config = BootstrapConfig::with_signature(flags, signature, timestamp);

        let verification_config = BootstrapVerificationConfig::strict();

        let options = FlagKitOptions::builder(api_key)
            .local_port(8200)
            .bootstrap_config(bootstrap_config)
            .bootstrap_verification(verification_config)
            .build();

        let client = FlagKitClient::new(options);
        assert!(client.is_err(), "Client creation should fail with expired bootstrap");
    }

    #[test]
    fn test_bootstrap_config_legacy_format_no_signature() {
        use crate::core::BootstrapConfig;

        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        // Legacy format: no signature
        let bootstrap_config = BootstrapConfig::new(flags);

        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .bootstrap_config(bootstrap_config)
            .build();

        let client = FlagKitClient::new(options);
        assert!(client.is_ok(), "Client creation should succeed with legacy format (no signature)");

        let client = client.unwrap();
        assert!(client.has_flag("feature"));
    }

    #[test]
    fn test_bootstrap_config_verification_disabled() {
        use crate::core::{BootstrapConfig, BootstrapVerificationConfig};

        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(true));

        let bootstrap_config = BootstrapConfig::with_signature(
            flags,
            "completely_invalid".to_string(),
            chrono::Utc::now().timestamp_millis(),
        );

        let verification_config = BootstrapVerificationConfig::permissive();
        assert!(!verification_config.enabled);

        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .bootstrap_config(bootstrap_config)
            .bootstrap_verification(verification_config)
            .build();

        let client = FlagKitClient::new(options);
        assert!(client.is_ok(), "Client creation should succeed when verification is disabled");

        let client = client.unwrap();
        assert!(client.has_flag("feature"));
    }

    #[test]
    fn test_bootstrap_with_signature_builder() {
        use crate::security::sign_bootstrap;

        let mut flags = HashMap::new();
        flags.insert("feature".to_string(), serde_json::json!(42));

        let api_key = "sdk_test_key";
        let timestamp = chrono::Utc::now().timestamp_millis();
        let signature = sign_bootstrap(&flags, api_key, timestamp).unwrap();

        let options = FlagKitOptions::builder(api_key)
            .local_port(8200)
            .bootstrap_with_signature(flags, signature, timestamp)
            .build();

        let client = FlagKitClient::new(options).unwrap();
        assert_eq!(client.get_number_value("feature", 0.0, None), 42.0);
    }

    #[test]
    fn test_bootstrap_config_takes_precedence_over_legacy() {
        use crate::core::BootstrapConfig;

        let mut legacy_flags = HashMap::new();
        legacy_flags.insert("legacy-feature".to_string(), serde_json::json!(true));

        let mut config_flags = HashMap::new();
        config_flags.insert("config-feature".to_string(), serde_json::json!(true));

        let bootstrap_config = BootstrapConfig::new(config_flags);

        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .bootstrap(legacy_flags) // This should be ignored
            .bootstrap_config(bootstrap_config) // This should take precedence
            .build();

        let client = FlagKitClient::new(options).unwrap();

        // Should have config-feature, not legacy-feature
        assert!(client.has_flag("config-feature"));
        assert!(!client.has_flag("legacy-feature"));
    }

    // === SDK Version Metadata Tests ===

    #[test]
    fn test_sdk_version_constant() {
        // Verify SDK_VERSION matches expected format
        assert!(!SDK_VERSION.is_empty());
        let parts: Vec<&str> = SDK_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "SDK_VERSION should be semver format");
    }

    #[test]
    fn test_init_metadata_deserialize() {
        let json = r#"{
            "sdkVersionMin": "0.9.0",
            "sdkVersionRecommended": "1.0.0",
            "sdkVersionLatest": "1.1.0",
            "deprecationWarning": "Please upgrade soon",
            "features": {
                "streaming": true,
                "localEval": false,
                "experiments": true,
                "segments": false
            }
        }"#;

        let metadata: InitMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(metadata.sdk_version_min, Some("0.9.0".to_string()));
        assert_eq!(metadata.sdk_version_recommended, Some("1.0.0".to_string()));
        assert_eq!(metadata.sdk_version_latest, Some("1.1.0".to_string()));
        assert_eq!(metadata.deprecation_warning, Some("Please upgrade soon".to_string()));
        assert!(metadata.features.streaming);
        assert!(!metadata.features.local_eval);
        assert!(metadata.features.experiments);
        assert!(!metadata.features.segments);
    }

    #[test]
    fn test_init_metadata_deserialize_partial() {
        // Test that partial metadata (common case) deserializes correctly
        let json = r#"{
            "sdkVersionLatest": "1.2.0"
        }"#;

        let metadata: InitMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(metadata.sdk_version_min, None);
        assert_eq!(metadata.sdk_version_recommended, None);
        assert_eq!(metadata.sdk_version_latest, Some("1.2.0".to_string()));
        assert_eq!(metadata.deprecation_warning, None);
    }

    #[test]
    fn test_init_response_with_metadata() {
        let json = r#"{
            "flags": [],
            "serverTime": "2024-01-01T00:00:00Z",
            "environment": "production",
            "environmentId": "env-123",
            "pollingIntervalSeconds": 30,
            "metadata": {
                "sdkVersionMin": "0.9.0",
                "sdkVersionRecommended": "1.0.0",
                "sdkVersionLatest": "1.1.0",
                "features": {}
            }
        }"#;

        let response: InitResponse = serde_json::from_str(json).unwrap();
        assert!(response.metadata.is_some());
        let metadata = response.metadata.unwrap();
        assert_eq!(metadata.sdk_version_min, Some("0.9.0".to_string()));
    }

    #[test]
    fn test_init_response_without_metadata() {
        // Ensure backwards compatibility when metadata is not present
        let json = r#"{
            "flags": [],
            "serverTime": "2024-01-01T00:00:00Z",
            "environmentId": "env-123"
        }"#;

        let response: InitResponse = serde_json::from_str(json).unwrap();
        assert!(response.metadata.is_none());
    }

    #[test]
    fn test_check_version_metadata_no_metadata() {
        // When there's no metadata, nothing should happen (no panic)
        let options = create_test_options();
        let client = FlagKitClient::new(options).unwrap();

        let response = InitResponse {
            flags: vec![],
            server_time: None,
            environment: None,
            environment_id: None,
            polling_interval_seconds: None,
            metadata: None,
        };

        // This should not panic
        client.check_version_metadata(&response);
    }

    #[test]
    fn test_check_version_metadata_with_deprecation_warning() {
        let options = create_test_options();
        let client = FlagKitClient::new(options).unwrap();

        let response = InitResponse {
            flags: vec![],
            server_time: None,
            environment: None,
            environment_id: None,
            polling_interval_seconds: None,
            metadata: Some(InitMetadata {
                sdk_version_min: None,
                sdk_version_recommended: None,
                sdk_version_latest: None,
                deprecation_warning: Some("This SDK version is deprecated".to_string()),
                features: InitMetadataFeatures::default(),
            }),
        };

        // This should log a warning but not panic
        client.check_version_metadata(&response);
    }

    #[test]
    fn test_check_version_metadata_with_all_versions() {
        let options = create_test_options();
        let client = FlagKitClient::new(options).unwrap();

        let response = InitResponse {
            flags: vec![],
            server_time: None,
            environment: None,
            environment_id: None,
            polling_interval_seconds: None,
            metadata: Some(InitMetadata {
                sdk_version_min: Some("0.5.0".to_string()),
                sdk_version_recommended: Some("0.9.0".to_string()),
                sdk_version_latest: Some("2.0.0".to_string()),
                deprecation_warning: None,
                features: InitMetadataFeatures::default(),
            }),
        };

        // This should log various messages but not panic
        client.check_version_metadata(&response);
    }
}
