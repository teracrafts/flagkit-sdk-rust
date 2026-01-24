//! Event queue for batching and sending analytics events.
//!
//! This module provides an event queue that batches events and sends them
//! to the server periodically or when the batch size is reached.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::error::{ErrorCode, FlagKitError, Result};

/// Default batch size (number of events before auto-flush).
pub const DEFAULT_BATCH_SIZE: usize = 10;

/// Default flush interval in seconds.
pub const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 30;

/// Default maximum queue size.
pub const DEFAULT_MAX_QUEUE_SIZE: usize = 1000;

/// Configuration for the event queue.
#[derive(Debug, Clone)]
pub struct EventQueueConfig {
    /// Number of events to batch before sending. Default: 10
    pub batch_size: usize,

    /// Interval between automatic flushes. Default: 30 seconds
    pub flush_interval: Duration,

    /// Maximum number of events to queue. Default: 1000
    pub max_queue_size: usize,

    /// Whether events are enabled. Default: true
    pub enabled: bool,

    /// Sample rate (0.0 to 1.0). Default: 1.0
    pub sample_rate: f64,
}

impl Default for EventQueueConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
            flush_interval: Duration::from_secs(DEFAULT_FLUSH_INTERVAL_SECS),
            max_queue_size: DEFAULT_MAX_QUEUE_SIZE,
            enabled: true,
            sample_rate: 1.0,
        }
    }
}

impl EventQueueConfig {
    /// Create a new config builder.
    pub fn builder() -> EventQueueConfigBuilder {
        EventQueueConfigBuilder::default()
    }
}

/// Builder for EventQueueConfig.
#[derive(Debug, Default)]
pub struct EventQueueConfigBuilder {
    batch_size: Option<usize>,
    flush_interval: Option<Duration>,
    max_queue_size: Option<usize>,
    enabled: Option<bool>,
    sample_rate: Option<f64>,
}

impl EventQueueConfigBuilder {
    /// Set batch size.
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = Some(size);
        self
    }

    /// Set flush interval.
    pub fn flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = Some(interval);
        self
    }

    /// Set maximum queue size.
    pub fn max_queue_size(mut self, size: usize) -> Self {
        self.max_queue_size = Some(size);
        self
    }

    /// Set whether events are enabled.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    /// Set sample rate.
    pub fn sample_rate(mut self, rate: f64) -> Self {
        self.sample_rate = Some(rate.clamp(0.0, 1.0));
        self
    }

    /// Build the configuration.
    pub fn build(self) -> EventQueueConfig {
        EventQueueConfig {
            batch_size: self.batch_size.unwrap_or(DEFAULT_BATCH_SIZE),
            flush_interval: self
                .flush_interval
                .unwrap_or(Duration::from_secs(DEFAULT_FLUSH_INTERVAL_SECS)),
            max_queue_size: self.max_queue_size.unwrap_or(DEFAULT_MAX_QUEUE_SIZE),
            enabled: self.enabled.unwrap_or(true),
            sample_rate: self.sample_rate.unwrap_or(1.0),
        }
    }
}

/// An analytics event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    /// Event type (e.g., "purchase", "page_view").
    pub event_type: String,

    /// Timestamp in RFC3339 format.
    pub timestamp: String,

    /// SDK version.
    pub sdk_version: String,

    /// SDK language.
    pub sdk_language: String,

    /// Session ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Environment ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,

    /// User ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Custom event data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_data: Option<HashMap<String, serde_json::Value>>,
}

impl Event {
    /// Create a new event.
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            sdk_version: env!("CARGO_PKG_VERSION").to_string(),
            sdk_language: "rust".to_string(),
            session_id: None,
            environment_id: None,
            user_id: None,
            event_data: None,
        }
    }

    /// Set session ID.
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Set environment ID.
    pub fn environment_id(mut self, id: impl Into<String>) -> Self {
        self.environment_id = Some(id.into());
        self
    }

    /// Set user ID.
    pub fn user_id(mut self, id: impl Into<String>) -> Self {
        self.user_id = Some(id.into());
        self
    }

    /// Set event data.
    pub fn data(mut self, data: HashMap<String, serde_json::Value>) -> Self {
        self.event_data = Some(data);
        self
    }

    /// Add a single data field.
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        let data = self.event_data.get_or_insert_with(HashMap::new);
        data.insert(key.into(), value.into());
        self
    }
}

/// Request body for batch event submission.
#[derive(Debug, Serialize)]
pub struct BatchEventsRequest {
    pub events: Vec<Event>,
}

/// Response from batch event submission.
#[derive(Debug, Deserialize)]
pub struct BatchEventsResponse {
    pub success: bool,
    pub message: Option<String>,
    pub recorded: Option<usize>,
    pub errors: Option<usize>,
}

/// Callback type for sending events.
pub type EventSender = Arc<dyn Fn(Vec<Event>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> + Send + Sync>;

/// Internal state for the event queue.
struct EventQueueState {
    events: Vec<Event>,
    environment_id: Option<String>,
    session_id: Option<String>,
    user_id: Option<String>,
}

/// Event queue for batching and sending analytics events.
///
/// The queue automatically flushes events when:
/// - The batch size is reached
/// - The flush interval elapses
/// - `flush()` is called manually
/// - The queue is dropped (graceful shutdown)
pub struct EventQueue {
    config: EventQueueConfig,
    state: Arc<Mutex<EventQueueState>>,
    sender: Option<EventSender>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    is_running: Arc<AtomicBool>,
    flush_tx: Option<mpsc::Sender<()>>,
}

impl EventQueue {
    /// Create a new event queue.
    pub fn new(config: EventQueueConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(EventQueueState {
                events: Vec::new(),
                environment_id: None,
                session_id: None,
                user_id: None,
            })),
            sender: None,
            shutdown_tx: None,
            is_running: Arc::new(AtomicBool::new(false)),
            flush_tx: None,
        }
    }

    /// Create a new event queue with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(EventQueueConfig::default())
    }

    /// Set the event sender callback.
    ///
    /// The sender is called when events need to be sent to the server.
    pub fn set_sender(&mut self, sender: EventSender) {
        self.sender = Some(sender);
    }

    /// Set the environment ID for all events.
    pub fn set_environment_id(&self, id: impl Into<String>) {
        let mut state = self.state.lock();
        state.environment_id = Some(id.into());
    }

    /// Set the session ID for all events.
    pub fn set_session_id(&self, id: impl Into<String>) {
        let mut state = self.state.lock();
        state.session_id = Some(id.into());
    }

    /// Set the user ID for all events.
    pub fn set_user_id(&self, id: Option<String>) {
        let mut state = self.state.lock();
        state.user_id = id;
    }

    /// Start the background flush task.
    ///
    /// This should be called after setting up the sender.
    pub fn start(&mut self) {
        if self.is_running.load(Ordering::SeqCst) {
            return;
        }

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let (flush_tx, mut flush_rx) = mpsc::channel::<()>(10);
        self.shutdown_tx = Some(shutdown_tx);
        self.flush_tx = Some(flush_tx);
        self.is_running.store(true, Ordering::SeqCst);

        let state = Arc::clone(&self.state);
        let config = self.config.clone();
        let sender = self.sender.clone();
        let is_running = Arc::clone(&self.is_running);

        tokio::spawn(async move {
            let mut flush_interval = interval(config.flush_interval);
            flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::debug!("Event queue shutting down");
                        // Final flush
                        if let Some(ref sender) = sender {
                            let events = {
                                let mut state = state.lock();
                                std::mem::take(&mut state.events)
                            };
                            if !events.is_empty() {
                                let _ = sender(events).await;
                            }
                        }
                        break;
                    }
                    _ = flush_rx.recv() => {
                        // Manual flush request
                        if let Some(ref sender) = sender {
                            let events = {
                                let mut state = state.lock();
                                std::mem::take(&mut state.events)
                            };
                            if !events.is_empty() {
                                if let Err(e) = sender(events.clone()).await {
                                    tracing::warn!("Failed to flush events: {}", e);
                                    // Re-queue failed events
                                    let mut state = state.lock();
                                    let available_space = config.max_queue_size.saturating_sub(state.events.len());
                                    let to_requeue: Vec<_> = events.into_iter().take(available_space).collect();
                                    state.events.splice(0..0, to_requeue);
                                }
                            }
                        }
                    }
                    _ = flush_interval.tick() => {
                        if !is_running.load(Ordering::SeqCst) {
                            break;
                        }

                        if let Some(ref sender) = sender {
                            let events = {
                                let mut state = state.lock();
                                std::mem::take(&mut state.events)
                            };
                            if !events.is_empty() {
                                if let Err(e) = sender(events.clone()).await {
                                    tracing::warn!("Failed to send events: {}", e);
                                    // Re-queue failed events
                                    let mut state = state.lock();
                                    let available_space = config.max_queue_size.saturating_sub(state.events.len());
                                    let to_requeue: Vec<_> = events.into_iter().take(available_space).collect();
                                    state.events.splice(0..0, to_requeue);
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    /// Track a custom event.
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
        if !self.config.enabled {
            return;
        }

        // Apply sampling
        if self.config.sample_rate < 1.0 && rand::random::<f64>() >= self.config.sample_rate {
            return;
        }

        let event_type = event_type.into();

        // Validate event type
        if event_type.is_empty() || event_type.len() > 256 {
            tracing::warn!("Invalid event type: {}", event_type);
            return;
        }

        let mut event = Event::new(event_type);
        event.event_data = event_data;

        // Apply context from state
        {
            let state = self.state.lock();
            if let Some(ref env_id) = state.environment_id {
                event.environment_id = Some(env_id.clone());
            }
            if let Some(ref session_id) = state.session_id {
                event.session_id = Some(session_id.clone());
            }
            if let Some(ref user_id) = state.user_id {
                event.user_id = Some(user_id.clone());
            }
        }

        self.add_event(event);
    }

    /// Add an event to the queue.
    fn add_event(&self, event: Event) {
        let should_flush = {
            let mut state = self.state.lock();

            // Enforce max queue size
            if state.events.len() >= self.config.max_queue_size {
                // Drop oldest event
                state.events.remove(0);
                tracing::warn!("Event queue full, dropping oldest event");
            }

            state.events.push(event);
            state.events.len() >= self.config.batch_size
        };

        // Trigger flush if batch size reached
        if should_flush {
            if let Some(ref tx) = self.flush_tx {
                let _ = tx.try_send(());
            }
        }
    }

    /// Flush pending events immediately.
    pub async fn flush(&self) -> Result<()> {
        if let Some(ref tx) = self.flush_tx {
            tx.send(())
                .await
                .map_err(|_| FlagKitError::new(ErrorCode::EventFlushFailed, "Flush channel closed"))?;
        }
        Ok(())
    }

    /// Get the number of queued events.
    pub fn queue_size(&self) -> usize {
        self.state.lock().events.len()
    }

    /// Get a copy of queued events (for debugging).
    pub fn get_queued_events(&self) -> Vec<Event> {
        self.state.lock().events.clone()
    }

    /// Clear the event queue without sending.
    pub fn clear(&self) {
        let mut state = self.state.lock();
        state.events.clear();
    }

    /// Stop the event queue.
    ///
    /// This will flush remaining events before stopping.
    pub async fn stop(&mut self) {
        self.is_running.store(false, Ordering::SeqCst);

        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Check if the event queue is running.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }
}

impl Drop for EventQueue {
    fn drop(&mut self) {
        self.is_running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EventQueueConfig::default();
        assert_eq!(config.batch_size, 10);
        assert_eq!(config.flush_interval, Duration::from_secs(30));
        assert_eq!(config.max_queue_size, 1000);
        assert!(config.enabled);
        assert_eq!(config.sample_rate, 1.0);
    }

    #[test]
    fn test_config_builder() {
        let config = EventQueueConfig::builder()
            .batch_size(20)
            .flush_interval(Duration::from_secs(60))
            .max_queue_size(500)
            .enabled(false)
            .sample_rate(0.5)
            .build();

        assert_eq!(config.batch_size, 20);
        assert_eq!(config.flush_interval, Duration::from_secs(60));
        assert_eq!(config.max_queue_size, 500);
        assert!(!config.enabled);
        assert_eq!(config.sample_rate, 0.5);
    }

    #[test]
    fn test_sample_rate_clamping() {
        let config = EventQueueConfig::builder()
            .sample_rate(1.5)
            .build();
        assert_eq!(config.sample_rate, 1.0);

        let config = EventQueueConfig::builder()
            .sample_rate(-0.5)
            .build();
        assert_eq!(config.sample_rate, 0.0);
    }

    #[test]
    fn test_event_creation() {
        let event = Event::new("purchase")
            .session_id("sess-123")
            .environment_id("env-456")
            .user_id("user-789")
            .with_data("amount", serde_json::json!(99.99))
            .with_data("currency", serde_json::json!("USD"));

        assert_eq!(event.event_type, "purchase");
        assert_eq!(event.session_id, Some("sess-123".to_string()));
        assert_eq!(event.environment_id, Some("env-456".to_string()));
        assert_eq!(event.user_id, Some("user-789".to_string()));
        assert!(event.event_data.is_some());

        let data = event.event_data.unwrap();
        assert_eq!(data.get("amount"), Some(&serde_json::json!(99.99)));
        assert_eq!(data.get("currency"), Some(&serde_json::json!("USD")));
    }

    #[test]
    fn test_queue_basic_operations() {
        let config = EventQueueConfig::builder()
            .batch_size(100) // High batch size to prevent auto-flush
            .build();
        let queue = EventQueue::new(config);

        assert_eq!(queue.queue_size(), 0);

        queue.track("event1", None);
        assert_eq!(queue.queue_size(), 1);

        queue.track("event2", Some(HashMap::new()));
        assert_eq!(queue.queue_size(), 2);

        queue.clear();
        assert_eq!(queue.queue_size(), 0);
    }

    #[test]
    fn test_queue_disabled() {
        let config = EventQueueConfig::builder()
            .enabled(false)
            .build();
        let queue = EventQueue::new(config);

        queue.track("event1", None);
        assert_eq!(queue.queue_size(), 0);
    }

    #[test]
    fn test_queue_max_size() {
        let config = EventQueueConfig::builder()
            .max_queue_size(3)
            .batch_size(100) // Prevent auto-flush
            .build();
        let queue = EventQueue::new(config);

        queue.track("event1", None);
        queue.track("event2", None);
        queue.track("event3", None);
        queue.track("event4", None); // Should drop event1

        assert_eq!(queue.queue_size(), 3);

        let events = queue.get_queued_events();
        assert_eq!(events[0].event_type, "event2");
        assert_eq!(events[1].event_type, "event3");
        assert_eq!(events[2].event_type, "event4");
    }

    #[test]
    fn test_invalid_event_type() {
        let queue = EventQueue::with_defaults();

        // Empty event type
        queue.track("", None);
        assert_eq!(queue.queue_size(), 0);

        // Event type too long
        let long_type = "x".repeat(300);
        queue.track(long_type, None);
        assert_eq!(queue.queue_size(), 0);
    }

    #[test]
    fn test_set_context() {
        let queue = EventQueue::with_defaults();

        queue.set_environment_id("env-123");
        queue.set_session_id("sess-456");
        queue.set_user_id(Some("user-789".to_string()));

        queue.track("test_event", None);

        let events = queue.get_queued_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].environment_id, Some("env-123".to_string()));
        assert_eq!(events[0].session_id, Some("sess-456".to_string()));
        assert_eq!(events[0].user_id, Some("user-789".to_string()));
    }
}
