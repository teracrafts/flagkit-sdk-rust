//! Crash-resilient event persistence using Write-Ahead Logging (WAL).
//!
//! This module provides event persistence to prevent analytics data loss
//! during unexpected process termination. Events are persisted to disk
//! before being queued for sending.
//!
//! # Example
//!
//! ```no_run
//! use flagkit::event_persistence::{EventPersistence, EventPersistenceConfig, PersistedEvent};
//! use std::time::Duration;
//!
//! let config = EventPersistenceConfig {
//!     storage_path: "/var/lib/flagkit/events".into(),
//!     max_events: 10000,
//!     flush_interval: Duration::from_millis(1000),
//!     buffer_size: 100,
//! };
//!
//! let mut persistence = EventPersistence::new(config).unwrap();
//!
//! // Persist an event
//! let event = PersistedEvent::new("custom", None);
//! persistence.persist(&event).unwrap();
//!
//! // Recover events on startup
//! let recovered = persistence.recover().unwrap();
//! ```

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::{ErrorCode, FlagKitError, Result};

/// Default maximum number of persisted events.
pub const DEFAULT_MAX_PERSISTED_EVENTS: usize = 10000;

/// Default buffer size before flushing to disk.
pub const DEFAULT_BUFFER_SIZE: usize = 100;

/// Default flush interval in milliseconds.
pub const DEFAULT_FLUSH_INTERVAL_MS: u64 = 1000;

/// Event status in the persistence layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventStatus {
    /// Event persisted, not yet sent.
    Pending,
    /// Event being sent (in current batch).
    Sending,
    /// Successfully sent to server.
    Sent,
    /// Failed to send after max retries.
    Failed,
}

/// A persisted event with metadata for crash recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedEvent {
    /// Unique event identifier.
    pub id: String,
    /// Event type (e.g., "flag.evaluated", "custom").
    #[serde(rename = "type")]
    pub event_type: String,
    /// Event data payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<HashMap<String, serde_json::Value>>,
    /// Timestamp when the event was created (milliseconds since epoch).
    pub timestamp: u64,
    /// Current status of the event.
    pub status: EventStatus,
    /// Timestamp when the event was sent (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<u64>,
    /// User ID associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Session ID associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Environment ID associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
}

impl PersistedEvent {
    /// Create a new persisted event.
    pub fn new(
        event_type: impl Into<String>,
        data: Option<HashMap<String, serde_json::Value>>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: event_type.into(),
            data,
            timestamp,
            status: EventStatus::Pending,
            sent_at: None,
            user_id: None,
            session_id: None,
            environment_id: None,
        }
    }

    /// Create a persisted event with a specific ID.
    pub fn with_id(
        id: impl Into<String>,
        event_type: impl Into<String>,
        data: Option<HashMap<String, serde_json::Value>>,
    ) -> Self {
        let mut event = Self::new(event_type, data);
        event.id = id.into();
        event
    }

    /// Set the user ID.
    pub fn user_id(mut self, id: impl Into<String>) -> Self {
        self.user_id = Some(id.into());
        self
    }

    /// Set the session ID.
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Set the environment ID.
    pub fn environment_id(mut self, id: impl Into<String>) -> Self {
        self.environment_id = Some(id.into());
        self
    }
}

/// Status update record for marking events as sent/failed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatusUpdate {
    /// Event ID to update.
    id: String,
    /// New status.
    status: EventStatus,
    /// Timestamp of the update.
    #[serde(skip_serializing_if = "Option::is_none")]
    sent_at: Option<u64>,
}

/// Configuration for event persistence.
#[derive(Debug, Clone)]
pub struct EventPersistenceConfig {
    /// Directory path for event storage.
    pub storage_path: PathBuf,
    /// Maximum number of events to persist.
    pub max_events: usize,
    /// Interval between automatic flushes to disk.
    pub flush_interval: Duration,
    /// Number of events to buffer before auto-flushing.
    pub buffer_size: usize,
}

impl Default for EventPersistenceConfig {
    fn default() -> Self {
        Self {
            storage_path: std::env::temp_dir().join("flagkit-events"),
            max_events: DEFAULT_MAX_PERSISTED_EVENTS,
            flush_interval: Duration::from_millis(DEFAULT_FLUSH_INTERVAL_MS),
            buffer_size: DEFAULT_BUFFER_SIZE,
        }
    }
}

impl EventPersistenceConfig {
    /// Create a new configuration with the specified storage path.
    pub fn new(storage_path: impl Into<PathBuf>) -> Self {
        Self {
            storage_path: storage_path.into(),
            ..Default::default()
        }
    }

    /// Set the maximum number of persisted events.
    pub fn max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }

    /// Set the flush interval.
    pub fn flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = interval;
        self
    }

    /// Set the buffer size.
    pub fn buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }
}

/// Crash-resilient event persistence manager.
///
/// Uses Write-Ahead Logging (WAL) pattern where events are persisted to disk
/// before being queued for sending. On crash recovery, unsent events are
/// recovered from the log.
pub struct EventPersistence {
    config: EventPersistenceConfig,
    /// In-memory buffer of events pending flush to disk.
    buffer: Vec<PersistedEvent>,
    /// Current event log file path.
    current_log_file: PathBuf,
    /// Lock file path.
    lock_file_path: PathBuf,
    /// Last flush time.
    last_flush: Instant,
    /// Total event count (for max_events enforcement).
    event_count: usize,
}

impl EventPersistence {
    /// Create a new event persistence manager.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for event persistence
    ///
    /// # Errors
    ///
    /// Returns an error if the storage directory cannot be created.
    pub fn new(config: EventPersistenceConfig) -> Result<Self> {
        // Ensure storage directory exists
        fs::create_dir_all(&config.storage_path).map_err(|e| {
            FlagKitError::with_source(
                ErrorCode::CacheStorageError,
                format!(
                    "Failed to create event storage directory: {}",
                    config.storage_path.display()
                ),
                e,
            )
        })?;

        // Generate current log file name with timestamp and random suffix
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let random_suffix: u32 = rand::random();
        let log_file_name = format!("flagkit-events-{}-{:08x}.jsonl", timestamp, random_suffix);
        let current_log_file = config.storage_path.join(log_file_name);

        let lock_file_path = config.storage_path.join("flagkit-events.lock");

        Ok(Self {
            config,
            buffer: Vec::new(),
            current_log_file,
            lock_file_path,
            last_flush: Instant::now(),
            event_count: 0,
        })
    }

    /// Get the storage path.
    pub fn storage_path(&self) -> &Path {
        &self.config.storage_path
    }

    /// Get the current log file path.
    pub fn current_log_file(&self) -> &Path {
        &self.current_log_file
    }

    /// Persist an event to the buffer.
    ///
    /// Events are buffered and flushed to disk periodically or when
    /// the buffer is full.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to persist
    ///
    /// # Errors
    ///
    /// Returns an error if the flush fails.
    pub fn persist(&mut self, event: &PersistedEvent) -> Result<()> {
        // Check if we've hit the max events limit
        if self.event_count >= self.config.max_events {
            tracing::warn!(
                "Event persistence at max capacity ({}), dropping oldest events",
                self.config.max_events
            );
            // Clean up old sent events to make room
            self.cleanup()?;
        }

        self.buffer.push(event.clone());
        self.event_count += 1;

        // Flush if buffer is full or flush interval has elapsed
        let should_flush = self.buffer.len() >= self.config.buffer_size
            || self.last_flush.elapsed() >= self.config.flush_interval;

        if should_flush {
            self.flush()?;
        }

        Ok(())
    }

    /// Flush buffered events to disk.
    ///
    /// This method acquires a file lock, writes all buffered events
    /// to the log file, and ensures data is synced to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file operation fails.
    pub fn flush(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        // Acquire file lock
        let lock_file = self.acquire_lock()?;

        // Open or create the log file in append mode
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.current_log_file)
            .map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheWriteError,
                    format!("Failed to open event log file: {}", self.current_log_file.display()),
                    e,
                )
            })?;

        // Write each event as a JSON line
        for event in &self.buffer {
            let line = serde_json::to_string(event).map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheWriteError,
                    "Failed to serialize event",
                    e,
                )
            })?;
            writeln!(file, "{}", line).map_err(|e| {
                FlagKitError::with_source(ErrorCode::CacheWriteError, "Failed to write event", e)
            })?;
        }

        // Sync to disk
        file.sync_all().map_err(|e| {
            FlagKitError::with_source(ErrorCode::CacheWriteError, "Failed to sync event log", e)
        })?;

        // Clear buffer and update last flush time
        self.buffer.clear();
        self.last_flush = Instant::now();

        // Release lock
        drop(lock_file);

        tracing::debug!("Flushed events to disk: {}", self.current_log_file.display());

        Ok(())
    }

    /// Mark events as sent.
    ///
    /// This updates the status of the specified events in the log file.
    ///
    /// # Arguments
    ///
    /// * `event_ids` - IDs of events to mark as sent
    ///
    /// # Errors
    ///
    /// Returns an error if the file operation fails.
    pub fn mark_sent(&mut self, event_ids: &[String]) -> Result<()> {
        if event_ids.is_empty() {
            return Ok(());
        }

        let sent_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Acquire file lock
        let lock_file = self.acquire_lock()?;

        // Append status updates to the log file
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.current_log_file)
            .map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheWriteError,
                    "Failed to open event log for status update",
                    e,
                )
            })?;

        for id in event_ids {
            let update = StatusUpdate {
                id: id.clone(),
                status: EventStatus::Sent,
                sent_at: Some(sent_at),
            };
            let line = serde_json::to_string(&update).map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheWriteError,
                    "Failed to serialize status update",
                    e,
                )
            })?;
            writeln!(file, "{}", line).map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheWriteError,
                    "Failed to write status update",
                    e,
                )
            })?;
        }

        file.sync_all().map_err(|e| {
            FlagKitError::with_source(
                ErrorCode::CacheWriteError,
                "Failed to sync status updates",
                e,
            )
        })?;

        // Decrement event count for sent events
        self.event_count = self.event_count.saturating_sub(event_ids.len());

        drop(lock_file);

        tracing::debug!("Marked {} events as sent", event_ids.len());

        Ok(())
    }

    /// Mark events as failed.
    ///
    /// # Arguments
    ///
    /// * `event_ids` - IDs of events to mark as failed
    ///
    /// # Errors
    ///
    /// Returns an error if the file operation fails.
    pub fn mark_failed(&mut self, event_ids: &[String]) -> Result<()> {
        if event_ids.is_empty() {
            return Ok(());
        }

        let lock_file = self.acquire_lock()?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.current_log_file)
            .map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheWriteError,
                    "Failed to open event log for status update",
                    e,
                )
            })?;

        for id in event_ids {
            let update = StatusUpdate {
                id: id.clone(),
                status: EventStatus::Failed,
                sent_at: None,
            };
            let line = serde_json::to_string(&update).map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheWriteError,
                    "Failed to serialize status update",
                    e,
                )
            })?;
            writeln!(file, "{}", line).map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheWriteError,
                    "Failed to write status update",
                    e,
                )
            })?;
        }

        file.sync_all().map_err(|e| {
            FlagKitError::with_source(
                ErrorCode::CacheWriteError,
                "Failed to sync status updates",
                e,
            )
        })?;

        drop(lock_file);

        tracing::debug!("Marked {} events as failed", event_ids.len());

        Ok(())
    }

    /// Recover pending events from disk.
    ///
    /// This reads all event log files and returns events that are
    /// in `pending` or `sending` status (sending = crashed mid-send).
    ///
    /// # Returns
    ///
    /// A vector of events that need to be re-sent.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the log files fails.
    pub fn recover(&mut self) -> Result<Vec<PersistedEvent>> {
        // Flush any buffered events first
        self.flush()?;

        let lock_file = self.acquire_lock()?;

        let mut events: HashMap<String, PersistedEvent> = HashMap::new();

        // Read all event log files in the storage directory
        let entries = fs::read_dir(&self.config.storage_path).map_err(|e| {
            FlagKitError::with_source(
                ErrorCode::CacheReadError,
                "Failed to read event storage directory",
                e,
            )
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "jsonl") {
                self.read_log_file(&path, &mut events)?;
            }
        }

        drop(lock_file);

        // Filter for pending and sending events (sending = crashed mid-send)
        let recovered: Vec<PersistedEvent> = events
            .into_values()
            .filter(|e| matches!(e.status, EventStatus::Pending | EventStatus::Sending))
            .collect();

        self.event_count = recovered.len();

        tracing::info!("Recovered {} pending events from disk", recovered.len());

        Ok(recovered)
    }

    /// Clean up old sent/failed events from disk.
    ///
    /// This compacts event log files by removing entries that have been
    /// successfully sent or have failed permanently.
    ///
    /// # Errors
    ///
    /// Returns an error if the cleanup operation fails.
    pub fn cleanup(&mut self) -> Result<()> {
        let lock_file = self.acquire_lock()?;

        let mut events: HashMap<String, PersistedEvent> = HashMap::new();

        // Read all event log files
        let entries = fs::read_dir(&self.config.storage_path).map_err(|e| {
            FlagKitError::with_source(
                ErrorCode::CacheReadError,
                "Failed to read event storage directory",
                e,
            )
        })?;

        let mut log_files: Vec<PathBuf> = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "jsonl") {
                log_files.push(path.clone());
                self.read_log_file(&path, &mut events)?;
            }
        }

        // Keep only pending events
        let pending_events: Vec<PersistedEvent> = events
            .into_values()
            .filter(|e| matches!(e.status, EventStatus::Pending | EventStatus::Sending))
            .collect();

        // Delete old log files
        for log_file in &log_files {
            if log_file != &self.current_log_file {
                if let Err(e) = fs::remove_file(log_file) {
                    tracing::warn!("Failed to remove old log file {:?}: {}", log_file, e);
                }
            }
        }

        // Rewrite current log file with only pending events
        if !pending_events.is_empty() {
            let mut file = File::create(&self.current_log_file).map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheWriteError,
                    "Failed to create compacted log file",
                    e,
                )
            })?;

            for event in &pending_events {
                let line = serde_json::to_string(event).map_err(|e| {
                    FlagKitError::with_source(
                        ErrorCode::CacheWriteError,
                        "Failed to serialize event during cleanup",
                        e,
                    )
                })?;
                writeln!(file, "{}", line).map_err(|e| {
                    FlagKitError::with_source(
                        ErrorCode::CacheWriteError,
                        "Failed to write event during cleanup",
                        e,
                    )
                })?;
            }

            file.sync_all().map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheWriteError,
                    "Failed to sync compacted log file",
                    e,
                )
            })?;
        } else {
            // No pending events, truncate the current log file
            File::create(&self.current_log_file).map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheWriteError,
                    "Failed to truncate log file",
                    e,
                )
            })?;
        }

        self.event_count = pending_events.len();

        drop(lock_file);

        tracing::debug!(
            "Cleanup complete, {} pending events remain",
            pending_events.len()
        );

        Ok(())
    }

    /// Get the number of buffered events.
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Get the total event count.
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// Acquire the file lock.
    fn acquire_lock(&self) -> Result<File> {
        let lock_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&self.lock_file_path)
            .map_err(|e| {
                FlagKitError::with_source(
                    ErrorCode::CacheStorageError,
                    "Failed to open lock file",
                    e,
                )
            })?;

        lock_file.lock_exclusive().map_err(|e| {
            FlagKitError::with_source(ErrorCode::CacheStorageError, "Failed to acquire file lock", e)
        })?;

        Ok(lock_file)
    }

    /// Read a log file and merge events into the map.
    fn read_log_file(
        &self,
        path: &Path,
        events: &mut HashMap<String, PersistedEvent>,
    ) -> Result<()> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(FlagKitError::with_source(
                    ErrorCode::CacheReadError,
                    format!("Failed to open event log file: {}", path.display()),
                    e,
                ));
            }
        };

        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!("Failed to read line from log file: {}", e);
                    continue;
                }
            };

            if line.trim().is_empty() {
                continue;
            }

            // Try to parse as a full event first
            if let Ok(event) = serde_json::from_str::<PersistedEvent>(&line) {
                events.insert(event.id.clone(), event);
                continue;
            }

            // Try to parse as a status update
            if let Ok(update) = serde_json::from_str::<StatusUpdate>(&line) {
                if let Some(event) = events.get_mut(&update.id) {
                    event.status = update.status;
                    event.sent_at = update.sent_at;
                }
            }
        }

        Ok(())
    }
}

impl Drop for EventPersistence {
    fn drop(&mut self) {
        // Try to flush remaining events on drop
        if let Err(e) = self.flush() {
            tracing::warn!("Failed to flush events on drop: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_persistence() -> (EventPersistence, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = EventPersistenceConfig::new(temp_dir.path())
            .buffer_size(2)
            .flush_interval(Duration::from_secs(60));
        let persistence = EventPersistence::new(config).unwrap();
        (persistence, temp_dir)
    }

    #[test]
    fn test_persist_and_flush() {
        let (mut persistence, _temp_dir) = create_test_persistence();

        let event1 = PersistedEvent::new("test_event", None);
        let event2 = PersistedEvent::new("test_event2", None);

        persistence.persist(&event1).unwrap();
        assert_eq!(persistence.buffer_len(), 1);

        // Second event should trigger flush (buffer_size = 2)
        persistence.persist(&event2).unwrap();
        assert_eq!(persistence.buffer_len(), 0);
    }

    #[test]
    fn test_recover_pending_events() {
        let temp_dir = TempDir::new().unwrap();
        let config = EventPersistenceConfig::new(temp_dir.path()).buffer_size(1);

        // Create and persist events
        {
            let mut persistence = EventPersistence::new(config.clone()).unwrap();
            let event1 = PersistedEvent::new("event1", None);
            let event2 = PersistedEvent::new("event2", None);
            persistence.persist(&event1).unwrap();
            persistence.persist(&event2).unwrap();
            persistence.flush().unwrap();
        }

        // Recover events with a new persistence instance
        {
            let mut persistence = EventPersistence::new(config).unwrap();
            let recovered = persistence.recover().unwrap();
            assert_eq!(recovered.len(), 2);
        }
    }

    #[test]
    fn test_mark_sent() {
        let temp_dir = TempDir::new().unwrap();
        let config = EventPersistenceConfig::new(temp_dir.path()).buffer_size(1);

        let event_id: String;

        // Create and persist event
        {
            let mut persistence = EventPersistence::new(config.clone()).unwrap();
            let event = PersistedEvent::new("test_event", None);
            event_id = event.id.clone();
            persistence.persist(&event).unwrap();
            persistence.flush().unwrap();
            persistence.mark_sent(&[event_id.clone()]).unwrap();
        }

        // Recover - should be empty since event was marked sent
        {
            let mut persistence = EventPersistence::new(config).unwrap();
            let recovered = persistence.recover().unwrap();
            assert_eq!(recovered.len(), 0);
        }
    }

    #[test]
    fn test_cleanup() {
        let temp_dir = TempDir::new().unwrap();
        let config = EventPersistenceConfig::new(temp_dir.path()).buffer_size(1);

        // Create events and mark some as sent
        {
            let mut persistence = EventPersistence::new(config.clone()).unwrap();
            let event1 = PersistedEvent::new("event1", None);
            let event2 = PersistedEvent::new("event2", None);
            let id1 = event1.id.clone();

            persistence.persist(&event1).unwrap();
            persistence.persist(&event2).unwrap();
            persistence.flush().unwrap();
            persistence.mark_sent(&[id1]).unwrap();
            persistence.cleanup().unwrap();

            assert_eq!(persistence.event_count(), 1);
        }
    }

    #[test]
    fn test_event_with_data() {
        let (mut persistence, _temp_dir) = create_test_persistence();

        let mut data = HashMap::new();
        data.insert("key".to_string(), serde_json::json!("value"));
        data.insert("number".to_string(), serde_json::json!(42));

        let event = PersistedEvent::new("custom_event", Some(data))
            .user_id("user-123")
            .session_id("sess-456")
            .environment_id("env-789");

        persistence.persist(&event).unwrap();
        persistence.flush().unwrap();

        let recovered = persistence.recover().unwrap();
        assert_eq!(recovered.len(), 1);

        let recovered_event = &recovered[0];
        assert_eq!(recovered_event.user_id, Some("user-123".to_string()));
        assert_eq!(recovered_event.session_id, Some("sess-456".to_string()));
        assert_eq!(recovered_event.environment_id, Some("env-789".to_string()));
        assert!(recovered_event.data.is_some());
    }

    #[test]
    fn test_status_transitions() {
        assert_eq!(
            serde_json::to_string(&EventStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&EventStatus::Sending).unwrap(),
            "\"sending\""
        );
        assert_eq!(
            serde_json::to_string(&EventStatus::Sent).unwrap(),
            "\"sent\""
        );
        assert_eq!(
            serde_json::to_string(&EventStatus::Failed).unwrap(),
            "\"failed\""
        );
    }

    #[test]
    fn test_config_defaults() {
        let config = EventPersistenceConfig::default();
        assert_eq!(config.max_events, DEFAULT_MAX_PERSISTED_EVENTS);
        assert_eq!(config.buffer_size, DEFAULT_BUFFER_SIZE);
        assert_eq!(
            config.flush_interval,
            Duration::from_millis(DEFAULT_FLUSH_INTERVAL_MS)
        );
    }
}
