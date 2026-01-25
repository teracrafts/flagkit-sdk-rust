//! Integration tests for crash-resilient event persistence.

use flagkit::event_persistence::{
    EventPersistence, EventPersistenceConfig, EventStatus, PersistedEvent,
    DEFAULT_BUFFER_SIZE, DEFAULT_FLUSH_INTERVAL_MS, DEFAULT_MAX_PERSISTED_EVENTS,
};
use std::collections::HashMap;
use std::time::Duration;
use tempfile::TempDir;

/// Helper to create a test persistence instance with a temporary directory.
fn create_test_persistence() -> (EventPersistence, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let config = EventPersistenceConfig::new(temp_dir.path())
        .buffer_size(2)
        .flush_interval(Duration::from_secs(60)); // Long interval to control flushing manually
    let persistence = EventPersistence::new(config).unwrap();
    (persistence, temp_dir)
}

// ============================================================================
// Configuration Tests
// ============================================================================

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

#[test]
fn test_config_builder() {
    let config = EventPersistenceConfig::new("/tmp/test")
        .max_events(5000)
        .buffer_size(50)
        .flush_interval(Duration::from_millis(500));

    assert_eq!(config.max_events, 5000);
    assert_eq!(config.buffer_size, 50);
    assert_eq!(config.flush_interval, Duration::from_millis(500));
}

// ============================================================================
// Persistence Tests
// ============================================================================

#[test]
fn test_persist_single_event() {
    let (mut persistence, _temp_dir) = create_test_persistence();

    let event = PersistedEvent::new("test_event", None);
    persistence.persist(&event).unwrap();

    assert_eq!(persistence.buffer_len(), 1);
}

#[test]
fn test_persist_triggers_flush_at_buffer_size() {
    let (mut persistence, _temp_dir) = create_test_persistence();

    let event1 = PersistedEvent::new("event1", None);
    let event2 = PersistedEvent::new("event2", None);

    persistence.persist(&event1).unwrap();
    assert_eq!(persistence.buffer_len(), 1);

    // Second event should trigger flush since buffer_size = 2
    persistence.persist(&event2).unwrap();
    assert_eq!(persistence.buffer_len(), 0);
}

#[test]
fn test_manual_flush() {
    let (mut persistence, _temp_dir) = create_test_persistence();

    let event = PersistedEvent::new("test_event", None);
    persistence.persist(&event).unwrap();
    assert_eq!(persistence.buffer_len(), 1);

    persistence.flush().unwrap();
    assert_eq!(persistence.buffer_len(), 0);
}

#[test]
fn test_persist_event_with_data() {
    let (mut persistence, _temp_dir) = create_test_persistence();

    let mut data = HashMap::new();
    data.insert("key".to_string(), serde_json::json!("value"));
    data.insert("number".to_string(), serde_json::json!(42));
    data.insert("nested".to_string(), serde_json::json!({"a": 1, "b": 2}));

    let event = PersistedEvent::new("custom_event", Some(data))
        .user_id("user-123")
        .session_id("sess-456")
        .environment_id("env-789");

    persistence.persist(&event).unwrap();
    persistence.flush().unwrap();

    let recovered = persistence.recover().unwrap();
    assert_eq!(recovered.len(), 1);

    let recovered_event = &recovered[0];
    assert_eq!(recovered_event.event_type, "custom_event");
    assert_eq!(recovered_event.user_id, Some("user-123".to_string()));
    assert_eq!(recovered_event.session_id, Some("sess-456".to_string()));
    assert_eq!(recovered_event.environment_id, Some("env-789".to_string()));
    assert!(recovered_event.data.is_some());

    let data = recovered_event.data.as_ref().unwrap();
    assert_eq!(data.get("key"), Some(&serde_json::json!("value")));
    assert_eq!(data.get("number"), Some(&serde_json::json!(42)));
}

// ============================================================================
// Recovery Tests
// ============================================================================

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

    // Recover events with a new persistence instance (simulates restart)
    {
        let mut persistence = EventPersistence::new(config).unwrap();
        let recovered = persistence.recover().unwrap();
        assert_eq!(recovered.len(), 2);

        let event_types: Vec<&str> = recovered.iter().map(|e| e.event_type.as_str()).collect();
        assert!(event_types.contains(&"event1"));
        assert!(event_types.contains(&"event2"));
    }
}

#[test]
fn test_recover_after_mark_sent() {
    let temp_dir = TempDir::new().unwrap();
    let config = EventPersistenceConfig::new(temp_dir.path()).buffer_size(1);

    let event_id: String;

    // Create, persist, and mark event as sent
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
fn test_recover_partial_sent() {
    let temp_dir = TempDir::new().unwrap();
    let config = EventPersistenceConfig::new(temp_dir.path()).buffer_size(1);

    let event1_id: String;

    // Create multiple events and mark only one as sent
    {
        let mut persistence = EventPersistence::new(config.clone()).unwrap();
        let event1 = PersistedEvent::new("event1", None);
        let event2 = PersistedEvent::new("event2", None);
        event1_id = event1.id.clone();

        persistence.persist(&event1).unwrap();
        persistence.persist(&event2).unwrap();
        persistence.flush().unwrap();
        persistence.mark_sent(&[event1_id]).unwrap();
    }

    // Recover - should only have event2
    {
        let mut persistence = EventPersistence::new(config).unwrap();
        let recovered = persistence.recover().unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].event_type, "event2");
    }
}

// ============================================================================
// Status Tests
// ============================================================================

#[test]
fn test_event_status_serialization() {
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
fn test_mark_failed() {
    let temp_dir = TempDir::new().unwrap();
    let config = EventPersistenceConfig::new(temp_dir.path()).buffer_size(1);

    let event_id: String;

    // Create, persist, and mark event as failed
    {
        let mut persistence = EventPersistence::new(config.clone()).unwrap();
        let event = PersistedEvent::new("test_event", None);
        event_id = event.id.clone();
        persistence.persist(&event).unwrap();
        persistence.flush().unwrap();
        persistence.mark_failed(&[event_id]).unwrap();
    }

    // Recover - should be empty since failed events are not recovered
    {
        let mut persistence = EventPersistence::new(config).unwrap();
        let recovered = persistence.recover().unwrap();
        assert_eq!(recovered.len(), 0);
    }
}

// ============================================================================
// Cleanup Tests
// ============================================================================

#[test]
fn test_cleanup_removes_sent_events() {
    let temp_dir = TempDir::new().unwrap();
    let config = EventPersistenceConfig::new(temp_dir.path()).buffer_size(1);

    {
        let mut persistence = EventPersistence::new(config.clone()).unwrap();

        // Create events
        let event1 = PersistedEvent::new("event1", None);
        let event2 = PersistedEvent::new("event2", None);
        let id1 = event1.id.clone();

        persistence.persist(&event1).unwrap();
        persistence.persist(&event2).unwrap();
        persistence.flush().unwrap();

        // Mark event1 as sent
        persistence.mark_sent(&[id1]).unwrap();

        // Cleanup
        persistence.cleanup().unwrap();

        // Should only have event2
        assert_eq!(persistence.event_count(), 1);
    }

    // Verify after restart
    {
        let mut persistence = EventPersistence::new(config).unwrap();
        let recovered = persistence.recover().unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].event_type, "event2");
    }
}

#[test]
fn test_cleanup_compacts_files() {
    let temp_dir = TempDir::new().unwrap();
    let config = EventPersistenceConfig::new(temp_dir.path()).buffer_size(1);

    {
        let mut persistence = EventPersistence::new(config.clone()).unwrap();

        // Create many events
        for i in 0..10 {
            let event = PersistedEvent::new(format!("event{}", i), None);
            persistence.persist(&event).unwrap();
        }
        persistence.flush().unwrap();

        // Mark all as sent
        let events = persistence.recover().unwrap();
        let ids: Vec<String> = events.iter().map(|e| e.id.clone()).collect();
        persistence.mark_sent(&ids).unwrap();

        // Cleanup
        persistence.cleanup().unwrap();

        // No events should remain
        assert_eq!(persistence.event_count(), 0);
    }
}

// ============================================================================
// File Locking Tests
// ============================================================================

#[test]
fn test_file_locking_creates_lock_file() {
    let temp_dir = TempDir::new().unwrap();
    let config = EventPersistenceConfig::new(temp_dir.path()).buffer_size(1);

    let mut persistence = EventPersistence::new(config).unwrap();

    let event = PersistedEvent::new("test_event", None);
    persistence.persist(&event).unwrap();
    persistence.flush().unwrap();

    // Lock file should exist
    let lock_file = temp_dir.path().join("flagkit-events.lock");
    assert!(lock_file.exists());
}

#[test]
fn test_storage_directory_created() {
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().join("nested").join("dir").join("events");

    let config = EventPersistenceConfig::new(&storage_path);
    let _persistence = EventPersistence::new(config).unwrap();

    assert!(storage_path.exists());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_flush() {
    let (mut persistence, _temp_dir) = create_test_persistence();

    // Flushing an empty buffer should not error
    persistence.flush().unwrap();
}

#[test]
fn test_mark_sent_empty() {
    let (mut persistence, _temp_dir) = create_test_persistence();

    // Marking empty list should not error
    persistence.mark_sent(&[]).unwrap();
}

#[test]
fn test_recover_empty() {
    let (mut persistence, _temp_dir) = create_test_persistence();

    // Recovering from empty storage should return empty vec
    let recovered = persistence.recover().unwrap();
    assert!(recovered.is_empty());
}

#[test]
fn test_cleanup_empty() {
    let (mut persistence, _temp_dir) = create_test_persistence();

    // Cleaning up empty storage should not error
    persistence.cleanup().unwrap();
}

#[test]
fn test_persisted_event_with_id() {
    let event = PersistedEvent::with_id("custom-id", "test_event", None);
    assert_eq!(event.id, "custom-id");
    assert_eq!(event.event_type, "test_event");
    assert_eq!(event.status, EventStatus::Pending);
}

#[test]
fn test_drop_flushes_buffer() {
    let temp_dir = TempDir::new().unwrap();
    let config = EventPersistenceConfig::new(temp_dir.path()).buffer_size(10); // Large buffer

    // Create persistence and add events without explicit flush
    {
        let mut persistence = EventPersistence::new(config.clone()).unwrap();
        let event = PersistedEvent::new("test_event", None);
        persistence.persist(&event).unwrap();
        // Don't call flush - rely on Drop
    }

    // Recover and verify event was persisted on drop
    {
        let mut persistence = EventPersistence::new(config).unwrap();
        let recovered = persistence.recover().unwrap();
        assert_eq!(recovered.len(), 1);
    }
}

// ============================================================================
// Event Queue Integration Tests
// ============================================================================

#[test]
fn test_event_queue_with_persistence() {
    use flagkit::core::{EventQueue, EventQueueConfig};

    let temp_dir = TempDir::new().unwrap();
    let config = EventQueueConfig::builder()
        .batch_size(100) // Large to prevent auto-flush
        .persist_events(true)
        .event_storage_path(temp_dir.path())
        .build();

    let queue = EventQueue::new(config);
    assert!(queue.is_persistence_enabled());

    // Track an event
    queue.track("test_event", None);

    // Event should be in the queue
    assert_eq!(queue.queue_size(), 1);
}

#[test]
fn test_event_queue_persistence_disabled() {
    use flagkit::core::{EventQueue, EventQueueConfig};

    let config = EventQueueConfig::builder()
        .persist_events(false)
        .build();

    let queue = EventQueue::new(config);
    assert!(!queue.is_persistence_enabled());
}

#[test]
fn test_event_queue_recover_events() {
    use flagkit::core::{EventQueue, EventQueueConfig};

    let temp_dir = TempDir::new().unwrap();

    // First queue: persist some events
    {
        let config = EventQueueConfig::builder()
            .batch_size(100)
            .persist_events(true)
            .event_storage_path(temp_dir.path())
            .build();

        let queue = EventQueue::new(config);
        queue.track("event1", None);
        queue.track("event2", None);

        // Manually flush persistence
        if let Some(p) = queue.persistence() {
            p.lock().flush().unwrap();
        }
    }

    // Second queue: recover events
    {
        let config = EventQueueConfig::builder()
            .batch_size(100)
            .persist_events(true)
            .event_storage_path(temp_dir.path())
            .build();

        let queue = EventQueue::new(config);
        let recovered = queue.recover_events().unwrap();

        // Should have recovered the 2 events
        assert_eq!(recovered, 2);
        assert_eq!(queue.queue_size(), 2);
    }
}
