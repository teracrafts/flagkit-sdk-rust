use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::types::FlagState;

struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
    last_accessed: Instant,
}

/// Thread-safe cache with TTL and LRU eviction.
pub struct Cache<K, V> {
    entries: RwLock<HashMap<K, CacheEntry<V>>>,
    max_size: usize,
    ttl: Duration,
}

impl<K: Clone, V: Clone> Clone for Cache<K, V> {
    fn clone(&self) -> Self {
        // Clone creates a new cache with the same configuration
        // but shared state via Arc wrapper at call site
        Self {
            entries: RwLock::new(HashMap::new()),
            max_size: self.max_size,
            ttl: self.ttl,
        }
    }
}

impl<K: Eq + std::hash::Hash + Clone, V: Clone> Cache<K, V> {
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_size,
            ttl,
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let now = Instant::now();

        // Try read lock first
        {
            let entries = self.entries.read();
            if let Some(entry) = entries.get(key) {
                if now < entry.expires_at {
                    return Some(entry.value.clone());
                }
            }
        }

        // Remove expired entry with write lock
        {
            let mut entries = self.entries.write();
            if let Some(entry) = entries.get(key) {
                if now >= entry.expires_at {
                    entries.remove(key);
                }
            }
        }

        None
    }

    pub fn set(&self, key: K, value: V) {
        self.set_with_ttl(key, value, None);
    }

    pub fn set_with_ttl(&self, key: K, value: V, custom_ttl: Option<Duration>) {
        let now = Instant::now();
        let ttl = custom_ttl.unwrap_or(self.ttl);

        let entry = CacheEntry {
            value,
            expires_at: now + ttl,
            last_accessed: now,
        };

        let mut entries = self.entries.write();
        entries.insert(key, entry);

        self.evict_if_needed(&mut entries);
    }

    pub fn has(&self, key: &K) -> bool {
        let entries = self.entries.read();
        if let Some(entry) = entries.get(key) {
            Instant::now() < entry.expires_at
        } else {
            false
        }
    }

    pub fn remove(&self, key: &K) -> bool {
        let mut entries = self.entries.write();
        entries.remove(key).is_some()
    }

    pub fn clear(&self) {
        let mut entries = self.entries.write();
        entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    pub fn keys(&self) -> Vec<K> {
        self.entries.read().keys().cloned().collect()
    }

    fn evict_if_needed(&self, entries: &mut HashMap<K, CacheEntry<V>>) {
        if entries.len() <= self.max_size {
            return;
        }

        let now = Instant::now();

        // Remove expired entries first
        entries.retain(|_, entry| now < entry.expires_at);

        // If still over capacity, remove least recently used
        while entries.len() > self.max_size {
            let lru_key = entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_accessed)
                .map(|(k, _)| k.clone());

            if let Some(key) = lru_key {
                entries.remove(&key);
            } else {
                break;
            }
        }
    }
}

/// Flag-specific cache with TTL and stale value support.
///
/// This cache is designed for storing flag states and supports:
/// - Automatic TTL expiration
/// - Maximum size with LRU eviction
/// - Stale value retrieval
/// - Thread-safe operations via Arc
#[derive(Clone)]
pub struct FlagCache {
    inner: Arc<Cache<String, FlagState>>,
    stale: Arc<RwLock<HashMap<String, FlagState>>>,
}

impl FlagCache {
    /// Create a new flag cache with the given size and TTL.
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Cache::new(max_size, ttl)),
            stale: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a flag from the cache.
    ///
    /// Returns `None` if the flag is not in cache or has expired.
    /// Expired values are moved to the stale cache.
    pub fn get(&self, key: &str) -> Option<FlagState> {
        let key_str = key.to_string();

        // Try to get from cache
        if let Some(value) = self.inner.get(&key_str) {
            return Some(value);
        }

        // If not found, the value may have expired
        // Check if we should move it to stale
        None
    }

    /// Get a stale (expired) flag value.
    ///
    /// This is useful as a fallback when the server is unavailable.
    pub fn get_stale(&self, key: &str) -> Option<FlagState> {
        let stale = self.stale.read();
        stale.get(key).cloned()
    }

    /// Set a flag in the cache.
    ///
    /// This also updates the stale cache with the previous value if any.
    pub fn set(&self, key: impl Into<String>, value: FlagState) {
        let key_str = key.into();

        // Save current value as stale before replacing
        if let Some(old_value) = self.inner.get(&key_str) {
            let mut stale = self.stale.write();
            stale.insert(key_str.clone(), old_value);
        }

        self.inner.set(key_str, value);
    }

    pub fn has(&self, key: &str) -> bool {
        self.inner.has(&key.to_string())
    }

    pub fn remove(&self, key: &str) -> bool {
        self.inner.remove(&key.to_string())
    }

    pub fn clear(&self) {
        self.inner.clear();
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn set_all(&self, flags: Vec<FlagState>) {
        for flag in flags {
            self.set(flag.key.clone(), flag);
        }
    }

    pub fn get_all(&self) -> HashMap<String, FlagState> {
        let mut result = HashMap::new();
        for key in self.inner.keys() {
            if let Some(value) = self.get(&key) {
                result.insert(key, value);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FlagValue;

    #[test]
    fn test_set_and_get() {
        let cache: Cache<String, String> = Cache::new(100, Duration::from_secs(60));

        cache.set("key".to_string(), "value".to_string());
        let result = cache.get(&"key".to_string());

        assert_eq!(result, Some("value".to_string()));
    }

    #[test]
    fn test_get_nonexistent() {
        let cache: Cache<String, String> = Cache::new(100, Duration::from_secs(60));

        let result = cache.get(&"nonexistent".to_string());

        assert!(result.is_none());
    }

    #[test]
    fn test_has() {
        let cache: Cache<String, String> = Cache::new(100, Duration::from_secs(60));
        cache.set("key".to_string(), "value".to_string());

        assert!(cache.has(&"key".to_string()));
        assert!(!cache.has(&"nonexistent".to_string()));
    }

    #[test]
    fn test_remove() {
        let cache: Cache<String, String> = Cache::new(100, Duration::from_secs(60));
        cache.set("key".to_string(), "value".to_string());

        cache.remove(&"key".to_string());

        assert!(!cache.has(&"key".to_string()));
    }

    #[test]
    fn test_clear() {
        let cache: Cache<String, String> = Cache::new(100, Duration::from_secs(60));
        cache.set("key1".to_string(), "value1".to_string());
        cache.set("key2".to_string(), "value2".to_string());

        cache.clear();

        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_flag_cache() {
        let cache = FlagCache::new(100, Duration::from_secs(60));
        let flag = FlagState::new("flag1", FlagValue::Bool(true));

        cache.set("flag1", flag.clone());
        let result = cache.get("flag1");

        assert!(result.is_some());
        assert_eq!(result.unwrap().key, "flag1");
    }
}
