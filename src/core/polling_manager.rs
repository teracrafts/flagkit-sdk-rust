//! Polling manager for background flag updates.
//!
//! This module provides a polling manager that periodically fetches
//! flag updates from the server with configurable interval, jitter,
//! and exponential backoff on errors.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval_at, Instant};

/// Default polling interval in seconds.
pub const DEFAULT_POLLING_INTERVAL_SECS: u64 = 30;

/// Default jitter in milliseconds.
pub const DEFAULT_JITTER_MS: u64 = 1000;

/// Default backoff multiplier.
pub const DEFAULT_BACKOFF_MULTIPLIER: f64 = 2.0;

/// Default maximum interval in seconds.
pub const DEFAULT_MAX_INTERVAL_SECS: u64 = 300; // 5 minutes

/// Configuration for the polling manager.
#[derive(Debug, Clone)]
pub struct PollingConfig {
    /// Polling interval. Default: 30 seconds
    pub interval: Duration,

    /// Maximum jitter added to interval. Default: 1000ms
    pub jitter_ms: u64,

    /// Backoff multiplier on errors. Default: 2.0
    pub backoff_multiplier: f64,

    /// Maximum interval after backoff. Default: 5 minutes
    pub max_interval: Duration,
}

impl Default for PollingConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(DEFAULT_POLLING_INTERVAL_SECS),
            jitter_ms: DEFAULT_JITTER_MS,
            backoff_multiplier: DEFAULT_BACKOFF_MULTIPLIER,
            max_interval: Duration::from_secs(DEFAULT_MAX_INTERVAL_SECS),
        }
    }
}

impl PollingConfig {
    /// Create a new configuration with the specified interval.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            ..Default::default()
        }
    }

    /// Create a configuration builder.
    pub fn builder() -> PollingConfigBuilder {
        PollingConfigBuilder::default()
    }
}

/// Builder for PollingConfig.
#[derive(Debug, Default)]
pub struct PollingConfigBuilder {
    interval: Option<Duration>,
    jitter_ms: Option<u64>,
    backoff_multiplier: Option<f64>,
    max_interval: Option<Duration>,
}

impl PollingConfigBuilder {
    /// Set the polling interval.
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = Some(interval);
        self
    }

    /// Set the polling interval in seconds.
    pub fn interval_secs(mut self, secs: u64) -> Self {
        self.interval = Some(Duration::from_secs(secs));
        self
    }

    /// Set the jitter in milliseconds.
    pub fn jitter_ms(mut self, jitter: u64) -> Self {
        self.jitter_ms = Some(jitter);
        self
    }

    /// Set the backoff multiplier.
    pub fn backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = Some(multiplier);
        self
    }

    /// Set the maximum interval.
    pub fn max_interval(mut self, max: Duration) -> Self {
        self.max_interval = Some(max);
        self
    }

    /// Set the maximum interval in seconds.
    pub fn max_interval_secs(mut self, secs: u64) -> Self {
        self.max_interval = Some(Duration::from_secs(secs));
        self
    }

    /// Build the configuration.
    pub fn build(self) -> PollingConfig {
        PollingConfig {
            interval: self
                .interval
                .unwrap_or(Duration::from_secs(DEFAULT_POLLING_INTERVAL_SECS)),
            jitter_ms: self.jitter_ms.unwrap_or(DEFAULT_JITTER_MS),
            backoff_multiplier: self.backoff_multiplier.unwrap_or(DEFAULT_BACKOFF_MULTIPLIER),
            max_interval: self
                .max_interval
                .unwrap_or(Duration::from_secs(DEFAULT_MAX_INTERVAL_SECS)),
        }
    }
}

/// Callback type for poll operations.
pub type PollCallback =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send>> + Send + Sync>;

/// Manages background polling for flag updates.
///
/// Features:
/// - Configurable polling interval
/// - Jitter to prevent thundering herd
/// - Exponential backoff on errors
/// - Graceful shutdown
pub struct PollingManager {
    config: PollingConfig,
    current_interval: Arc<parking_lot::Mutex<Duration>>,
    consecutive_errors: Arc<AtomicU32>,
    is_running: Arc<AtomicBool>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    poll_now_tx: Option<mpsc::Sender<()>>,
}

impl PollingManager {
    /// Create a new polling manager with the given configuration.
    pub fn new(config: PollingConfig) -> Self {
        let interval = config.interval;
        Self {
            config,
            current_interval: Arc::new(parking_lot::Mutex::new(interval)),
            consecutive_errors: Arc::new(AtomicU32::new(0)),
            is_running: Arc::new(AtomicBool::new(false)),
            shutdown_tx: None,
            poll_now_tx: None,
        }
    }

    /// Create a new polling manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PollingConfig::default())
    }

    /// Start the polling manager with the given callback.
    ///
    /// The callback is called on each poll tick and should return
    /// `Ok(())` on success or `Err(())` on failure.
    pub fn start(&mut self, on_poll: PollCallback) {
        if self.is_running.load(Ordering::SeqCst) {
            return;
        }

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let (poll_now_tx, mut poll_now_rx) = mpsc::channel::<()>(10);
        self.shutdown_tx = Some(shutdown_tx);
        self.poll_now_tx = Some(poll_now_tx);
        self.is_running.store(true, Ordering::SeqCst);

        let config = self.config.clone();
        let current_interval = Arc::clone(&self.current_interval);
        let consecutive_errors = Arc::clone(&self.consecutive_errors);
        let is_running = Arc::clone(&self.is_running);

        tokio::spawn(async move {
            // Start with initial delay
            let initial_delay = Self::calculate_next_delay(&config, *current_interval.lock());
            let start = Instant::now() + initial_delay;
            let mut poll_interval = interval_at(start, config.interval);
            poll_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                let current = *current_interval.lock();

                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::debug!("Polling manager shutting down");
                        break;
                    }
                    _ = poll_now_rx.recv() => {
                        // Immediate poll requested
                        tracing::debug!("Immediate poll requested");
                        Self::execute_poll(
                            &on_poll,
                            &config,
                            &current_interval,
                            &consecutive_errors,
                        ).await;
                    }
                    _ = tokio::time::sleep(current) => {
                        if !is_running.load(Ordering::SeqCst) {
                            break;
                        }

                        Self::execute_poll(
                            &on_poll,
                            &config,
                            &current_interval,
                            &consecutive_errors,
                        ).await;
                    }
                }
            }

            is_running.store(false, Ordering::SeqCst);
        });

        tracing::debug!(
            "Polling manager started with interval {:?}",
            self.config.interval
        );
    }

    /// Execute a single poll.
    async fn execute_poll(
        on_poll: &PollCallback,
        config: &PollingConfig,
        current_interval: &Arc<parking_lot::Mutex<Duration>>,
        consecutive_errors: &Arc<AtomicU32>,
    ) {
        let result = on_poll().await;

        match result {
            Ok(()) => {
                // Reset on success
                consecutive_errors.store(0, Ordering::SeqCst);
                *current_interval.lock() = config.interval;
                tracing::debug!("Poll succeeded, interval reset to {:?}", config.interval);
            }
            Err(()) => {
                // Backoff on error
                let errors = consecutive_errors.fetch_add(1, Ordering::SeqCst) + 1;
                let new_interval = Self::calculate_backoff(config, errors);
                *current_interval.lock() = new_interval;
                tracing::debug!(
                    "Poll failed (consecutive errors: {}), backing off to {:?}",
                    errors,
                    new_interval
                );
            }
        }
    }

    /// Calculate backoff interval based on consecutive errors.
    fn calculate_backoff(config: &PollingConfig, consecutive_errors: u32) -> Duration {
        let base_ms = config.interval.as_millis() as f64;
        let backoff_ms = base_ms * config.backoff_multiplier.powi(consecutive_errors as i32);
        let capped_ms = backoff_ms.min(config.max_interval.as_millis() as f64);
        Duration::from_millis(capped_ms as u64)
    }

    /// Calculate the next delay with jitter.
    fn calculate_next_delay(config: &PollingConfig, interval: Duration) -> Duration {
        let jitter = (rand::random::<f64>() * config.jitter_ms as f64) as u64;
        interval + Duration::from_millis(jitter)
    }

    /// Stop the polling manager.
    pub async fn stop(&mut self) {
        if !self.is_running.load(Ordering::SeqCst) {
            return;
        }

        self.is_running.store(false, Ordering::SeqCst);

        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }

        tracing::debug!("Polling manager stopped");
    }

    /// Trigger an immediate poll.
    ///
    /// This resets the interval timer after polling.
    pub async fn poll_now(&self) {
        if let Some(ref tx) = self.poll_now_tx {
            let _ = tx.send(()).await;
        }
    }

    /// Check if the polling manager is running.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// Check if the polling manager is active.
    pub fn is_active(&self) -> bool {
        self.is_running()
    }

    /// Get the current polling interval.
    pub fn current_interval(&self) -> Duration {
        *self.current_interval.lock()
    }

    /// Get the number of consecutive errors.
    pub fn consecutive_errors(&self) -> u32 {
        self.consecutive_errors.load(Ordering::SeqCst)
    }

    /// Reset the polling manager state.
    ///
    /// Resets the interval to the default and clears the error count.
    pub fn reset(&self) {
        self.consecutive_errors.store(0, Ordering::SeqCst);
        *self.current_interval.lock() = self.config.interval;
        tracing::debug!("Polling manager reset");
    }

    /// Manually record a success (resets backoff).
    pub fn on_success(&self) {
        self.consecutive_errors.store(0, Ordering::SeqCst);
        *self.current_interval.lock() = self.config.interval;
    }

    /// Manually record an error (triggers backoff).
    pub fn on_error(&self) {
        let errors = self.consecutive_errors.fetch_add(1, Ordering::SeqCst) + 1;
        let new_interval = Self::calculate_backoff(&self.config, errors);
        *self.current_interval.lock() = new_interval;
    }
}

impl Drop for PollingManager {
    fn drop(&mut self) {
        self.is_running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PollingConfig::default();
        assert_eq!(config.interval, Duration::from_secs(30));
        assert_eq!(config.jitter_ms, 1000);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert_eq!(config.max_interval, Duration::from_secs(300));
    }

    #[test]
    fn test_config_builder() {
        let config = PollingConfig::builder()
            .interval_secs(60)
            .jitter_ms(500)
            .backoff_multiplier(1.5)
            .max_interval_secs(600)
            .build();

        assert_eq!(config.interval, Duration::from_secs(60));
        assert_eq!(config.jitter_ms, 500);
        assert_eq!(config.backoff_multiplier, 1.5);
        assert_eq!(config.max_interval, Duration::from_secs(600));
    }

    #[test]
    fn test_backoff_calculation() {
        let config = PollingConfig::builder()
            .interval(Duration::from_millis(1000))
            .backoff_multiplier(2.0)
            .max_interval(Duration::from_millis(10000))
            .build();

        // 1st error: 1000 * 2^1 = 2000
        let delay1 = PollingManager::calculate_backoff(&config, 1);
        assert_eq!(delay1, Duration::from_millis(2000));

        // 2nd error: 1000 * 2^2 = 4000
        let delay2 = PollingManager::calculate_backoff(&config, 2);
        assert_eq!(delay2, Duration::from_millis(4000));

        // 3rd error: 1000 * 2^3 = 8000
        let delay3 = PollingManager::calculate_backoff(&config, 3);
        assert_eq!(delay3, Duration::from_millis(8000));

        // 4th error: 1000 * 2^4 = 16000, but capped at 10000
        let delay4 = PollingManager::calculate_backoff(&config, 4);
        assert_eq!(delay4, Duration::from_millis(10000));
    }

    #[test]
    fn test_manager_initial_state() {
        let manager = PollingManager::with_defaults();

        assert!(!manager.is_running());
        assert_eq!(manager.consecutive_errors(), 0);
        assert_eq!(manager.current_interval(), Duration::from_secs(30));
    }

    #[test]
    fn test_manual_success_error() {
        let config = PollingConfig::builder()
            .interval(Duration::from_millis(100))
            .backoff_multiplier(2.0)
            .max_interval(Duration::from_millis(1000))
            .build();
        let manager = PollingManager::new(config);

        // Record errors
        manager.on_error();
        assert_eq!(manager.consecutive_errors(), 1);
        assert_eq!(manager.current_interval(), Duration::from_millis(200));

        manager.on_error();
        assert_eq!(manager.consecutive_errors(), 2);
        assert_eq!(manager.current_interval(), Duration::from_millis(400));

        // Record success
        manager.on_success();
        assert_eq!(manager.consecutive_errors(), 0);
        assert_eq!(manager.current_interval(), Duration::from_millis(100));
    }

    #[test]
    fn test_reset() {
        let config = PollingConfig::builder()
            .interval(Duration::from_millis(100))
            .build();
        let manager = PollingManager::new(config);

        // Simulate errors
        manager.on_error();
        manager.on_error();
        assert_eq!(manager.consecutive_errors(), 2);

        // Reset
        manager.reset();
        assert_eq!(manager.consecutive_errors(), 0);
        assert_eq!(manager.current_interval(), Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_start_stop() {
        let config = PollingConfig::builder()
            .interval(Duration::from_millis(50))
            .jitter_ms(0)
            .build();
        let mut manager = PollingManager::new(config);

        let poll_count = Arc::new(AtomicU32::new(0));
        let poll_count_clone = Arc::clone(&poll_count);

        let callback: PollCallback = Arc::new(move || {
            let count = Arc::clone(&poll_count_clone);
            Box::pin(async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        manager.start(callback);
        assert!(manager.is_running());

        // Wait for a few polls
        tokio::time::sleep(Duration::from_millis(180)).await;

        manager.stop().await;
        assert!(!manager.is_running());

        // Should have polled at least once
        assert!(poll_count.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn test_poll_now() {
        let config = PollingConfig::builder()
            .interval(Duration::from_secs(60)) // Long interval
            .jitter_ms(0)
            .build();
        let mut manager = PollingManager::new(config);

        let poll_count = Arc::new(AtomicU32::new(0));
        let poll_count_clone = Arc::clone(&poll_count);

        let callback: PollCallback = Arc::new(move || {
            let count = Arc::clone(&poll_count_clone);
            Box::pin(async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        manager.start(callback);

        // Request immediate poll
        manager.poll_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        manager.stop().await;

        // Should have polled at least once from poll_now
        assert!(poll_count.load(Ordering::SeqCst) >= 1);
    }
}
