use parking_lot::Mutex;
use std::time::{Duration, Instant};

use crate::error::{ErrorCode, FlagKitError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: Mutex<CircuitState>,
    failure_count: Mutex<u32>,
    opened_at: Mutex<Option<Instant>>,
    threshold: u32,
    reset_timeout: Duration,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            state: Mutex::new(CircuitState::Closed),
            failure_count: Mutex::new(0),
            opened_at: Mutex::new(None),
            threshold,
            reset_timeout,
        }
    }

    pub fn state(&self) -> CircuitState {
        let mut state = self.state.lock();
        let opened_at = self.opened_at.lock();

        if *state == CircuitState::Open {
            if let Some(opened) = *opened_at {
                if Instant::now().duration_since(opened) >= self.reset_timeout {
                    *state = CircuitState::HalfOpen;
                }
            }
        }

        *state
    }

    pub fn is_open(&self) -> bool {
        self.state() == CircuitState::Open
    }

    pub fn is_closed(&self) -> bool {
        self.state() == CircuitState::Closed
    }

    pub fn is_half_open(&self) -> bool {
        self.state() == CircuitState::HalfOpen
    }

    pub fn failure_count(&self) -> u32 {
        *self.failure_count.lock()
    }

    pub fn can_execute(&self) -> bool {
        let state = self.state();
        state == CircuitState::Closed || state == CircuitState::HalfOpen
    }

    pub fn record_success(&self) {
        let mut state = self.state.lock();
        let mut failure_count = self.failure_count.lock();
        let mut opened_at = self.opened_at.lock();

        *failure_count = 0;
        *state = CircuitState::Closed;
        *opened_at = None;
    }

    pub fn record_failure(&self) {
        let mut state = self.state.lock();
        let mut failure_count = self.failure_count.lock();
        let mut opened_at = self.opened_at.lock();

        *failure_count += 1;

        if *state == CircuitState::HalfOpen || *failure_count >= self.threshold {
            *state = CircuitState::Open;
            *opened_at = Some(Instant::now());
        }
    }

    pub fn reset(&self) {
        let mut state = self.state.lock();
        let mut failure_count = self.failure_count.lock();
        let mut opened_at = self.opened_at.lock();

        *state = CircuitState::Closed;
        *failure_count = 0;
        *opened_at = None;
    }

    pub fn execute<T, F>(&self, action: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        if !self.can_execute() {
            return Err(FlagKitError::network_error(
                ErrorCode::HttpCircuitOpen,
                "Circuit breaker is open",
            ));
        }

        match action() {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(e) => {
                if e.code != ErrorCode::HttpCircuitOpen {
                    self.record_failure();
                }
                Err(e)
            }
        }
    }

    pub async fn execute_async<T, F, Fut>(&self, action: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        if !self.can_execute() {
            return Err(FlagKitError::network_error(
                ErrorCode::HttpCircuitOpen,
                "Circuit breaker is open",
            ));
        }

        match action().await {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(e) => {
                if e.code != ErrorCode::HttpCircuitOpen {
                    self.record_failure();
                }
                Err(e)
            }
        }
    }

    pub fn execute_with_fallback<T, F, G>(&self, action: F, fallback: G) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
        G: FnOnce() -> T,
    {
        if !self.can_execute() {
            return Ok(fallback());
        }

        match action() {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(e) => {
                if e.code != ErrorCode::HttpCircuitOpen {
                    self.record_failure();
                }
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state_is_closed() {
        let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

        assert_eq!(breaker.state(), CircuitState::Closed);
        assert!(breaker.is_closed());
        assert!(breaker.can_execute());
    }

    #[test]
    fn test_opens_after_threshold_failures() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(30));

        breaker.record_failure();
        breaker.record_failure();
        assert!(breaker.is_closed());

        breaker.record_failure();
        assert!(breaker.is_open());
        assert!(!breaker.can_execute());
    }

    #[test]
    fn test_success_resets_failure_count() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(30));

        breaker.record_failure();
        breaker.record_failure();
        breaker.record_success();

        assert_eq!(breaker.failure_count(), 0);
        assert!(breaker.is_closed());
    }

    #[test]
    fn test_reset_returns_to_closed() {
        let breaker = CircuitBreaker::new(1, Duration::from_secs(30));

        breaker.record_failure();
        assert!(breaker.is_open());

        breaker.reset();

        assert!(breaker.is_closed());
        assert_eq!(breaker.failure_count(), 0);
    }

    #[test]
    fn test_execute_records_success() {
        let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

        let result = breaker.execute(|| Ok("success"));

        assert_eq!(result.unwrap(), "success");
        assert_eq!(breaker.failure_count(), 0);
    }

    #[test]
    fn test_execute_throws_when_open() {
        let breaker = CircuitBreaker::new(1, Duration::from_secs(30));
        breaker.record_failure();

        let result: Result<&str> = breaker.execute(|| Ok("value"));

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::HttpCircuitOpen);
    }
}
