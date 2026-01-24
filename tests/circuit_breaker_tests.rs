use flagkit::{CircuitBreaker, CircuitState, ErrorCode};
use std::time::Duration;

#[test]
fn test_initial_state_is_closed() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

    assert_eq!(breaker.state(), CircuitState::Closed);
    assert!(breaker.is_closed());
    assert!(!breaker.is_open());
    assert!(!breaker.is_half_open());
    assert!(breaker.can_execute());
}

#[test]
fn test_failure_count_starts_at_zero() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

    assert_eq!(breaker.failure_count(), 0);
}

#[test]
fn test_record_failure_increments_count() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

    breaker.record_failure();
    assert_eq!(breaker.failure_count(), 1);

    breaker.record_failure();
    assert_eq!(breaker.failure_count(), 2);
}

#[test]
fn test_opens_after_threshold_failures() {
    let breaker = CircuitBreaker::new(3, Duration::from_secs(30));

    breaker.record_failure();
    breaker.record_failure();
    assert!(breaker.is_closed());
    assert_eq!(breaker.failure_count(), 2);

    breaker.record_failure();
    assert!(breaker.is_open());
    assert!(!breaker.can_execute());
}

#[test]
fn test_does_not_open_before_threshold() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

    for _ in 0..4 {
        breaker.record_failure();
    }

    assert!(breaker.is_closed());
    assert!(breaker.can_execute());
}

#[test]
fn test_success_resets_failure_count() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

    breaker.record_failure();
    breaker.record_failure();
    assert_eq!(breaker.failure_count(), 2);

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
    assert!(breaker.can_execute());
}

#[test]
fn test_execute_on_success() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

    let result = breaker.execute(|| Ok("success"));

    assert_eq!(result.unwrap(), "success");
    assert_eq!(breaker.failure_count(), 0);
}

#[test]
fn test_execute_on_failure() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

    let result: Result<&str, _> = breaker.execute(|| {
        Err(flagkit::FlagKitError::new(
            ErrorCode::NetworkError,
            "test error",
        ))
    });

    assert!(result.is_err());
    assert_eq!(breaker.failure_count(), 1);
}

#[test]
fn test_execute_throws_when_open() {
    let breaker = CircuitBreaker::new(1, Duration::from_secs(30));
    breaker.record_failure();

    assert!(breaker.is_open());

    let result: Result<&str, _> = breaker.execute(|| Ok("value"));

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.code, ErrorCode::HttpCircuitOpen);
}

#[test]
fn test_execute_does_not_record_circuit_open_error() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

    // Simulate an error that shouldn't be counted as a failure
    let _: Result<&str, _> = breaker.execute(|| {
        Err(flagkit::FlagKitError::new(
            ErrorCode::HttpCircuitOpen,
            "circuit open",
        ))
    });

    // The failure count should not have increased for circuit open errors
    // Note: The actual implementation may vary - this tests the expected behavior
    assert_eq!(breaker.failure_count(), 0);
}

#[test]
fn test_half_open_after_timeout() {
    let breaker = CircuitBreaker::new(1, Duration::from_millis(50));

    breaker.record_failure();
    assert!(breaker.is_open());

    // Wait for reset timeout
    std::thread::sleep(Duration::from_millis(60));

    assert!(breaker.is_half_open());
    assert!(breaker.can_execute());
}

#[test]
fn test_closes_from_half_open_on_success() {
    let breaker = CircuitBreaker::new(1, Duration::from_millis(50));

    breaker.record_failure();
    assert!(breaker.is_open());

    std::thread::sleep(Duration::from_millis(60));
    assert!(breaker.is_half_open());

    breaker.record_success();

    assert!(breaker.is_closed());
}

#[test]
fn test_opens_from_half_open_on_failure() {
    let breaker = CircuitBreaker::new(1, Duration::from_millis(50));

    breaker.record_failure();
    assert!(breaker.is_open());

    std::thread::sleep(Duration::from_millis(60));
    assert!(breaker.is_half_open());

    breaker.record_failure();

    assert!(breaker.is_open());
}

#[test]
fn test_execute_with_fallback_when_open() {
    let breaker = CircuitBreaker::new(1, Duration::from_secs(30));
    breaker.record_failure();

    let result = breaker.execute_with_fallback(
        || Ok("primary"),
        || "fallback",
    );

    assert_eq!(result.unwrap(), "fallback");
}

#[test]
fn test_execute_with_fallback_when_closed() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

    let result = breaker.execute_with_fallback(
        || Ok("primary"),
        || "fallback",
    );

    assert_eq!(result.unwrap(), "primary");
}

#[tokio::test]
async fn test_execute_async_success() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));

    let result = breaker.execute_async(|| async { Ok("async success") }).await;

    assert_eq!(result.unwrap(), "async success");
    assert_eq!(breaker.failure_count(), 0);
}

#[tokio::test]
async fn test_execute_async_when_open() {
    let breaker = CircuitBreaker::new(1, Duration::from_secs(30));
    breaker.record_failure();

    let result: Result<&str, _> = breaker.execute_async(|| async { Ok("value") }).await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ErrorCode::HttpCircuitOpen);
}
