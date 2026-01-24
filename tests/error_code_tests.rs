use flagkit::{ErrorCode, FlagKitError};

#[test]
fn test_error_code_string_values() {
    assert_eq!(ErrorCode::InitFailed.as_str(), "INIT_FAILED");
    assert_eq!(ErrorCode::InitTimeout.as_str(), "INIT_TIMEOUT");
    assert_eq!(ErrorCode::InitAlreadyInitialized.as_str(), "INIT_ALREADY_INITIALIZED");
    assert_eq!(ErrorCode::InitNotInitialized.as_str(), "INIT_NOT_INITIALIZED");

    assert_eq!(ErrorCode::AuthInvalidKey.as_str(), "AUTH_INVALID_KEY");
    assert_eq!(ErrorCode::AuthExpiredKey.as_str(), "AUTH_EXPIRED_KEY");
    assert_eq!(ErrorCode::AuthMissingKey.as_str(), "AUTH_MISSING_KEY");
    assert_eq!(ErrorCode::AuthUnauthorized.as_str(), "AUTH_UNAUTHORIZED");
    assert_eq!(ErrorCode::AuthPermissionDenied.as_str(), "AUTH_PERMISSION_DENIED");

    assert_eq!(ErrorCode::NetworkError.as_str(), "NETWORK_ERROR");
    assert_eq!(ErrorCode::NetworkTimeout.as_str(), "NETWORK_TIMEOUT");
    assert_eq!(ErrorCode::NetworkRetryLimit.as_str(), "NETWORK_RETRY_LIMIT");

    assert_eq!(ErrorCode::HttpCircuitOpen.as_str(), "HTTP_CIRCUIT_OPEN");
    assert_eq!(ErrorCode::HttpRateLimited.as_str(), "HTTP_RATE_LIMITED");
    assert_eq!(ErrorCode::HttpServerError.as_str(), "HTTP_SERVER_ERROR");
}

#[test]
fn test_recoverable_errors() {
    assert!(ErrorCode::NetworkError.is_recoverable());
    assert!(ErrorCode::NetworkTimeout.is_recoverable());
    assert!(ErrorCode::NetworkRetryLimit.is_recoverable());
    assert!(ErrorCode::CircuitOpen.is_recoverable());
    assert!(ErrorCode::HttpCircuitOpen.is_recoverable());
    assert!(ErrorCode::HttpTimeout.is_recoverable());
    assert!(ErrorCode::HttpNetworkError.is_recoverable());
    assert!(ErrorCode::HttpServerError.is_recoverable());
    assert!(ErrorCode::HttpRateLimited.is_recoverable());
    assert!(ErrorCode::CacheExpired.is_recoverable());
    assert!(ErrorCode::EvalStaleValue.is_recoverable());
    assert!(ErrorCode::EvalCacheMiss.is_recoverable());
    assert!(ErrorCode::EvalNetworkError.is_recoverable());
    assert!(ErrorCode::EventSendFailed.is_recoverable());
}

#[test]
fn test_non_recoverable_errors() {
    assert!(!ErrorCode::InitFailed.is_recoverable());
    assert!(!ErrorCode::AuthInvalidKey.is_recoverable());
    assert!(!ErrorCode::ConfigInvalidApiKey.is_recoverable());
    assert!(!ErrorCode::EvalFlagNotFound.is_recoverable());
    assert!(!ErrorCode::EvalTypeMismatch.is_recoverable());
    assert!(!ErrorCode::SdkNotInitialized.is_recoverable());
}

#[test]
fn test_flagkit_error_creation() {
    let error = FlagKitError::new(ErrorCode::InitFailed, "Test error");

    assert_eq!(error.code, ErrorCode::InitFailed);
    assert_eq!(error.message, "Test error");
    assert!(error.source.is_none());
}

#[test]
fn test_flagkit_error_is_recoverable() {
    let recoverable = FlagKitError::new(ErrorCode::NetworkError, "Network error");
    let non_recoverable = FlagKitError::new(ErrorCode::AuthInvalidKey, "Invalid key");

    assert!(recoverable.is_recoverable());
    assert!(!non_recoverable.is_recoverable());
}

#[test]
fn test_flagkit_error_is_config_error() {
    let config_error = FlagKitError::config_error(ErrorCode::ConfigInvalidApiKey, "Bad key");
    let network_error = FlagKitError::network_error(ErrorCode::NetworkError, "Network issue");

    assert!(config_error.is_config_error());
    assert!(!network_error.is_config_error());
}

#[test]
fn test_flagkit_error_is_network_error() {
    let network_error = FlagKitError::network_error(ErrorCode::HttpTimeout, "Timeout");
    let config_error = FlagKitError::config_error(ErrorCode::ConfigInvalidApiKey, "Bad key");

    assert!(network_error.is_network_error());
    assert!(!config_error.is_network_error());
}

#[test]
fn test_not_initialized_error() {
    let error = FlagKitError::not_initialized();

    assert_eq!(error.code, ErrorCode::SdkNotInitialized);
}

#[test]
fn test_already_initialized_error() {
    let error = FlagKitError::already_initialized();

    assert_eq!(error.code, ErrorCode::SdkAlreadyInitialized);
}

#[test]
fn test_error_display() {
    let error = FlagKitError::new(ErrorCode::InitFailed, "Test message");
    let display = format!("{}", error);

    assert!(display.contains("INIT_FAILED"));
    assert!(display.contains("Test message"));
}

#[test]
fn test_error_code_display() {
    let code = ErrorCode::HttpCircuitOpen;
    let display = format!("{}", code);

    assert_eq!(display, "HTTP_CIRCUIT_OPEN");
}
