use flagkit::{ErrorCode, FlagKitOptions};
use std::time::Duration;

#[test]
fn test_default_values() {
    let options = FlagKitOptions::new("sdk_test_key");

    assert_eq!(options.api_key, "sdk_test_key");
    assert_eq!(options.polling_interval, Duration::from_secs(30));
    assert_eq!(options.cache_ttl, Duration::from_secs(300));
    assert_eq!(options.max_cache_size, 1000);
    assert!(options.cache_enabled);
    assert_eq!(options.event_batch_size, 10);
    assert_eq!(options.event_flush_interval, Duration::from_secs(30));
    assert!(options.events_enabled);
    assert_eq!(options.timeout, Duration::from_secs(10));
    assert_eq!(options.retry_attempts, 3);
    assert_eq!(options.circuit_breaker_threshold, 5);
    assert_eq!(options.circuit_breaker_reset_timeout, Duration::from_secs(30));
    assert!(options.bootstrap.is_none());
    assert!(options.local_port.is_none());
}

#[test]
fn test_builder_custom_values() {
    let options = FlagKitOptions::builder("sdk_test_key")
        .polling_interval(Duration::from_secs(60))
        .cache_ttl(Duration::from_secs(600))
        .max_cache_size(500)
        .cache_enabled(false)
        .event_batch_size(20)
        .event_flush_interval(Duration::from_secs(60))
        .events_enabled(false)
        .timeout(Duration::from_secs(30))
        .retry_attempts(5)
        .circuit_breaker_threshold(10)
        .circuit_breaker_reset_timeout(Duration::from_secs(60))
        .local_port(8200)
        .build();

    assert_eq!(options.polling_interval, Duration::from_secs(60));
    assert_eq!(options.cache_ttl, Duration::from_secs(600));
    assert_eq!(options.max_cache_size, 500);
    assert!(!options.cache_enabled);
    assert_eq!(options.event_batch_size, 20);
    assert_eq!(options.event_flush_interval, Duration::from_secs(60));
    assert!(!options.events_enabled);
    assert_eq!(options.timeout, Duration::from_secs(30));
    assert_eq!(options.retry_attempts, 5);
    assert_eq!(options.circuit_breaker_threshold, 10);
    assert_eq!(options.circuit_breaker_reset_timeout, Duration::from_secs(60));
    assert_eq!(options.local_port, Some(8200));
}

#[test]
fn test_local_port_none_by_default() {
    let options = FlagKitOptions::new("sdk_test_key");
    assert!(options.local_port.is_none());
}

#[test]
fn test_local_port_builder_defaults_to_none() {
    let options = FlagKitOptions::builder("sdk_test_key").build();
    assert!(options.local_port.is_none());
}

#[test]
fn test_local_port_can_be_set() {
    let options = FlagKitOptions::builder("sdk_test_key")
        .local_port(8200)
        .build();
    assert_eq!(options.local_port, Some(8200));
}

#[test]
fn test_local_port_custom_value() {
    let options = FlagKitOptions::builder("sdk_test_key")
        .local_port(3000)
        .build();
    assert_eq!(options.local_port, Some(3000));
}

#[test]
fn test_validate_valid_sdk_key() {
    let options = FlagKitOptions::new("sdk_test_key");
    assert!(options.validate().is_ok());
}

#[test]
fn test_validate_valid_srv_key() {
    let options = FlagKitOptions::new("srv_test_key");
    assert!(options.validate().is_ok());
}

#[test]
fn test_validate_valid_cli_key() {
    let options = FlagKitOptions::new("cli_test_key");
    assert!(options.validate().is_ok());
}

#[test]
fn test_validate_empty_api_key() {
    let options = FlagKitOptions::new("");
    let result = options.validate();

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.code, ErrorCode::ConfigInvalidApiKey);
}

#[test]
fn test_validate_invalid_api_key_prefix() {
    let options = FlagKitOptions::new("invalid_key");
    let result = options.validate();

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.code, ErrorCode::ConfigInvalidApiKey);
}

#[test]
fn test_validate_zero_polling_interval() {
    let options = FlagKitOptions::builder("sdk_test_key")
        .polling_interval(Duration::ZERO)
        .build();
    let result = options.validate();

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.code, ErrorCode::ConfigInvalidPollingInterval);
}

#[test]
fn test_validate_zero_cache_ttl() {
    let options = FlagKitOptions::builder("sdk_test_key")
        .cache_ttl(Duration::ZERO)
        .build();
    let result = options.validate();

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.code, ErrorCode::ConfigInvalidCacheTtl);
}

#[test]
fn test_builder_with_bootstrap() {
    use std::collections::HashMap;

    let mut bootstrap = HashMap::new();
    bootstrap.insert("flag1".to_string(), serde_json::json!(true));
    bootstrap.insert("flag2".to_string(), serde_json::json!("value"));

    let options = FlagKitOptions::builder("sdk_test_key")
        .bootstrap(bootstrap)
        .build();

    assert!(options.bootstrap.is_some());
    let bs = options.bootstrap.unwrap();
    assert_eq!(bs.get("flag1"), Some(&serde_json::json!(true)));
    assert_eq!(bs.get("flag2"), Some(&serde_json::json!("value")));
}

#[test]
fn test_options_clone() {
    let options = FlagKitOptions::builder("sdk_test_key")
        .polling_interval(Duration::from_secs(60))
        .local_port(8200)
        .build();

    let cloned = options.clone();

    assert_eq!(cloned.api_key, options.api_key);
    assert_eq!(cloned.polling_interval, options.polling_interval);
    assert_eq!(cloned.local_port, options.local_port);
}

#[test]
fn test_options_debug() {
    let options = FlagKitOptions::new("sdk_test_key");
    let debug_str = format!("{:?}", options);

    assert!(debug_str.contains("sdk_test_key"));
    assert!(debug_str.contains("FlagKitOptions"));
}
