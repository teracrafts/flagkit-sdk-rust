use flagkit::security::{
    check_pii_strict, detect_potential_pii, detect_potential_pii_with_config, is_client_key,
    is_potential_pii_field, is_potential_pii_field_with_config, is_production_environment,
    is_server_key, sign_request, validate_api_key_security, validate_local_port,
    verify_signature, warn_if_potential_pii, warn_if_potential_pii_with_config,
    warn_if_server_key_in_browser, ApiKeyManager, DataType, EncryptedCache, Logger,
    SecurityConfig,
};
use flagkit::ErrorCode;
use serde_json::json;
use std::sync::{Arc, Mutex};

/// Test logger that captures all log messages for verification
struct MockLogger {
    debug_messages: Arc<Mutex<Vec<String>>>,
    info_messages: Arc<Mutex<Vec<String>>>,
    warn_messages: Arc<Mutex<Vec<String>>>,
    error_messages: Arc<Mutex<Vec<String>>>,
}

impl MockLogger {
    fn new() -> Self {
        Self {
            debug_messages: Arc::new(Mutex::new(Vec::new())),
            info_messages: Arc::new(Mutex::new(Vec::new())),
            warn_messages: Arc::new(Mutex::new(Vec::new())),
            error_messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn warn_messages(&self) -> Vec<String> {
        self.warn_messages.lock().unwrap().clone()
    }

    fn has_warning_containing(&self, substring: &str) -> bool {
        self.warn_messages
            .lock()
            .unwrap()
            .iter()
            .any(|msg| msg.contains(substring))
    }

    fn warning_count(&self) -> usize {
        self.warn_messages.lock().unwrap().len()
    }
}

impl Logger for MockLogger {
    fn debug(&self, message: &str) {
        self.debug_messages
            .lock()
            .unwrap()
            .push(message.to_string());
    }

    fn info(&self, message: &str) {
        self.info_messages
            .lock()
            .unwrap()
            .push(message.to_string());
    }

    fn warn(&self, message: &str) {
        self.warn_messages
            .lock()
            .unwrap()
            .push(message.to_string());
    }

    fn error(&self, message: &str) {
        self.error_messages
            .lock()
            .unwrap()
            .push(message.to_string());
    }
}

// =============================================================================
// is_potential_pii_field tests
// =============================================================================

mod is_potential_pii_field_tests {
    use super::*;

    #[test]
    fn detects_email_field() {
        assert!(is_potential_pii_field("email"));
        assert!(is_potential_pii_field("user_email"));
        assert!(is_potential_pii_field("primary_email"));
        assert!(is_potential_pii_field("emailAddress"));
    }

    #[test]
    fn detects_phone_fields() {
        assert!(is_potential_pii_field("phone"));
        assert!(is_potential_pii_field("telephone"));
        assert!(is_potential_pii_field("mobile"));
        assert!(is_potential_pii_field("phone_number"));
        assert!(is_potential_pii_field("mobilePhone"));
    }

    #[test]
    fn detects_ssn_fields() {
        assert!(is_potential_pii_field("ssn"));
        assert!(is_potential_pii_field("social_security"));
        assert!(is_potential_pii_field("socialSecurity"));
        assert!(is_potential_pii_field("social_security_number"));
    }

    #[test]
    fn detects_credit_card_fields() {
        assert!(is_potential_pii_field("credit_card"));
        assert!(is_potential_pii_field("creditCard"));
        assert!(is_potential_pii_field("card_number"));
        assert!(is_potential_pii_field("cardNumber"));
        assert!(is_potential_pii_field("cvv"));
    }

    #[test]
    fn detects_password_fields() {
        assert!(is_potential_pii_field("password"));
        assert!(is_potential_pii_field("passwd"));
        assert!(is_potential_pii_field("user_password"));
        assert!(is_potential_pii_field("passwordHash"));
    }

    #[test]
    fn detects_secret_and_token_fields() {
        assert!(is_potential_pii_field("secret"));
        assert!(is_potential_pii_field("token"));
        assert!(is_potential_pii_field("api_key"));
        assert!(is_potential_pii_field("apiKey"));
        assert!(is_potential_pii_field("private_key"));
        assert!(is_potential_pii_field("privateKey"));
        assert!(is_potential_pii_field("access_token"));
        assert!(is_potential_pii_field("accessToken"));
        assert!(is_potential_pii_field("refresh_token"));
        assert!(is_potential_pii_field("refreshToken"));
        assert!(is_potential_pii_field("auth_token"));
        assert!(is_potential_pii_field("authToken"));
    }

    #[test]
    fn detects_address_fields() {
        assert!(is_potential_pii_field("address"));
        assert!(is_potential_pii_field("street"));
        assert!(is_potential_pii_field("zip_code"));
        assert!(is_potential_pii_field("zipCode"));
        assert!(is_potential_pii_field("postal_code"));
        assert!(is_potential_pii_field("postalCode"));
    }

    #[test]
    fn detects_date_of_birth_fields() {
        assert!(is_potential_pii_field("date_of_birth"));
        assert!(is_potential_pii_field("dateOfBirth"));
        assert!(is_potential_pii_field("dob"));
        assert!(is_potential_pii_field("birth_date"));
        assert!(is_potential_pii_field("birthDate"));
    }

    #[test]
    fn detects_id_document_fields() {
        assert!(is_potential_pii_field("passport"));
        assert!(is_potential_pii_field("driver_license"));
        assert!(is_potential_pii_field("driverLicense"));
        assert!(is_potential_pii_field("national_id"));
        assert!(is_potential_pii_field("nationalId"));
    }

    #[test]
    fn detects_financial_fields() {
        assert!(is_potential_pii_field("bank_account"));
        assert!(is_potential_pii_field("bankAccount"));
        assert!(is_potential_pii_field("routing_number"));
        assert!(is_potential_pii_field("routingNumber"));
        assert!(is_potential_pii_field("iban"));
        assert!(is_potential_pii_field("swift"));
    }

    #[test]
    fn is_case_insensitive() {
        assert!(is_potential_pii_field("EMAIL"));
        assert!(is_potential_pii_field("Email"));
        assert!(is_potential_pii_field("eMaIl"));
        assert!(is_potential_pii_field("PHONE"));
        assert!(is_potential_pii_field("Password"));
    }

    #[test]
    fn does_not_detect_safe_fields() {
        assert!(!is_potential_pii_field("username"));
        assert!(!is_potential_pii_field("id"));
        assert!(!is_potential_pii_field("name"));
        assert!(!is_potential_pii_field("count"));
        assert!(!is_potential_pii_field("status"));
        assert!(!is_potential_pii_field("enabled"));
        assert!(!is_potential_pii_field("timestamp"));
        assert!(!is_potential_pii_field("version"));
    }

    #[test]
    fn handles_empty_string() {
        assert!(!is_potential_pii_field(""));
    }

    #[test]
    fn with_custom_patterns() {
        let config = SecurityConfig::builder()
            .add_pii_pattern("employee_id")
            .add_pii_pattern("salary")
            .build();

        assert!(is_potential_pii_field_with_config("employee_id", Some(&config)));
        assert!(is_potential_pii_field_with_config("user_salary", Some(&config)));
        assert!(!is_potential_pii_field_with_config("department", Some(&config)));
    }
}

// =============================================================================
// detect_potential_pii tests
// =============================================================================

mod detect_potential_pii_tests {
    use super::*;

    #[test]
    fn detects_flat_pii_fields() {
        let data = json!({
            "email": "test@example.com",
            "phone": "123-456-7890",
            "name": "John"
        });

        let pii = detect_potential_pii(&data, "");

        assert_eq!(pii.len(), 2);
        assert!(pii.contains(&"email".to_string()));
        assert!(pii.contains(&"phone".to_string()));
    }

    #[test]
    fn detects_nested_pii_fields() {
        let data = json!({
            "user": {
                "email": "test@example.com",
                "details": {
                    "ssn": "123-45-6789",
                    "address": "123 Main St"
                }
            }
        });

        let pii = detect_potential_pii(&data, "");

        assert_eq!(pii.len(), 3);
        assert!(pii.contains(&"user.email".to_string()));
        assert!(pii.contains(&"user.details.ssn".to_string()));
        assert!(pii.contains(&"user.details.address".to_string()));
    }

    #[test]
    fn respects_prefix_parameter() {
        let data = json!({
            "email": "test@example.com"
        });

        let pii = detect_potential_pii(&data, "context.attributes");

        assert_eq!(pii.len(), 1);
        assert!(pii.contains(&"context.attributes.email".to_string()));
    }

    #[test]
    fn detects_pii_in_arrays() {
        let data = json!({
            "contacts": [
                { "email": "a@example.com", "type": "work" },
                { "phone": "555-1234", "type": "home" }
            ]
        });

        let pii = detect_potential_pii(&data, "");

        assert!(pii.contains(&"contacts[0].email".to_string()));
        assert!(pii.contains(&"contacts[1].phone".to_string()));
    }

    #[test]
    fn handles_empty_object() {
        let data = json!({});
        let pii = detect_potential_pii(&data, "");
        assert!(pii.is_empty());
    }

    #[test]
    fn handles_non_object_values() {
        let data = json!("string value");
        let pii = detect_potential_pii(&data, "");
        assert!(pii.is_empty());

        let data = json!(123);
        let pii = detect_potential_pii(&data, "");
        assert!(pii.is_empty());

        let data = json!(null);
        let pii = detect_potential_pii(&data, "");
        assert!(pii.is_empty());
    }

    #[test]
    fn handles_deeply_nested_objects() {
        let data = json!({
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "email": "deep@example.com"
                        }
                    }
                }
            }
        });

        let pii = detect_potential_pii(&data, "");

        assert_eq!(pii.len(), 1);
        assert!(pii.contains(&"level1.level2.level3.level4.email".to_string()));
    }

    #[test]
    fn with_custom_config() {
        let config = SecurityConfig::builder()
            .add_pii_pattern("custom_field")
            .build();

        let data = json!({
            "custom_field": "sensitive",
            "normal_field": "safe"
        });

        let pii = detect_potential_pii_with_config(&data, "", Some(&config));

        assert_eq!(pii.len(), 1);
        assert!(pii.contains(&"custom_field".to_string()));
    }

    #[test]
    fn handles_mixed_array_content() {
        let data = json!({
            "items": [
                { "email": "test@example.com" },
                "string value",
                123,
                null,
                { "password": "secret" }
            ]
        });

        let pii = detect_potential_pii(&data, "");

        assert!(pii.contains(&"items[0].email".to_string()));
        assert!(pii.contains(&"items[4].password".to_string()));
    }

    #[test]
    fn respects_private_attributes() {
        let config = SecurityConfig::builder()
            .add_private_attribute("email")
            .add_private_attribute("ssn")
            .build();

        let data = json!({
            "email": "test@example.com",
            "ssn": "123-45-6789",
            "phone": "555-1234"
        });

        let pii = detect_potential_pii_with_config(&data, "", Some(&config));

        assert!(!pii.contains(&"email".to_string()));
        assert!(!pii.contains(&"ssn".to_string()));
        assert!(pii.contains(&"phone".to_string()));
    }
}

// =============================================================================
// warn_if_potential_pii tests
// =============================================================================

mod warn_if_potential_pii_tests {
    use super::*;

    #[test]
    fn no_warning_when_no_data() {
        let logger = MockLogger::new();
        warn_if_potential_pii(None, DataType::Context, Some(&logger));
        assert_eq!(logger.warning_count(), 0);
    }

    #[test]
    fn no_warning_when_no_logger() {
        let data = json!({ "email": "test@example.com" });
        // Should not panic
        warn_if_potential_pii(Some(&data), DataType::Context, None);
    }

    #[test]
    fn no_warning_when_no_pii() {
        let logger = MockLogger::new();
        let data = json!({
            "username": "john",
            "status": "active"
        });

        warn_if_potential_pii(Some(&data), DataType::Context, Some(&logger));

        assert_eq!(logger.warning_count(), 0);
    }

    #[test]
    fn warns_on_pii_in_context() {
        let logger = MockLogger::new();
        let data = json!({
            "email": "test@example.com",
            "phone": "123-456-7890"
        });

        warn_if_potential_pii(Some(&data), DataType::Context, Some(&logger));

        assert_eq!(logger.warning_count(), 1);
        assert!(logger.has_warning_containing("context"));
        assert!(logger.has_warning_containing("email"));
        assert!(logger.has_warning_containing("phone"));
        assert!(logger.has_warning_containing("privateAttributes"));
    }

    #[test]
    fn warns_on_pii_in_event() {
        let logger = MockLogger::new();
        let data = json!({
            "ssn": "123-45-6789"
        });

        warn_if_potential_pii(Some(&data), DataType::Event, Some(&logger));

        assert_eq!(logger.warning_count(), 1);
        assert!(logger.has_warning_containing("event"));
        assert!(logger.has_warning_containing("ssn"));
        assert!(logger.has_warning_containing("removing sensitive data"));
    }

    #[test]
    fn no_warning_when_disabled_in_config() {
        let logger = MockLogger::new();
        let data = json!({ "email": "test@example.com" });
        let config = SecurityConfig::builder()
            .warn_on_potential_pii(false)
            .build();

        warn_if_potential_pii_with_config(
            Some(&data),
            DataType::Context,
            Some(&logger),
            Some(&config),
        );

        assert_eq!(logger.warning_count(), 0);
    }

    #[test]
    fn uses_custom_patterns_from_config() {
        let logger = MockLogger::new();
        let data = json!({
            "employee_id": "EMP123",
            "username": "john"
        });
        let config = SecurityConfig::builder()
            .add_pii_pattern("employee_id")
            .build();

        warn_if_potential_pii_with_config(
            Some(&data),
            DataType::Context,
            Some(&logger),
            Some(&config),
        );

        assert_eq!(logger.warning_count(), 1);
        assert!(logger.has_warning_containing("employee_id"));
    }
}

// =============================================================================
// Strict PII Mode tests
// =============================================================================

mod strict_pii_mode_tests {
    use super::*;

    #[test]
    fn check_pii_strict_disabled() {
        let config = SecurityConfig::builder().strict_pii_mode(false).build();

        let data = json!({ "email": "test@example.com" });
        let result = check_pii_strict(Some(&data), DataType::Context, &config);

        assert!(result.is_ok());
    }

    #[test]
    fn check_pii_strict_enabled_with_pii() {
        let config = SecurityConfig::builder().strict_pii_mode(true).build();

        let data = json!({ "email": "test@example.com" });
        let result = check_pii_strict(Some(&data), DataType::Context, &config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::SecurityPiiDetected);
        assert!(err.message.contains("email"));
    }

    #[test]
    fn check_pii_strict_with_private_attributes() {
        let config = SecurityConfig::builder()
            .strict_pii_mode(true)
            .add_private_attribute("email")
            .build();

        let data = json!({ "email": "test@example.com" });
        let result = check_pii_strict(Some(&data), DataType::Context, &config);

        assert!(result.is_ok());
    }

    #[test]
    fn check_pii_strict_no_data() {
        let config = SecurityConfig::builder().strict_pii_mode(true).build();

        let result = check_pii_strict(None, DataType::Context, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn check_pii_strict_partial_coverage() {
        let config = SecurityConfig::builder()
            .strict_pii_mode(true)
            .add_private_attribute("email")
            .build();

        let data = json!({
            "email": "test@example.com",
            "phone": "555-1234"
        });

        let result = check_pii_strict(Some(&data), DataType::Context, &config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("phone"));
        assert!(!err.message.contains("email"));
    }
}

// =============================================================================
// is_server_key and is_client_key tests
// =============================================================================

mod api_key_type_tests {
    use super::*;

    #[test]
    fn server_key_detection() {
        assert!(is_server_key("srv_abc123"));
        assert!(is_server_key("srv_"));
        assert!(is_server_key("srv_very_long_key_here"));
    }

    #[test]
    fn server_key_negative_cases() {
        assert!(!is_server_key("sdk_abc123"));
        assert!(!is_server_key("cli_abc123"));
        assert!(!is_server_key(""));
        assert!(!is_server_key("srv"));
        assert!(!is_server_key("SRV_abc123")); // Case sensitive
        assert!(!is_server_key("_srv_abc123"));
    }

    #[test]
    fn client_key_detection_sdk() {
        assert!(is_client_key("sdk_abc123"));
        assert!(is_client_key("sdk_"));
        assert!(is_client_key("sdk_very_long_key_here"));
    }

    #[test]
    fn client_key_detection_cli() {
        assert!(is_client_key("cli_abc123"));
        assert!(is_client_key("cli_"));
        assert!(is_client_key("cli_very_long_key_here"));
    }

    #[test]
    fn client_key_negative_cases() {
        assert!(!is_client_key("srv_abc123"));
        assert!(!is_client_key(""));
        assert!(!is_client_key("sdk"));
        assert!(!is_client_key("cli"));
        assert!(!is_client_key("SDK_abc123")); // Case sensitive
        assert!(!is_client_key("CLI_abc123")); // Case sensitive
    }

    #[test]
    fn mutually_exclusive() {
        let server_key = "srv_test";
        let sdk_key = "sdk_test";
        let cli_key = "cli_test";

        assert!(is_server_key(server_key) && !is_client_key(server_key));
        assert!(!is_server_key(sdk_key) && is_client_key(sdk_key));
        assert!(!is_server_key(cli_key) && is_client_key(cli_key));
    }
}

// =============================================================================
// warn_if_server_key_in_browser tests
// =============================================================================

mod warn_if_server_key_in_browser_tests {
    use super::*;

    #[test]
    fn no_warning_for_client_keys() {
        let logger = MockLogger::new();
        warn_if_server_key_in_browser("sdk_abc123", Some(&logger));
        warn_if_server_key_in_browser("cli_abc123", Some(&logger));

        // In non-WASM environments, no warning is expected regardless of key type
        // In WASM environments, client keys should not trigger warnings
        // Since we're likely running in a non-WASM test environment, expect 0 warnings
        assert_eq!(logger.warning_count(), 0);
    }

    #[test]
    fn no_panic_without_logger() {
        // Should not panic
        warn_if_server_key_in_browser("srv_abc123", None);
        warn_if_server_key_in_browser("sdk_abc123", None);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn no_warning_in_non_browser_environment() {
        let logger = MockLogger::new();
        warn_if_server_key_in_browser("srv_abc123", Some(&logger));

        // In non-WASM (non-browser) environment, no warning expected
        assert_eq!(logger.warning_count(), 0);
    }
}

// =============================================================================
// validate_api_key_security tests
// =============================================================================

mod validate_api_key_security_tests {
    use super::*;

    #[test]
    fn rejects_empty_key() {
        let result = validate_api_key_security("", None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn rejects_invalid_prefix() {
        let result = validate_api_key_security("invalid_key", None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid API key format"));
    }

    #[test]
    fn rejects_key_without_underscore() {
        let result = validate_api_key_security("sdkabc123", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn accepts_valid_sdk_key() {
        let result = validate_api_key_security("sdk_abc123", None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_valid_server_key() {
        let result = validate_api_key_security("srv_abc123", None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_valid_cli_key() {
        let result = validate_api_key_security("cli_abc123", None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_minimal_keys() {
        assert!(validate_api_key_security("sdk_", None, None).is_ok());
        assert!(validate_api_key_security("srv_", None, None).is_ok());
        assert!(validate_api_key_security("cli_", None, None).is_ok());
    }
}

// =============================================================================
// Local Port Restriction tests
// =============================================================================

mod local_port_restriction_tests {
    use super::*;

    #[test]
    fn validate_local_port_none() {
        let result = validate_local_port(None);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_local_port_non_production() {
        // Ensure we're not in production
        std::env::remove_var("RUST_ENV");
        std::env::remove_var("APP_ENV");

        let result = validate_local_port(Some(8200));
        assert!(result.is_ok());
    }

    #[test]
    fn is_production_environment_default() {
        std::env::remove_var("RUST_ENV");
        std::env::remove_var("APP_ENV");

        assert!(!is_production_environment());
    }
}

// =============================================================================
// Request Signing tests
// =============================================================================

mod request_signing_tests {
    use super::*;

    #[test]
    fn sign_request_creates_valid_signature() {
        let body = r#"{"flag_key": "my-flag"}"#;
        let result = sign_request(body, "sdk_test_key");

        assert!(result.is_ok());
        let signature = result.unwrap();

        assert!(!signature.signature.is_empty());
        assert!(signature.timestamp > 0);
        assert_eq!(signature.key_id.len(), 8);
    }

    #[test]
    fn verify_signature_valid() {
        let body = r#"{"flag_key": "my-flag"}"#;
        let api_key = "sdk_test_key";

        let signature = sign_request(body, api_key).unwrap();

        let is_valid =
            verify_signature(body, &signature.signature, signature.timestamp, api_key).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn verify_signature_wrong_body() {
        let body = r#"{"flag_key": "my-flag"}"#;
        let api_key = "sdk_test_key";

        let signature = sign_request(body, api_key).unwrap();

        let wrong_body = r#"{"flag_key": "other-flag"}"#;
        let is_valid =
            verify_signature(wrong_body, &signature.signature, signature.timestamp, api_key)
                .unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn verify_signature_wrong_key() {
        let body = r#"{"flag_key": "my-flag"}"#;
        let api_key = "sdk_test_key";

        let signature = sign_request(body, api_key).unwrap();

        let wrong_key = "sdk_wrong_key";
        let is_valid =
            verify_signature(body, &signature.signature, signature.timestamp, wrong_key).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn verify_signature_wrong_timestamp() {
        let body = r#"{"flag_key": "my-flag"}"#;
        let api_key = "sdk_test_key";

        let signature = sign_request(body, api_key).unwrap();

        let is_valid =
            verify_signature(body, &signature.signature, signature.timestamp + 1, api_key).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn signature_headers() {
        let body = r#"{"test": true}"#;
        let signature = sign_request(body, "sdk_key").unwrap();

        assert_eq!(signature.x_signature(), signature.signature);
        assert_eq!(signature.x_timestamp(), signature.timestamp.to_string());
        assert_eq!(signature.x_key_id(), signature.key_id);
    }

    #[test]
    fn different_bodies_different_signatures() {
        let api_key = "sdk_test_key";
        let sig1 = sign_request(r#"{"a": 1}"#, api_key).unwrap();
        let sig2 = sign_request(r#"{"b": 2}"#, api_key).unwrap();

        assert_ne!(sig1.signature, sig2.signature);
    }

    #[test]
    fn different_keys_different_signatures() {
        let body = r#"{"test": true}"#;
        let sig1 = sign_request(body, "sdk_key_1").unwrap();
        let sig2 = sign_request(body, "sdk_key_2").unwrap();

        assert_ne!(sig1.signature, sig2.signature);
        assert_ne!(sig1.key_id, sig2.key_id);
    }
}

// =============================================================================
// Key Rotation tests
// =============================================================================

mod key_rotation_tests {
    use super::*;

    #[test]
    fn api_key_manager_no_secondary() {
        let manager = ApiKeyManager::new("sdk_primary", None);

        assert_eq!(manager.current_key(), "sdk_primary");
        assert!(!manager.is_using_secondary());
        assert!(!manager.has_secondary_key());

        let rotated = manager.handle_401_error().unwrap();
        assert!(!rotated);
    }

    #[test]
    fn api_key_manager_with_secondary() {
        let manager = ApiKeyManager::new("sdk_primary", Some("sdk_secondary".to_string()));

        assert_eq!(manager.current_key(), "sdk_primary");
        assert!(!manager.is_using_secondary());
        assert!(manager.has_secondary_key());

        let rotated = manager.handle_401_error().unwrap();
        assert!(rotated);
        assert!(manager.is_using_secondary());
        assert_eq!(manager.current_key(), "sdk_secondary");
    }

    #[test]
    fn api_key_manager_double_rotation_fails() {
        let manager = ApiKeyManager::new("sdk_primary", Some("sdk_secondary".to_string()));

        // First rotation succeeds
        let rotated = manager.handle_401_error().unwrap();
        assert!(rotated);

        // Second rotation fails
        let result = manager.handle_401_error();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::SecurityKeyRotationFailed);
    }

    #[test]
    fn api_key_manager_reset() {
        let manager = ApiKeyManager::new("sdk_primary", Some("sdk_secondary".to_string()));

        manager.handle_401_error().unwrap();
        assert!(manager.is_using_secondary());

        manager.reset_to_primary();
        assert!(!manager.is_using_secondary());
        assert_eq!(manager.current_key(), "sdk_primary");
    }

    #[test]
    fn api_key_manager_multiple_resets() {
        let manager = ApiKeyManager::new("sdk_primary", Some("sdk_secondary".to_string()));

        // Rotate and reset multiple times
        for _ in 0..3 {
            manager.handle_401_error().unwrap();
            assert!(manager.is_using_secondary());

            manager.reset_to_primary();
            assert!(!manager.is_using_secondary());
        }
    }
}

// =============================================================================
// Cache Encryption tests
// =============================================================================

mod cache_encryption_tests {
    use super::*;

    const NONCE_SIZE: usize = 12;

    #[test]
    fn encrypted_cache_roundtrip() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();

        let plaintext = b"Hello, World!";
        let encrypted = cache.encrypt(plaintext).unwrap();

        assert_ne!(encrypted.as_slice(), plaintext);
        assert!(encrypted.len() > NONCE_SIZE);

        let decrypted = cache.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypted_cache_json_roundtrip() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();

        let value = json!({
            "flags": {
                "feature-a": true,
                "feature-b": "enabled"
            }
        });

        let encrypted = cache.encrypt_json(&value).unwrap();
        let decrypted = cache.decrypt_json(&encrypted).unwrap();

        assert_eq!(decrypted, value);
    }

    #[test]
    fn encrypted_cache_different_keys() {
        let cache1 = EncryptedCache::new("sdk_key_1").unwrap();
        let cache2 = EncryptedCache::new("sdk_key_2").unwrap();

        let plaintext = b"Secret data";
        let encrypted = cache1.encrypt(plaintext).unwrap();

        // Should fail to decrypt with wrong key
        let result = cache2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_cache_tampered_data() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();

        let plaintext = b"Secret data";
        let mut encrypted = cache.encrypt(plaintext).unwrap();

        // Tamper with the ciphertext
        if let Some(last) = encrypted.last_mut() {
            *last ^= 0xFF;
        }

        let result = cache.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_cache_too_short() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();

        let result = cache.decrypt(&[0u8; 5]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::CacheDecryptionError);
    }

    #[test]
    fn encrypted_cache_unique_nonces() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();
        let plaintext = b"Same data";

        // Encrypt the same data multiple times
        let encrypted1 = cache.encrypt(plaintext).unwrap();
        let encrypted2 = cache.encrypt(plaintext).unwrap();
        let encrypted3 = cache.encrypt(plaintext).unwrap();

        // Each encryption should produce different ciphertext due to random nonce
        assert_ne!(encrypted1, encrypted2);
        assert_ne!(encrypted2, encrypted3);
        assert_ne!(encrypted1, encrypted3);

        // But all should decrypt to the same plaintext
        assert_eq!(cache.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(cache.decrypt(&encrypted2).unwrap(), plaintext);
        assert_eq!(cache.decrypt(&encrypted3).unwrap(), plaintext);
    }

    #[test]
    fn encrypted_cache_empty_data() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();

        let plaintext = b"";
        let encrypted = cache.encrypt(plaintext).unwrap();
        let decrypted = cache.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypted_cache_large_data() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();

        let plaintext: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let encrypted = cache.encrypt(&plaintext).unwrap();
        let decrypted = cache.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypted_cache_complex_json() {
        let cache = EncryptedCache::new("sdk_test_key").unwrap();

        let value = json!({
            "flags": {
                "feature-a": true,
                "feature-b": "enabled",
                "feature-c": 42,
                "feature-d": null,
                "feature-e": [1, 2, 3],
                "feature-f": {
                    "nested": true
                }
            },
            "metadata": {
                "version": "1.0.0",
                "timestamp": 1234567890
            }
        });

        let encrypted = cache.encrypt_json(&value).unwrap();
        let decrypted = cache.decrypt_json(&encrypted).unwrap();

        assert_eq!(decrypted, value);
    }
}

// =============================================================================
// SecurityConfig tests
// =============================================================================

mod security_config_tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = SecurityConfig::default();

        assert!(config.warn_on_server_key_in_browser);
        assert!(config.additional_pii_patterns.is_empty());
        assert!(!config.strict_pii_mode);
        assert!(config.private_attributes.is_empty());
        assert!(config.secondary_api_key.is_none());
        assert!(!config.enable_request_signing);
        assert!(!config.enable_cache_encryption);
    }

    #[test]
    fn builder_defaults() {
        let config = SecurityConfig::builder().build();

        assert!(config.warn_on_server_key_in_browser);
        assert!(config.additional_pii_patterns.is_empty());
    }

    #[test]
    fn builder_customization() {
        let config = SecurityConfig::builder()
            .warn_on_potential_pii(false)
            .warn_on_server_key_in_browser(false)
            .additional_pii_patterns(vec!["custom1".to_string(), "custom2".to_string()])
            .strict_pii_mode(true)
            .private_attributes(vec!["email".to_string()])
            .secondary_api_key("sdk_secondary")
            .enable_request_signing(true)
            .enable_cache_encryption(true)
            .build();

        assert!(!config.warn_on_potential_pii);
        assert!(!config.warn_on_server_key_in_browser);
        assert_eq!(config.additional_pii_patterns.len(), 2);
        assert!(config.additional_pii_patterns.contains(&"custom1".to_string()));
        assert!(config.additional_pii_patterns.contains(&"custom2".to_string()));
        assert!(config.strict_pii_mode);
        assert!(config.private_attributes.contains(&"email".to_string()));
        assert_eq!(config.secondary_api_key, Some("sdk_secondary".to_string()));
        assert!(config.enable_request_signing);
        assert!(config.enable_cache_encryption);
    }

    #[test]
    fn builder_add_single_pattern() {
        let config = SecurityConfig::builder()
            .add_pii_pattern("pattern1")
            .add_pii_pattern("pattern2")
            .add_pii_pattern("pattern3")
            .build();

        assert_eq!(config.additional_pii_patterns.len(), 3);
    }

    #[test]
    fn builder_add_single_private_attribute() {
        let config = SecurityConfig::builder()
            .add_private_attribute("attr1")
            .add_private_attribute("attr2")
            .build();

        assert_eq!(config.private_attributes.len(), 2);
    }

    #[test]
    fn new_equals_default() {
        let config1 = SecurityConfig::new();
        let config2 = SecurityConfig::default();

        assert_eq!(config1.warn_on_potential_pii, config2.warn_on_potential_pii);
        assert_eq!(
            config1.warn_on_server_key_in_browser,
            config2.warn_on_server_key_in_browser
        );
        assert_eq!(
            config1.additional_pii_patterns.len(),
            config2.additional_pii_patterns.len()
        );
    }
}

// =============================================================================
// DataType tests
// =============================================================================

mod data_type_tests {
    use super::*;

    #[test]
    fn context_display() {
        assert_eq!(DataType::Context.as_str(), "context");
    }

    #[test]
    fn event_display() {
        assert_eq!(DataType::Event.as_str(), "event");
    }

    #[test]
    fn equality() {
        assert_eq!(DataType::Context, DataType::Context);
        assert_eq!(DataType::Event, DataType::Event);
        assert_ne!(DataType::Context, DataType::Event);
    }
}

// =============================================================================
// Integration tests
// =============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn full_workflow_context_with_pii() {
        let logger = MockLogger::new();
        let config = SecurityConfig::builder()
            .warn_on_potential_pii(true)
            .add_pii_pattern("employee_number")
            .build();

        let context_data = json!({
            "user": {
                "id": "user-123",
                "email": "user@example.com",
                "employee_number": "EMP001",
                "department": "Engineering"
            }
        });

        // First, detect PII
        let pii_fields = detect_potential_pii_with_config(&context_data, "", Some(&config));
        assert!(!pii_fields.is_empty());

        // Then warn
        warn_if_potential_pii_with_config(
            Some(&context_data),
            DataType::Context,
            Some(&logger),
            Some(&config),
        );

        assert_eq!(logger.warning_count(), 1);
        let warnings = logger.warn_messages();
        let warning = &warnings[0];

        assert!(warning.contains("user.email"));
        assert!(warning.contains("user.employee_number"));
        assert!(warning.contains("privateAttributes"));
    }

    #[test]
    fn full_workflow_event_with_pii() {
        let logger = MockLogger::new();

        let event_data = json!({
            "action": "purchase",
            "credit_card": "4111111111111111",
            "amount": 99.99
        });

        warn_if_potential_pii(Some(&event_data), DataType::Event, Some(&logger));

        assert_eq!(logger.warning_count(), 1);
        assert!(logger.has_warning_containing("credit_card"));
        assert!(logger.has_warning_containing("removing sensitive data"));
    }

    #[test]
    fn api_key_validation_workflow() {
        // Test various key formats
        let test_cases = vec![
            ("sdk_test123", true),
            ("srv_test123", true),
            ("cli_test123", true),
            ("invalid", false),
            ("", false),
            ("test_key", false),
        ];

        for (key, expected_valid) in test_cases {
            let result = validate_api_key_security(key, None, None);
            assert_eq!(
                result.is_ok(),
                expected_valid,
                "Key '{}' validation mismatch",
                key
            );
        }
    }

    #[test]
    fn full_security_workflow_with_encryption_and_signing() {
        // Create a security config with all features enabled
        let config = SecurityConfig::builder()
            .strict_pii_mode(true)
            .add_private_attribute("user_id")
            .secondary_api_key("sdk_backup_key")
            .enable_request_signing(true)
            .enable_cache_encryption(true)
            .build();

        // Create encrypted cache
        let cache = EncryptedCache::new("sdk_primary_key").unwrap();

        // Encrypt some flag data
        let flag_data = json!({
            "feature-x": true,
            "feature-y": "variant-a"
        });
        let encrypted = cache.encrypt_json(&flag_data).unwrap();
        let decrypted = cache.decrypt_json(&encrypted).unwrap();
        assert_eq!(decrypted, flag_data);

        // Sign a request
        let request_body = serde_json::to_string(&json!({
            "flag_key": "feature-x",
            "user_id": "user-123"
        }))
        .unwrap();
        let signature = sign_request(&request_body, "sdk_primary_key").unwrap();
        assert!(verify_signature(&request_body, &signature.signature, signature.timestamp, "sdk_primary_key").unwrap());

        // Check PII with private attributes
        let context = json!({
            "user_id": "user-123",
            "name": "John"
        });
        let result = check_pii_strict(Some(&context), DataType::Context, &config);
        assert!(result.is_ok()); // user_id is a private attribute

        // Test key rotation
        let key_manager = ApiKeyManager::new("sdk_primary_key", config.secondary_api_key.clone());
        assert_eq!(key_manager.current_key(), "sdk_primary_key");
    }
}
