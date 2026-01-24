use flagkit::security::{
    detect_potential_pii, detect_potential_pii_with_config, is_client_key, is_potential_pii_field,
    is_potential_pii_field_with_config, is_server_key, validate_api_key_security,
    warn_if_potential_pii, warn_if_potential_pii_with_config, warn_if_server_key_in_browser,
    DataType, Logger, SecurityConfig,
};
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
// SecurityConfig tests
// =============================================================================

mod security_config_tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = SecurityConfig::default();

        assert!(config.warn_on_server_key_in_browser);
        assert!(config.additional_pii_patterns.is_empty());
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
            .build();

        assert!(!config.warn_on_potential_pii);
        assert!(!config.warn_on_server_key_in_browser);
        assert_eq!(config.additional_pii_patterns.len(), 2);
        assert!(config.additional_pii_patterns.contains(&"custom1".to_string()));
        assert!(config.additional_pii_patterns.contains(&"custom2".to_string()));
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
}
