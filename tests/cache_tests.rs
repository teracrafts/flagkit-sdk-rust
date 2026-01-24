use flagkit::{FlagState, FlagValue};
use std::time::Duration;

// Note: The Cache struct is internal, but FlagCache is exposed through the crate.
// These tests use the internal module test approach.

mod cache_unit_tests {
    use super::*;

    // We'll test the FlagCache functionality that's exposed
    // The internal Cache<K,V> has inline tests in the source file

    #[test]
    fn test_flag_state_creation() {
        let flag = FlagState::new("test-flag", FlagValue::Bool(true));

        assert_eq!(flag.key, "test-flag");
        assert_eq!(flag.value.as_bool(), Some(true));
        assert!(flag.enabled);
    }

    #[test]
    fn test_flag_state_with_string_value() {
        let flag = FlagState::new("string-flag", FlagValue::String("hello".to_string()));

        assert_eq!(flag.key, "string-flag");
        assert_eq!(flag.string_value(), Some("hello"));
    }

    #[test]
    fn test_flag_state_with_number_value() {
        let flag = FlagState::new("number-flag", FlagValue::Number(42.5));

        assert_eq!(flag.key, "number-flag");
        assert!((flag.number_value() - 42.5).abs() < 0.001);
    }

    #[test]
    fn test_flag_state_bool_value_default() {
        let flag = FlagState::new("string-flag", FlagValue::String("not a bool".to_string()));

        // When the value isn't a bool, bool_value() returns false
        assert!(!flag.bool_value());
    }

    #[test]
    fn test_flag_state_int_value() {
        let flag = FlagState::new("number-flag", FlagValue::Number(42.9));

        assert_eq!(flag.int_value(), 42);
    }

    #[test]
    fn test_flag_state_effective_type_inferred() {
        let bool_flag = FlagState::new("bool-flag", FlagValue::Bool(true));
        let string_flag = FlagState::new("string-flag", FlagValue::String("test".to_string()));
        let number_flag = FlagState::new("number-flag", FlagValue::Number(1.0));
        let json_flag = FlagState::new("json-flag", FlagValue::Json(serde_json::json!({})));

        assert_eq!(bool_flag.effective_flag_type(), flagkit::FlagType::Boolean);
        assert_eq!(string_flag.effective_flag_type(), flagkit::FlagType::String);
        assert_eq!(number_flag.effective_flag_type(), flagkit::FlagType::Number);
        assert_eq!(json_flag.effective_flag_type(), flagkit::FlagType::Json);
    }

    #[test]
    fn test_flag_state_explicit_type() {
        let mut flag = FlagState::new("flag", FlagValue::Bool(true));
        flag.flag_type = Some(flagkit::FlagType::Boolean);

        assert_eq!(flag.effective_flag_type(), flagkit::FlagType::Boolean);
    }

    #[test]
    fn test_flag_state_serialization() {
        let flag = FlagState::new("test-flag", FlagValue::Bool(true));
        let json = serde_json::to_string(&flag).unwrap();

        assert!(json.contains("test-flag"));
        assert!(json.contains("true"));
    }

    #[test]
    fn test_flag_state_deserialization() {
        let json = r#"{"key":"test-flag","value":true,"enabled":true,"version":1}"#;
        let flag: FlagState = serde_json::from_str(json).unwrap();

        assert_eq!(flag.key, "test-flag");
        assert_eq!(flag.value.as_bool(), Some(true));
        assert!(flag.enabled);
        assert_eq!(flag.version, 1);
    }

    #[test]
    fn test_flag_state_clone() {
        let original = FlagState::new("test-flag", FlagValue::Bool(true));
        let cloned = original.clone();

        assert_eq!(cloned.key, original.key);
        assert_eq!(cloned.value.as_bool(), original.value.as_bool());
    }

    #[test]
    fn test_flag_state_with_metadata() {
        let json = r#"{
            "key": "test-flag",
            "value": true,
            "enabled": true,
            "version": 1,
            "metadata": {"team": "platform", "owner": "alice"}
        }"#;

        let flag: FlagState = serde_json::from_str(json).unwrap();

        assert!(flag.metadata.is_some());
        let metadata = flag.metadata.unwrap();
        assert_eq!(metadata.get("team"), Some(&"platform".to_string()));
        assert_eq!(metadata.get("owner"), Some(&"alice".to_string()));
    }

    #[test]
    fn test_flag_state_with_last_modified() {
        let json = r#"{
            "key": "test-flag",
            "value": true,
            "lastModified": "2024-01-15T10:30:00Z"
        }"#;

        let flag: FlagState = serde_json::from_str(json).unwrap();

        assert_eq!(flag.last_modified, Some("2024-01-15T10:30:00Z".to_string()));
    }
}
