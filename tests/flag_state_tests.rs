use flagkit::{FlagState, FlagType, FlagValue};

#[test]
fn test_flag_state_new() {
    let state = FlagState::new("test-flag", FlagValue::Bool(true));

    assert_eq!(state.key, "test-flag");
    assert_eq!(state.value.as_bool(), Some(true));
    assert!(state.enabled);
    assert_eq!(state.version, 0);
    assert!(state.flag_type.is_none());
    assert!(state.last_modified.is_none());
    assert!(state.metadata.is_none());
}

#[test]
fn test_flag_state_effective_flag_type_explicit() {
    let mut state = FlagState::new("test-flag", FlagValue::Bool(true));
    state.flag_type = Some(FlagType::Boolean);

    assert_eq!(state.effective_flag_type(), FlagType::Boolean);
}

#[test]
fn test_flag_state_effective_flag_type_inferred() {
    let state = FlagState::new("test-flag", FlagValue::String("hello".to_string()));

    assert_eq!(state.effective_flag_type(), FlagType::String);
}

#[test]
fn test_flag_state_bool_value() {
    let state = FlagState::new("bool-flag", FlagValue::Bool(true));

    assert!(state.bool_value());
}

#[test]
fn test_flag_state_bool_value_default() {
    let state = FlagState::new("string-flag", FlagValue::String("hello".to_string()));

    assert!(!state.bool_value()); // Returns false as default
}

#[test]
fn test_flag_state_string_value() {
    let state = FlagState::new("string-flag", FlagValue::String("hello".to_string()));

    assert_eq!(state.string_value(), Some("hello"));
}

#[test]
fn test_flag_state_number_value() {
    let state = FlagState::new("number-flag", FlagValue::Number(42.5));

    assert!((state.number_value() - 42.5).abs() < 0.001);
}

#[test]
fn test_flag_state_int_value() {
    let state = FlagState::new("int-flag", FlagValue::Number(42.9));

    assert_eq!(state.int_value(), 42);
}

#[test]
fn test_flag_state_json_deserialization() {
    let json = r#"{
        "key": "test-flag",
        "value": true,
        "enabled": true,
        "version": 5,
        "flagType": "boolean",
        "lastModified": "2024-01-15T10:30:00Z"
    }"#;

    let state: FlagState = serde_json::from_str(json).unwrap();

    assert_eq!(state.key, "test-flag");
    assert_eq!(state.value.as_bool(), Some(true));
    assert!(state.enabled);
    assert_eq!(state.version, 5);
    assert_eq!(state.flag_type, Some(FlagType::Boolean));
    assert_eq!(state.last_modified, Some("2024-01-15T10:30:00Z".to_string()));
}

#[test]
fn test_flag_state_json_deserialization_string_value() {
    let json = r#"{
        "key": "string-flag",
        "value": "hello world",
        "enabled": true,
        "version": 1,
        "flagType": "string"
    }"#;

    let state: FlagState = serde_json::from_str(json).unwrap();

    assert_eq!(state.key, "string-flag");
    assert_eq!(state.value.as_string(), Some("hello world"));
    assert_eq!(state.flag_type, Some(FlagType::String));
}

#[test]
fn test_flag_state_json_deserialization_number_value() {
    let json = r#"{
        "key": "number-flag",
        "value": 42.5,
        "enabled": true,
        "version": 2,
        "flagType": "number"
    }"#;

    let state: FlagState = serde_json::from_str(json).unwrap();

    assert_eq!(state.key, "number-flag");
    assert!((state.value.as_number().unwrap() - 42.5).abs() < 0.001);
    assert_eq!(state.flag_type, Some(FlagType::Number));
}

#[test]
fn test_flag_state_json_deserialization_json_value() {
    let json = r#"{
        "key": "json-flag",
        "value": {"nested": "value", "count": 10},
        "enabled": true,
        "version": 3,
        "flagType": "json"
    }"#;

    let state: FlagState = serde_json::from_str(json).unwrap();

    assert_eq!(state.key, "json-flag");
    assert!(state.value.as_json().is_some());
    assert_eq!(state.flag_type, Some(FlagType::Json));

    let json_value = state.value.as_json().unwrap();
    assert_eq!(json_value["nested"], "value");
    assert_eq!(json_value["count"], 10);
}

#[test]
fn test_flag_state_defaults_enabled_true() {
    let json = r#"{
        "key": "test-flag",
        "value": true
    }"#;

    let state: FlagState = serde_json::from_str(json).unwrap();

    assert!(state.enabled);
}

#[test]
fn test_flag_type_raw_values() {
    let json_boolean = serde_json::to_string(&FlagType::Boolean).unwrap();
    let json_string = serde_json::to_string(&FlagType::String).unwrap();
    let json_number = serde_json::to_string(&FlagType::Number).unwrap();
    let json_json = serde_json::to_string(&FlagType::Json).unwrap();

    assert_eq!(json_boolean, "\"boolean\"");
    assert_eq!(json_string, "\"string\"");
    assert_eq!(json_number, "\"number\"");
    assert_eq!(json_json, "\"json\"");
}

#[test]
fn test_flag_type_deserialization() {
    let boolean: FlagType = serde_json::from_str("\"boolean\"").unwrap();
    let string: FlagType = serde_json::from_str("\"string\"").unwrap();
    let number: FlagType = serde_json::from_str("\"number\"").unwrap();
    let json: FlagType = serde_json::from_str("\"json\"").unwrap();

    assert_eq!(boolean, FlagType::Boolean);
    assert_eq!(string, FlagType::String);
    assert_eq!(number, FlagType::Number);
    assert_eq!(json, FlagType::Json);
}
