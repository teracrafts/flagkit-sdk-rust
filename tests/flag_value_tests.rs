use flagkit::{FlagType, FlagValue};

#[test]
fn test_bool_value() {
    let value = FlagValue::Bool(true);

    assert_eq!(value.as_bool(), Some(true));
    assert!(value.as_string().is_none());
    assert!(value.as_number().is_none());
}

#[test]
fn test_bool_value_false() {
    let value = FlagValue::Bool(false);

    assert_eq!(value.as_bool(), Some(false));
}

#[test]
fn test_string_value() {
    let value = FlagValue::String("hello".to_string());

    assert_eq!(value.as_string(), Some("hello"));
    assert!(value.as_bool().is_none());
    assert!(value.as_number().is_none());
}

#[test]
fn test_number_value() {
    let value = FlagValue::Number(42.5);

    assert_eq!(value.as_number(), Some(42.5));
    assert_eq!(value.as_int(), Some(42));
    assert!(value.as_bool().is_none());
    assert!(value.as_string().is_none());
}

#[test]
fn test_json_value() {
    let json = serde_json::json!({"key": "value"});
    let value = FlagValue::Json(json.clone());

    assert_eq!(value.as_json(), Some(&json));
    assert!(value.as_bool().is_none());
}

#[test]
fn test_null_value() {
    let value = FlagValue::Null;

    assert!(value.is_null());
    assert!(value.as_bool().is_none());
    assert!(value.as_string().is_none());
    assert!(value.as_number().is_none());
}

#[test]
fn test_is_null() {
    assert!(FlagValue::Null.is_null());
    assert!(!FlagValue::Bool(true).is_null());
    assert!(!FlagValue::String("test".to_string()).is_null());
}

#[test]
fn test_inferred_type_boolean() {
    let value = FlagValue::Bool(true);
    assert_eq!(value.inferred_type(), FlagType::Boolean);
}

#[test]
fn test_inferred_type_string() {
    let value = FlagValue::String("test".to_string());
    assert_eq!(value.inferred_type(), FlagType::String);
}

#[test]
fn test_inferred_type_number() {
    let value = FlagValue::Number(42.0);
    assert_eq!(value.inferred_type(), FlagType::Number);
}

#[test]
fn test_inferred_type_json() {
    let value = FlagValue::Json(serde_json::json!({}));
    assert_eq!(value.inferred_type(), FlagType::Json);

    let null_value = FlagValue::Null;
    assert_eq!(null_value.inferred_type(), FlagType::Json);
}

#[test]
fn test_from_bool() {
    let value: FlagValue = true.into();
    assert_eq!(value.as_bool(), Some(true));
}

#[test]
fn test_from_string() {
    let value: FlagValue = "hello".into();
    assert_eq!(value.as_string(), Some("hello"));
}

#[test]
fn test_from_owned_string() {
    let value: FlagValue = String::from("hello").into();
    assert_eq!(value.as_string(), Some("hello"));
}

#[test]
fn test_from_f64() {
    let value: FlagValue = 3.14_f64.into();
    assert!((value.as_number().unwrap() - 3.14).abs() < 0.001);
}

#[test]
fn test_from_i64() {
    let value: FlagValue = 42_i64.into();
    assert_eq!(value.as_number(), Some(42.0));
}

#[test]
fn test_from_i32() {
    let value: FlagValue = 42_i32.into();
    assert_eq!(value.as_number(), Some(42.0));
}

#[test]
fn test_from_serde_json_bool() {
    let json = serde_json::json!(true);
    let value: FlagValue = json.into();
    assert_eq!(value.as_bool(), Some(true));
}

#[test]
fn test_from_serde_json_string() {
    let json = serde_json::json!("test");
    let value: FlagValue = json.into();
    assert_eq!(value.as_string(), Some("test"));
}

#[test]
fn test_from_serde_json_number() {
    let json = serde_json::json!(123);
    let value: FlagValue = json.into();
    assert_eq!(value.as_number(), Some(123.0));
}

#[test]
fn test_from_serde_json_null() {
    let json = serde_json::Value::Null;
    let value: FlagValue = json.into();
    assert!(value.is_null());
}

#[test]
fn test_from_serde_json_object() {
    let json = serde_json::json!({"key": "value"});
    let value: FlagValue = json.into();
    assert!(value.as_json().is_some());
}

#[test]
fn test_serialization() {
    let value = FlagValue::Bool(true);
    let serialized = serde_json::to_string(&value).unwrap();
    assert_eq!(serialized, "true");

    let value = FlagValue::String("hello".to_string());
    let serialized = serde_json::to_string(&value).unwrap();
    assert_eq!(serialized, "\"hello\"");

    let value = FlagValue::Number(42.0);
    let serialized = serde_json::to_string(&value).unwrap();
    assert_eq!(serialized, "42.0");
}

#[test]
fn test_deserialization() {
    let value: FlagValue = serde_json::from_str("true").unwrap();
    assert_eq!(value.as_bool(), Some(true));

    let value: FlagValue = serde_json::from_str("\"hello\"").unwrap();
    assert_eq!(value.as_string(), Some("hello"));

    let value: FlagValue = serde_json::from_str("42").unwrap();
    assert_eq!(value.as_number(), Some(42.0));
}
