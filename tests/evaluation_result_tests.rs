use flagkit::{EvaluationReason, EvaluationResult, FlagValue};

#[test]
fn test_default_result() {
    let result = EvaluationResult::default_result(
        "test-flag",
        FlagValue::Bool(false),
        EvaluationReason::FlagNotFound,
    );

    assert_eq!(result.flag_key, "test-flag");
    assert_eq!(result.value.as_bool(), Some(false));
    assert!(!result.enabled);
    assert_eq!(result.reason, EvaluationReason::FlagNotFound);
    assert_eq!(result.version, 0);
}

#[test]
fn test_bool_value_true() {
    let result = EvaluationResult::default_result(
        "bool-flag",
        FlagValue::Bool(true),
        EvaluationReason::Cached,
    );

    assert!(result.bool_value());
}

#[test]
fn test_bool_value_false() {
    let result = EvaluationResult::default_result(
        "bool-flag",
        FlagValue::Bool(false),
        EvaluationReason::Cached,
    );

    assert!(!result.bool_value());
}

#[test]
fn test_bool_value_default() {
    let result = EvaluationResult::default_result(
        "string-flag",
        FlagValue::String("hello".to_string()),
        EvaluationReason::Cached,
    );

    assert!(!result.bool_value()); // Returns false as default for non-bool
}

#[test]
fn test_string_value() {
    let result = EvaluationResult::default_result(
        "string-flag",
        FlagValue::String("hello".to_string()),
        EvaluationReason::Server,
    );

    assert_eq!(result.string_value(), Some("hello"));
}

#[test]
fn test_number_value() {
    let result = EvaluationResult::default_result(
        "number-flag",
        FlagValue::Number(3.14),
        EvaluationReason::Cached,
    );

    assert!((result.number_value() - 3.14).abs() < 0.001);
}

#[test]
fn test_number_value_default() {
    let result = EvaluationResult::default_result(
        "bool-flag",
        FlagValue::Bool(true),
        EvaluationReason::Cached,
    );

    assert!((result.number_value() - 0.0).abs() < 0.001);
}

#[test]
fn test_int_value() {
    let result = EvaluationResult::default_result(
        "int-flag",
        FlagValue::Number(42.0),
        EvaluationReason::Cached,
    );

    assert_eq!(result.int_value(), 42);
}

#[test]
fn test_int_value_default() {
    let result = EvaluationResult::default_result(
        "string-flag",
        FlagValue::String("test".to_string()),
        EvaluationReason::Cached,
    );

    assert_eq!(result.int_value(), 0);
}

#[test]
fn test_json_value() {
    let json = serde_json::json!({"enabled": true, "count": 5});
    let result = EvaluationResult::default_result(
        "json-flag",
        FlagValue::Json(json.clone()),
        EvaluationReason::Cached,
    );

    let json_value = result.json_value().unwrap();
    assert_eq!(json_value["enabled"], true);
    assert_eq!(json_value["count"], 5);
}

#[test]
fn test_json_value_none() {
    let result = EvaluationResult::default_result(
        "bool-flag",
        FlagValue::Bool(true),
        EvaluationReason::Cached,
    );

    assert!(result.json_value().is_none());
}

#[test]
fn test_evaluation_reason_cached() {
    let result = EvaluationResult::default_result(
        "flag",
        FlagValue::Bool(true),
        EvaluationReason::Cached,
    );

    assert_eq!(result.reason, EvaluationReason::Cached);
}

#[test]
fn test_evaluation_reason_server() {
    let result = EvaluationResult::default_result(
        "flag",
        FlagValue::Bool(true),
        EvaluationReason::Server,
    );

    assert_eq!(result.reason, EvaluationReason::Server);
}

#[test]
fn test_evaluation_reason_bootstrap() {
    let result = EvaluationResult::default_result(
        "flag",
        FlagValue::Bool(true),
        EvaluationReason::Bootstrap,
    );

    assert_eq!(result.reason, EvaluationReason::Bootstrap);
}

#[test]
fn test_evaluation_reason_default() {
    let result = EvaluationResult::default_result(
        "flag",
        FlagValue::Bool(true),
        EvaluationReason::Default,
    );

    assert_eq!(result.reason, EvaluationReason::Default);
}

#[test]
fn test_evaluation_reason_error() {
    let result = EvaluationResult::default_result(
        "flag",
        FlagValue::Bool(true),
        EvaluationReason::Error,
    );

    assert_eq!(result.reason, EvaluationReason::Error);
}

#[test]
fn test_evaluation_reason_serialization() {
    let cached = serde_json::to_string(&EvaluationReason::Cached).unwrap();
    let server = serde_json::to_string(&EvaluationReason::Server).unwrap();
    let bootstrap = serde_json::to_string(&EvaluationReason::Bootstrap).unwrap();
    let default_reason = serde_json::to_string(&EvaluationReason::Default).unwrap();
    let error = serde_json::to_string(&EvaluationReason::Error).unwrap();
    let flag_not_found = serde_json::to_string(&EvaluationReason::FlagNotFound).unwrap();

    assert_eq!(cached, "\"cached\"");
    assert_eq!(server, "\"server\"");
    assert_eq!(bootstrap, "\"bootstrap\"");
    assert_eq!(default_reason, "\"default\"");
    assert_eq!(error, "\"error\"");
    assert_eq!(flag_not_found, "\"flag_not_found\"");
}
