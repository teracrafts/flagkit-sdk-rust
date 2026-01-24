use flagkit::{EvaluationContext, EvaluationContextBuilder, FlagValue};
use std::collections::HashMap;

#[test]
fn test_empty_context() {
    let context = EvaluationContext::new();

    assert!(context.user_id.is_none());
    assert!(context.attributes.is_empty());
    assert!(context.is_empty());
}

#[test]
fn test_context_with_user_id() {
    let context = EvaluationContext::with_user_id("user-123");

    assert_eq!(context.user_id, Some("user-123".to_string()));
    assert!(context.attributes.is_empty());
    assert!(!context.is_empty());
}

#[test]
fn test_context_builder() {
    let context = EvaluationContextBuilder::new()
        .user_id("user-123")
        .attribute("plan", "premium")
        .attribute("beta", true)
        .build();

    assert_eq!(context.user_id, Some("user-123".to_string()));
    assert!(context.get("plan").is_some());
    assert!(context.get("beta").is_some());
}

#[test]
fn test_context_chained_methods() {
    let context = EvaluationContext::new()
        .user_id("user-456")
        .attribute("role", "admin")
        .attribute("count", 10_i32);

    assert_eq!(context.user_id, Some("user-456".to_string()));
    assert!(context.get("role").is_some());
    assert!(context.get("count").is_some());
}

#[test]
fn test_context_with_attributes() {
    let mut attrs = HashMap::new();
    attrs.insert("key1".to_string(), FlagValue::String("value1".to_string()));
    attrs.insert("key2".to_string(), FlagValue::Bool(true));

    let context = EvaluationContext::new().attributes(attrs);

    assert!(context.get("key1").is_some());
    assert!(context.get("key2").is_some());
}

#[test]
fn test_merge_contexts() {
    let base = EvaluationContext::with_user_id("user-1")
        .attribute("plan", "free");

    let override_ctx = EvaluationContext::with_user_id("user-2")
        .attribute("beta", true);

    let merged = base.merge(Some(&override_ctx));

    assert_eq!(merged.user_id, Some("user-2".to_string()));
    assert!(merged.get("plan").is_some());
    assert!(merged.get("beta").is_some());
}

#[test]
fn test_merge_with_none() {
    let base = EvaluationContext::with_user_id("user-1")
        .attribute("plan", "free");

    let merged = base.merge(None);

    assert_eq!(merged.user_id, Some("user-1".to_string()));
    assert!(merged.get("plan").is_some());
}

#[test]
fn test_merge_preserves_base_user_id_when_override_has_none() {
    let base = EvaluationContext::with_user_id("user-1");
    let override_ctx = EvaluationContext::new().attribute("key", "value");

    let merged = base.merge(Some(&override_ctx));

    assert_eq!(merged.user_id, Some("user-1".to_string()));
}

#[test]
fn test_strip_private_attributes() {
    let context = EvaluationContext::new()
        .attribute("_privateKey", "secret")
        .attribute("_anotherPrivate", true)
        .attribute("publicKey", "visible")
        .attribute("anotherPublic", 42_i32);

    let stripped = context.strip_private_attributes();

    assert!(stripped.get("_privateKey").is_none());
    assert!(stripped.get("_anotherPrivate").is_none());
    assert!(stripped.get("publicKey").is_some());
    assert!(stripped.get("anotherPublic").is_some());
}

#[test]
fn test_strip_preserves_user_id() {
    let context = EvaluationContext::with_user_id("user-123")
        .attribute("_private", "secret");

    let stripped = context.strip_private_attributes();

    assert_eq!(stripped.user_id, Some("user-123".to_string()));
}

#[test]
fn test_get_attribute() {
    let context = EvaluationContext::new()
        .attribute("key", "value");

    let value = context.get("key");
    assert!(value.is_some());
    assert_eq!(value.unwrap().as_string(), Some("value"));
}

#[test]
fn test_get_missing_attribute() {
    let context = EvaluationContext::new();

    assert!(context.get("nonexistent").is_none());
}

#[test]
fn test_to_map() {
    let context = EvaluationContext::with_user_id("user-123")
        .attribute("plan", "premium");

    let map = context.to_map();

    assert!(map.contains_key("userId"));
    assert!(map.contains_key("attributes"));
    assert_eq!(map["userId"], serde_json::json!("user-123"));
}

#[test]
fn test_to_map_without_user_id() {
    let context = EvaluationContext::new()
        .attribute("key", "value");

    let map = context.to_map();

    assert!(!map.contains_key("userId"));
    assert!(map.contains_key("attributes"));
}

#[test]
fn test_to_map_empty_context() {
    let context = EvaluationContext::new();

    let map = context.to_map();

    assert!(!map.contains_key("userId"));
    assert!(!map.contains_key("attributes"));
}

#[test]
fn test_context_serialization() {
    let context = EvaluationContext::with_user_id("user-123")
        .attribute("plan", "premium");

    let json = serde_json::to_string(&context).unwrap();

    assert!(json.contains("userId"));
    assert!(json.contains("user-123"));
    assert!(json.contains("attributes"));
    assert!(json.contains("plan"));
}

#[test]
fn test_context_deserialization() {
    let json = r#"{"userId":"user-123","attributes":{"plan":"premium"}}"#;

    let context: EvaluationContext = serde_json::from_str(json).unwrap();

    assert_eq!(context.user_id, Some("user-123".to_string()));
    assert!(context.get("plan").is_some());
}
