use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlagType {
    Boolean,
    String,
    Number,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationReason {
    Cached,
    Default,
    FlagNotFound,
    Bootstrap,
    Server,
    StaleCache,
    Error,
    Disabled,
    TypeMismatch,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FlagValue {
    Bool(bool),
    String(String),
    Number(f64),
    Json(serde_json::Value),
    Null,
}

impl FlagValue {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            FlagValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            FlagValue::String(s) => Some(s),
            FlagValue::Bool(_) => None,
            FlagValue::Number(_) => None,
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<f64> {
        match self {
            FlagValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            FlagValue::Number(n) => Some(*n as i64),
            _ => None,
        }
    }

    pub fn as_json(&self) -> Option<&serde_json::Value> {
        match self {
            FlagValue::Json(v) => Some(v),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, FlagValue::Null)
    }

    pub fn inferred_type(&self) -> FlagType {
        match self {
            FlagValue::Bool(_) => FlagType::Boolean,
            FlagValue::String(_) => FlagType::String,
            FlagValue::Number(_) => FlagType::Number,
            FlagValue::Json(_) | FlagValue::Null => FlagType::Json,
        }
    }
}

impl From<bool> for FlagValue {
    fn from(value: bool) -> Self {
        FlagValue::Bool(value)
    }
}

impl From<String> for FlagValue {
    fn from(value: String) -> Self {
        FlagValue::String(value)
    }
}

impl From<&str> for FlagValue {
    fn from(value: &str) -> Self {
        FlagValue::String(value.to_string())
    }
}

impl From<f64> for FlagValue {
    fn from(value: f64) -> Self {
        FlagValue::Number(value)
    }
}

impl From<i64> for FlagValue {
    fn from(value: i64) -> Self {
        FlagValue::Number(value as f64)
    }
}

impl From<i32> for FlagValue {
    fn from(value: i32) -> Self {
        FlagValue::Number(value as f64)
    }
}

impl From<serde_json::Value> for FlagValue {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Bool(b) => FlagValue::Bool(b),
            serde_json::Value::String(s) => FlagValue::String(s),
            serde_json::Value::Number(n) => FlagValue::Number(n.as_f64().unwrap_or(0.0)),
            serde_json::Value::Null => FlagValue::Null,
            other => FlagValue::Json(other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlagState {
    pub key: String,
    pub value: FlagValue,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub version: i32,
    pub flag_type: Option<FlagType>,
    pub last_modified: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

fn default_enabled() -> bool {
    true
}

impl FlagState {
    pub fn new(key: impl Into<String>, value: FlagValue) -> Self {
        Self {
            key: key.into(),
            value,
            enabled: true,
            version: 0,
            flag_type: None,
            last_modified: None,
            metadata: None,
        }
    }

    pub fn effective_flag_type(&self) -> FlagType {
        self.flag_type.unwrap_or_else(|| self.value.inferred_type())
    }

    pub fn bool_value(&self) -> bool {
        self.value.as_bool().unwrap_or(false)
    }

    pub fn string_value(&self) -> Option<&str> {
        self.value.as_string()
    }

    pub fn number_value(&self) -> f64 {
        self.value.as_number().unwrap_or(0.0)
    }

    pub fn int_value(&self) -> i64 {
        self.value.as_int().unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub flag_key: String,
    pub value: FlagValue,
    pub enabled: bool,
    pub reason: EvaluationReason,
    pub version: i32,
    pub timestamp: DateTime<Utc>,
}

impl EvaluationResult {
    pub fn default_result(key: impl Into<String>, default_value: FlagValue, reason: EvaluationReason) -> Self {
        Self {
            flag_key: key.into(),
            value: default_value,
            enabled: false,
            reason,
            version: 0,
            timestamp: Utc::now(),
        }
    }

    pub fn bool_value(&self) -> bool {
        self.value.as_bool().unwrap_or(false)
    }

    pub fn string_value(&self) -> Option<&str> {
        self.value.as_string()
    }

    pub fn number_value(&self) -> f64 {
        self.value.as_number().unwrap_or(0.0)
    }

    pub fn int_value(&self) -> i64 {
        self.value.as_int().unwrap_or(0)
    }

    pub fn json_value(&self) -> Option<&serde_json::Value> {
        self.value.as_json()
    }
}

// EvaluationContext moved here from context.rs
const PRIVATE_ATTRIBUTE_PREFIX: &str = "_";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, FlagValue>,
}

impl EvaluationContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_user_id(user_id: impl Into<String>) -> Self {
        Self {
            user_id: Some(user_id.into()),
            attributes: HashMap::new(),
        }
    }

    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<FlagValue>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    pub fn attributes(mut self, attrs: HashMap<String, FlagValue>) -> Self {
        self.attributes.extend(attrs);
        self
    }

    pub fn merge(&self, other: Option<&EvaluationContext>) -> EvaluationContext {
        match other {
            None => self.clone(),
            Some(other) => {
                let mut merged = self.clone();
                if other.user_id.is_some() {
                    merged.user_id = other.user_id.clone();
                }
                merged.attributes.extend(other.attributes.clone());
                merged
            }
        }
    }

    pub fn strip_private_attributes(&self) -> EvaluationContext {
        let filtered: HashMap<String, FlagValue> = self
            .attributes
            .iter()
            .filter(|(key, _)| !key.starts_with(PRIVATE_ATTRIBUTE_PREFIX))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        EvaluationContext {
            user_id: self.user_id.clone(),
            attributes: filtered,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.user_id.is_none() && self.attributes.is_empty()
    }

    pub fn get(&self, key: &str) -> Option<&FlagValue> {
        self.attributes.get(key)
    }

    pub fn to_map(&self) -> HashMap<String, serde_json::Value> {
        let mut result = HashMap::new();
        if let Some(ref user_id) = self.user_id {
            result.insert("userId".to_string(), serde_json::Value::String(user_id.clone()));
        }
        if !self.attributes.is_empty() {
            let attrs: HashMap<String, serde_json::Value> = self
                .attributes
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap_or(serde_json::Value::Null)))
                .collect();
            result.insert("attributes".to_string(), serde_json::to_value(attrs).unwrap_or(serde_json::Value::Null));
        }
        result
    }
}

pub struct EvaluationContextBuilder {
    user_id: Option<String>,
    attributes: HashMap<String, FlagValue>,
}

impl EvaluationContextBuilder {
    pub fn new() -> Self {
        Self {
            user_id: None,
            attributes: HashMap::new(),
        }
    }

    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<FlagValue>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> EvaluationContext {
        EvaluationContext {
            user_id: self.user_id,
            attributes: self.attributes,
        }
    }
}

impl Default for EvaluationContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_merge() {
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
    fn test_strip_private_attributes() {
        let context = EvaluationContext::new()
            .attribute("_privateKey", "secret")
            .attribute("publicKey", "visible");

        let stripped = context.strip_private_attributes();

        assert!(stripped.get("_privateKey").is_none());
        assert!(stripped.get("publicKey").is_some());
    }
}
