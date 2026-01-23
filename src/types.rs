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
            FlagValue::Bool(b) => None,
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
