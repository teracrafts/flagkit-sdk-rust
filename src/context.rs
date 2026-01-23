use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::FlagValue;

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
