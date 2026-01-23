use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::core::{FlagCache, FlagKitOptions};
use crate::error::{Result};
use crate::http::HttpClient;
use crate::types::{EvaluationContext, EvaluationReason, EvaluationResult, FlagState, FlagValue};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitResponse {
    pub flags: Vec<FlagState>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatesResponse {
    pub flags: Option<Vec<FlagState>>,
    pub has_updates: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluateRequest {
    pub flag_key: String,
    pub context: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluateResponse {
    pub flag_key: String,
    pub value: FlagValue,
    pub enabled: bool,
    pub reason: EvaluationReason,
    pub version: i32,
}

pub struct FlagKitClient {
    options: FlagKitOptions,
    http_client: HttpClient,
    cache: FlagCache,
    global_context: RwLock<EvaluationContext>,
    initialized: RwLock<bool>,
}

impl FlagKitClient {
    pub fn new(options: FlagKitOptions) -> Result<Self> {
        options.validate()?;

        let http_client = HttpClient::new(options.clone())?;
        let cache = FlagCache::new(options.max_cache_size, options.cache_ttl);

        let client = Self {
            options: options.clone(),
            http_client,
            cache,
            global_context: RwLock::new(EvaluationContext::new()),
            initialized: RwLock::new(false),
        };

        // Load bootstrap data if provided
        if let Some(ref bootstrap) = options.bootstrap {
            for (key, value) in bootstrap {
                let flag = FlagState::new(key.clone(), FlagValue::from(value.clone()));
                client.cache.set(key.clone(), flag);
            }
        }

        Ok(client)
    }

    pub fn is_initialized(&self) -> bool {
        *self.initialized.read()
    }

    pub async fn initialize(&self) -> Result<()> {
        let response: InitResponse = self.http_client.get("/sdk/init").await?;

        for flag in response.flags {
            self.cache.set(flag.key.clone(), flag);
        }

        *self.initialized.write() = true;

        Ok(())
    }

    pub fn identify(&self, user_id: impl Into<String>, attributes: Option<HashMap<String, FlagValue>>) {
        let mut context = self.global_context.write();
        *context = context.clone().user_id(user_id);

        if let Some(attrs) = attributes {
            *context = context.clone().attributes(attrs);
        }
    }

    pub fn set_context(&self, context: EvaluationContext) {
        *self.global_context.write() = context;
    }

    pub fn clear_context(&self) {
        *self.global_context.write() = EvaluationContext::new();
    }

    pub fn global_context(&self) -> EvaluationContext {
        self.global_context.read().clone()
    }

    pub fn evaluate(&self, flag_key: &str, context: Option<&EvaluationContext>) -> EvaluationResult {
        let _merged_context = self.merge_context(context);
        let flag = self.cache.get(flag_key);

        match flag {
            None => EvaluationResult::default_result(
                flag_key,
                FlagValue::Null,
                EvaluationReason::FlagNotFound,
            ),
            Some(flag) => EvaluationResult {
                flag_key: flag_key.to_string(),
                value: flag.value.clone(),
                enabled: flag.enabled,
                reason: EvaluationReason::Cached,
                version: flag.version,
                timestamp: Utc::now(),
            },
        }
    }

    pub async fn evaluate_async(
        &self,
        flag_key: &str,
        context: Option<&EvaluationContext>,
    ) -> EvaluationResult {
        let merged_context = self.merge_context(context);

        let request = EvaluateRequest {
            flag_key: flag_key.to_string(),
            context: Some(merged_context.strip_private_attributes().to_map()),
        };

        match self.http_client.post::<_, EvaluateResponse>("/sdk/evaluate", &request).await {
            Ok(response) => EvaluationResult {
                flag_key: response.flag_key,
                value: response.value,
                enabled: response.enabled,
                reason: response.reason,
                version: response.version,
                timestamp: Utc::now(),
            },
            Err(_) => self.evaluate(flag_key, context),
        }
    }

    pub fn get_boolean_value(
        &self,
        flag_key: &str,
        default_value: bool,
        context: Option<&EvaluationContext>,
    ) -> bool {
        let result = self.evaluate(flag_key, context);
        if result.reason == EvaluationReason::FlagNotFound {
            default_value
        } else {
            result.bool_value()
        }
    }

    pub fn get_string_value(
        &self,
        flag_key: &str,
        default_value: &str,
        context: Option<&EvaluationContext>,
    ) -> String {
        let result = self.evaluate(flag_key, context);
        if result.reason == EvaluationReason::FlagNotFound {
            default_value.to_string()
        } else {
            result.string_value().map(|s| s.to_string()).unwrap_or_else(|| default_value.to_string())
        }
    }

    pub fn get_number_value(
        &self,
        flag_key: &str,
        default_value: f64,
        context: Option<&EvaluationContext>,
    ) -> f64 {
        let result = self.evaluate(flag_key, context);
        if result.reason == EvaluationReason::FlagNotFound {
            default_value
        } else {
            result.number_value()
        }
    }

    pub fn get_int_value(
        &self,
        flag_key: &str,
        default_value: i64,
        context: Option<&EvaluationContext>,
    ) -> i64 {
        let result = self.evaluate(flag_key, context);
        if result.reason == EvaluationReason::FlagNotFound {
            default_value
        } else {
            result.int_value()
        }
    }

    pub fn get_json_value(
        &self,
        flag_key: &str,
        default_value: Option<serde_json::Value>,
        context: Option<&EvaluationContext>,
    ) -> Option<serde_json::Value> {
        let result = self.evaluate(flag_key, context);
        if result.reason == EvaluationReason::FlagNotFound {
            default_value
        } else {
            result.json_value().cloned().or(default_value)
        }
    }

    pub fn get_all_flags(&self) -> HashMap<String, FlagState> {
        self.cache.get_all()
    }

    pub async fn poll_for_updates(&self, since: Option<&str>) -> Result<()> {
        let path = match since {
            Some(s) => format!("/sdk/updates?since={}", s),
            None => "/sdk/updates".to_string(),
        };

        let response: UpdatesResponse = self.http_client.get(&path).await?;

        if response.has_updates {
            if let Some(flags) = response.flags {
                for flag in flags {
                    self.cache.set(flag.key.clone(), flag);
                }
            }
        }

        Ok(())
    }

    fn merge_context(&self, context: Option<&EvaluationContext>) -> EvaluationContext {
        let global = self.global_context.read();
        global.merge(context)
    }
}

pub type SharedClient = Arc<FlagKitClient>;
