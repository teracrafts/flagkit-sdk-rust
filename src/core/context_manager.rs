//! Context manager for global and per-evaluation context.
//!
//! This module provides a thread-safe context manager that handles
//! global evaluation context, user identification, and context merging.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::types::{EvaluationContext, FlagValue};

/// Manages global and per-evaluation context.
///
/// The context manager provides thread-safe operations for:
/// - Setting and getting global context
/// - Identifying users
/// - Merging global context with evaluation-time context
/// - Resetting to anonymous state
///
/// # Thread Safety
///
/// All operations are thread-safe using `RwLock`.
///
/// # Example
///
/// ```rust
/// use flagkit::core::ContextManager;
/// use flagkit::types::EvaluationContext;
///
/// let manager = ContextManager::new();
///
/// // Identify a user
/// manager.identify("user-123", None);
///
/// // Get the current context
/// let context = manager.get_context();
/// assert!(context.is_some());
/// ```
pub struct ContextManager {
    context: Arc<RwLock<Option<EvaluationContext>>>,
}

impl Default for ContextManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextManager {
    /// Create a new context manager.
    pub fn new() -> Self {
        Self {
            context: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a new context manager with an initial context.
    pub fn with_context(context: EvaluationContext) -> Self {
        Self {
            context: Arc::new(RwLock::new(Some(context))),
        }
    }

    /// Set the global evaluation context.
    ///
    /// This context will be used as the base for all evaluations
    /// and can be overridden by evaluation-time context.
    pub fn set_context(&self, context: EvaluationContext) {
        let mut guard = self.context.write();
        *guard = Some(context);
        tracing::debug!("Global context set");
    }

    /// Get the current global context.
    ///
    /// Returns `None` if no context has been set.
    pub fn get_context(&self) -> Option<EvaluationContext> {
        self.context.read().clone()
    }

    /// Clear the global context.
    ///
    /// After calling this, evaluations will not have a global context
    /// unless one is provided at evaluation time.
    pub fn clear_context(&self) {
        let mut guard = self.context.write();
        *guard = None;
        tracing::debug!("Global context cleared");
    }

    /// Identify a user.
    ///
    /// Sets the user ID and optional attributes in the global context.
    /// This marks the user as non-anonymous.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user identifier
    /// * `attributes` - Optional additional attributes to set
    pub fn identify(
        &self,
        user_id: impl Into<String>,
        attributes: Option<HashMap<String, FlagValue>>,
    ) {
        let user_id = user_id.into();
        tracing::debug!("Identifying user: {}", user_id);

        let mut guard = self.context.write();
        let mut context = guard.take().unwrap_or_default();

        context.user_id = Some(user_id);

        if let Some(attrs) = attributes {
            context.attributes.extend(attrs);
        }

        // Mark as non-anonymous
        context.attributes.remove("_anonymous");

        *guard = Some(context);
    }

    /// Reset the context to anonymous state.
    ///
    /// Clears the user ID and sets the anonymous flag.
    pub fn reset(&self) {
        let mut guard = self.context.write();
        *guard = Some(EvaluationContext {
            user_id: None,
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert("_anonymous".to_string(), FlagValue::Bool(true));
                attrs
            },
        });
        tracing::debug!("Context reset to anonymous");
    }

    /// Check if a user is currently identified.
    ///
    /// Returns `true` if a user ID is set and the user is not anonymous.
    pub fn is_identified(&self) -> bool {
        let guard = self.context.read();
        if let Some(ref ctx) = *guard {
            ctx.user_id.is_some()
                && !ctx
                    .attributes
                    .get("_anonymous")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
        } else {
            false
        }
    }

    /// Check if the current context is anonymous.
    ///
    /// Returns `true` if no context is set, no user ID is set,
    /// or the anonymous flag is true.
    pub fn is_anonymous(&self) -> bool {
        let guard = self.context.read();
        match *guard {
            None => true,
            Some(ref ctx) => {
                ctx.user_id.is_none()
                    || ctx
                        .attributes
                        .get("_anonymous")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
            }
        }
    }

    /// Get the current user ID if identified.
    pub fn get_user_id(&self) -> Option<String> {
        let guard = self.context.read();
        guard.as_ref().and_then(|ctx| ctx.user_id.clone())
    }

    /// Resolve context by merging global and evaluation context.
    ///
    /// The evaluation context takes precedence over global context.
    /// Private attributes (prefixed with `_`) are stripped from the result.
    ///
    /// # Arguments
    ///
    /// * `evaluation_context` - Optional context provided at evaluation time
    ///
    /// # Returns
    ///
    /// The merged context with private attributes stripped.
    pub fn resolve_context(
        &self,
        evaluation_context: Option<&EvaluationContext>,
    ) -> Option<EvaluationContext> {
        let guard = self.context.read();
        let global = guard.as_ref();

        let merged = match (global, evaluation_context) {
            (None, None) => return None,
            (Some(g), None) => g.clone(),
            (None, Some(e)) => e.clone(),
            (Some(g), Some(e)) => g.merge(Some(e)),
        };

        Some(merged.strip_private_attributes())
    }

    /// Get the raw merged context without stripping private attributes.
    ///
    /// Useful for internal evaluation that needs access to all attributes.
    pub fn get_merged_context(
        &self,
        evaluation_context: Option<&EvaluationContext>,
    ) -> Option<EvaluationContext> {
        let guard = self.context.read();
        let global = guard.as_ref();

        match (global, evaluation_context) {
            (None, None) => None,
            (Some(g), None) => Some(g.clone()),
            (None, Some(e)) => Some(e.clone()),
            (Some(g), Some(e)) => Some(g.merge(Some(e))),
        }
    }

    /// Add an attribute to the current context.
    ///
    /// Creates a new context if none exists.
    pub fn add_attribute(&self, key: impl Into<String>, value: impl Into<FlagValue>) {
        let mut guard = self.context.write();
        let context = guard.get_or_insert_with(EvaluationContext::default);
        context.attributes.insert(key.into(), value.into());
    }

    /// Remove an attribute from the current context.
    pub fn remove_attribute(&self, key: &str) -> Option<FlagValue> {
        let mut guard = self.context.write();
        if let Some(ref mut ctx) = *guard {
            ctx.attributes.remove(key)
        } else {
            None
        }
    }

    /// Get an attribute value from the current context.
    pub fn get_attribute(&self, key: &str) -> Option<FlagValue> {
        let guard = self.context.read();
        guard
            .as_ref()
            .and_then(|ctx| ctx.attributes.get(key).cloned())
    }

    /// Check if the context has a specific attribute.
    pub fn has_attribute(&self, key: &str) -> bool {
        let guard = self.context.read();
        guard
            .as_ref()
            .map(|ctx| ctx.attributes.contains_key(key))
            .unwrap_or(false)
    }
}

impl Clone for ContextManager {
    fn clone(&self) -> Self {
        Self {
            context: Arc::new(RwLock::new(self.context.read().clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_manager() {
        let manager = ContextManager::new();
        assert!(manager.get_context().is_none());
        assert!(manager.is_anonymous());
        assert!(!manager.is_identified());
    }

    #[test]
    fn test_set_and_get_context() {
        let manager = ContextManager::new();
        let context = EvaluationContext::with_user_id("user-123");

        manager.set_context(context);

        let retrieved = manager.get_context();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, Some("user-123".to_string()));
    }

    #[test]
    fn test_clear_context() {
        let manager = ContextManager::new();
        manager.set_context(EvaluationContext::with_user_id("user-123"));

        manager.clear_context();

        assert!(manager.get_context().is_none());
    }

    #[test]
    fn test_identify() {
        let manager = ContextManager::new();

        manager.identify("user-456", None);

        assert!(manager.is_identified());
        assert!(!manager.is_anonymous());
        assert_eq!(manager.get_user_id(), Some("user-456".to_string()));
    }

    #[test]
    fn test_identify_with_attributes() {
        let manager = ContextManager::new();

        let mut attrs = HashMap::new();
        attrs.insert("plan".to_string(), FlagValue::String("premium".to_string()));
        attrs.insert("beta".to_string(), FlagValue::Bool(true));

        manager.identify("user-789", Some(attrs));

        let context = manager.get_context().unwrap();
        assert_eq!(context.user_id, Some("user-789".to_string()));
        assert_eq!(
            context.attributes.get("plan"),
            Some(&FlagValue::String("premium".to_string()))
        );
        assert_eq!(
            context.attributes.get("beta"),
            Some(&FlagValue::Bool(true))
        );
    }

    #[test]
    fn test_reset() {
        let manager = ContextManager::new();
        manager.identify("user-123", None);

        manager.reset();

        assert!(manager.is_anonymous());
        assert!(!manager.is_identified());
        assert!(manager.get_user_id().is_none());
    }

    #[test]
    fn test_resolve_context_no_global() {
        let manager = ContextManager::new();

        let eval_context = EvaluationContext::with_user_id("eval-user");
        let resolved = manager.resolve_context(Some(&eval_context));

        assert!(resolved.is_some());
        assert_eq!(
            resolved.unwrap().user_id,
            Some("eval-user".to_string())
        );
    }

    #[test]
    fn test_resolve_context_merge() {
        let manager = ContextManager::new();
        manager.set_context(
            EvaluationContext::with_user_id("global-user")
                .attribute("global_attr", "global_value"),
        );

        let eval_context = EvaluationContext::new()
            .attribute("eval_attr", "eval_value");
        let resolved = manager.resolve_context(Some(&eval_context)).unwrap();

        // Eval context doesn't override user_id since it's not set
        assert_eq!(resolved.user_id, Some("global-user".to_string()));
        // Both attributes should be present
        assert!(resolved.attributes.contains_key("global_attr"));
        assert!(resolved.attributes.contains_key("eval_attr"));
    }

    #[test]
    fn test_resolve_context_strips_private() {
        let manager = ContextManager::new();
        manager.set_context(
            EvaluationContext::new()
                .attribute("_private", "secret")
                .attribute("public", "visible"),
        );

        let resolved = manager.resolve_context(None).unwrap();

        assert!(!resolved.attributes.contains_key("_private"));
        assert!(resolved.attributes.contains_key("public"));
    }

    #[test]
    fn test_add_and_get_attribute() {
        let manager = ContextManager::new();

        manager.add_attribute("key1", "value1");
        manager.add_attribute("key2", 42i64);

        assert!(manager.has_attribute("key1"));
        assert!(manager.has_attribute("key2"));
        assert!(!manager.has_attribute("key3"));

        assert_eq!(
            manager.get_attribute("key1"),
            Some(FlagValue::String("value1".to_string()))
        );
    }

    #[test]
    fn test_remove_attribute() {
        let manager = ContextManager::new();
        manager.add_attribute("key", "value");

        let removed = manager.remove_attribute("key");

        assert_eq!(
            removed,
            Some(FlagValue::String("value".to_string()))
        );
        assert!(!manager.has_attribute("key"));
    }

    #[test]
    fn test_with_context_constructor() {
        let context = EvaluationContext::with_user_id("initial-user");
        let manager = ContextManager::with_context(context);

        assert_eq!(
            manager.get_user_id(),
            Some("initial-user".to_string())
        );
    }

    #[test]
    fn test_clone() {
        let manager = ContextManager::new();
        manager.identify("user-123", None);

        let cloned = manager.clone();

        assert_eq!(manager.get_user_id(), cloned.get_user_id());

        // Modifying clone doesn't affect original
        cloned.identify("user-456", None);
        assert_eq!(manager.get_user_id(), Some("user-123".to_string()));
        assert_eq!(cloned.get_user_id(), Some("user-456".to_string()));
    }

    #[test]
    fn test_thread_safety() {
        use std::thread;

        let manager = Arc::new(ContextManager::new());
        let mut handles = vec![];

        // Spawn multiple threads that read and write
        for i in 0..10 {
            let m = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                m.identify(format!("user-{}", i), None);
                m.add_attribute(format!("key-{}", i), format!("value-{}", i));
                let _ = m.get_context();
                let _ = m.is_identified();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should be able to get context after concurrent access
        let context = manager.get_context();
        assert!(context.is_some());
    }
}
