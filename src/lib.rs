//! FlagKit Rust SDK
//!
//! Official Rust SDK for FlagKit feature flag management.
//!
//! # Quick Start
//!
//! ```no_run
//! use flagkit::{FlagKit, FlagKitOptions};
//!
//! #[tokio::main]
//! async fn main() -> flagkit::Result<()> {
//!     // Initialize the SDK
//!     let options = FlagKitOptions::new("sdk_your_api_key");
//!     FlagKit::initialize(options)?;
//!
//!     // Initialize connection
//!     FlagKit::instance().initialize().await?;
//!
//!     // Identify user
//!     FlagKit::identify("user-123", None);
//!
//!     // Evaluate flags
//!     let dark_mode = FlagKit::get_boolean_value("dark-mode", false, None);
//!     let theme = FlagKit::get_string_value("theme", "light", None);
//!
//!     // Cleanup
//!     FlagKit::close();
//!
//!     Ok(())
//! }
//! ```

// Module declarations
pub mod types;
pub mod error;
pub mod http;
pub mod core;
pub mod security;
mod client;

// Re-exports from types module
pub use types::{
    EvaluationContext, EvaluationContextBuilder, EvaluationReason, EvaluationResult,
    FlagState, FlagType, FlagValue,
};

// Re-exports from error module
pub use error::{ErrorCode, FlagKitError, Result};

// Re-exports from core module
pub use core::{FlagKitOptions, FlagKitOptionsBuilder};

// Re-exports from http module
pub use http::{CircuitBreaker, CircuitState, HttpClient};

// Re-exports from client module
pub use client::{FlagKitClient, SharedClient};

use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

static INSTANCE: OnceCell<Arc<FlagKitClient>> = OnceCell::new();
static INITIALIZED: RwLock<bool> = RwLock::new(false);

/// Static factory for FlagKit SDK with singleton pattern.
pub struct FlagKit;

impl FlagKit {
    /// Gets the current client instance.
    ///
    /// # Panics
    ///
    /// Panics if the SDK has not been initialized.
    pub fn instance() -> &'static Arc<FlagKitClient> {
        INSTANCE.get().expect("FlagKit not initialized. Call FlagKit::initialize() first.")
    }

    /// Tries to get the current client instance.
    ///
    /// Returns `None` if the SDK has not been initialized.
    pub fn try_instance() -> Option<&'static Arc<FlagKitClient>> {
        INSTANCE.get()
    }

    /// Returns whether the SDK has been initialized.
    pub fn is_initialized() -> bool {
        INSTANCE.get().is_some()
    }

    /// Initializes the FlagKit SDK with the given options.
    ///
    /// # Errors
    ///
    /// Returns an error if the SDK is already initialized or if options validation fails.
    pub fn initialize(options: FlagKitOptions) -> Result<&'static Arc<FlagKitClient>> {
        let client = FlagKitClient::new(options)?;
        let client = Arc::new(client);

        INSTANCE
            .set(client)
            .map_err(|_| FlagKitError::already_initialized())?;

        Ok(INSTANCE.get().unwrap())
    }

    /// Closes the SDK.
    ///
    /// Note: Due to Rust's memory model, the singleton cannot be truly reset.
    /// This method is provided for API compatibility.
    pub fn close() {
        // In Rust, we can't actually clear a OnceCell.
        // The client will be dropped when the program ends.
    }

    // Convenience methods

    /// Identifies a user with optional attributes.
    pub fn identify(user_id: impl Into<String>, attributes: Option<HashMap<String, FlagValue>>) {
        Self::instance().identify(user_id, attributes);
    }

    /// Sets the global evaluation context.
    pub fn set_context(context: EvaluationContext) {
        Self::instance().set_context(context);
    }

    /// Clears the global evaluation context.
    pub fn clear_context() {
        Self::instance().clear_context();
    }

    /// Evaluates a flag and returns the result.
    pub fn evaluate(flag_key: &str, context: Option<&EvaluationContext>) -> EvaluationResult {
        Self::instance().evaluate(flag_key, context)
    }

    /// Gets a boolean flag value.
    pub fn get_boolean_value(
        flag_key: &str,
        default_value: bool,
        context: Option<&EvaluationContext>,
    ) -> bool {
        Self::instance().get_boolean_value(flag_key, default_value, context)
    }

    /// Gets a string flag value.
    pub fn get_string_value(
        flag_key: &str,
        default_value: &str,
        context: Option<&EvaluationContext>,
    ) -> String {
        Self::instance().get_string_value(flag_key, default_value, context)
    }

    /// Gets a numeric flag value.
    pub fn get_number_value(
        flag_key: &str,
        default_value: f64,
        context: Option<&EvaluationContext>,
    ) -> f64 {
        Self::instance().get_number_value(flag_key, default_value, context)
    }

    /// Gets an integer flag value.
    pub fn get_int_value(
        flag_key: &str,
        default_value: i64,
        context: Option<&EvaluationContext>,
    ) -> i64 {
        Self::instance().get_int_value(flag_key, default_value, context)
    }

    /// Gets a JSON flag value.
    pub fn get_json_value(
        flag_key: &str,
        default_value: Option<serde_json::Value>,
        context: Option<&EvaluationContext>,
    ) -> Option<serde_json::Value> {
        Self::instance().get_json_value(flag_key, default_value, context)
    }

    /// Gets all cached flags.
    pub fn get_all_flags() -> HashMap<String, FlagState> {
        Self::instance().get_all_flags()
    }
}
