use thiserror::Error;

pub mod sanitizer;

pub use sanitizer::{sanitize_message, ErrorSanitizationConfig, SanitizedMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    // Initialization errors
    InitFailed,
    InitTimeout,
    InitAlreadyInitialized,
    InitNotInitialized,

    // Authentication errors
    AuthInvalidKey,
    AuthExpiredKey,
    AuthMissingKey,
    AuthUnauthorized,
    AuthPermissionDenied,
    AuthIpRestricted,
    AuthOrganizationRequired,
    AuthSubscriptionSuspended,

    // Network errors
    NetworkError,
    NetworkTimeout,
    NetworkRetryLimit,
    NetworkServiceUnavailable,

    // HTTP errors
    HttpBadRequest,
    HttpUnauthorized,
    HttpForbidden,
    HttpNotFound,
    HttpRateLimited,
    HttpServerError,
    HttpTimeout,
    HttpNetworkError,
    HttpInvalidResponse,
    HttpCircuitOpen,

    // Evaluation errors
    EvalFlagNotFound,
    EvalTypeMismatch,
    EvalInvalidKey,
    EvalInvalidValue,
    EvalDisabled,
    EvalError,
    EvalContextError,
    EvalDefaultUsed,
    EvalStaleValue,
    EvalCacheMiss,
    EvalNetworkError,
    EvalParseError,
    EvalTimeoutError,

    // Cache errors
    CacheReadError,
    CacheWriteError,
    CacheInvalidData,
    CacheExpired,
    CacheStorageError,
    CacheEncryptionError,
    CacheDecryptionError,

    // Event errors
    EventQueueFull,
    EventInvalidType,
    EventInvalidData,
    EventSendFailed,
    EventFlushFailed,
    EventFlushTimeout,

    // Circuit breaker errors
    CircuitOpen,

    // SDK lifecycle errors
    SdkNotInitialized,
    SdkAlreadyInitialized,
    SdkNotReady,

    // Configuration errors
    ConfigInvalidUrl,
    ConfigInvalidInterval,
    ConfigMissingRequired,
    ConfigInvalidApiKey,
    ConfigInvalidPollingInterval,
    ConfigInvalidCacheTtl,

    // Streaming errors
    StreamingTokenInvalid,
    StreamingTokenExpired,
    StreamingSubscriptionSuspended,
    StreamingConnectionLimit,
    StreamingUnavailable,

    // Security errors
    SecurityLocalPortInProduction,
    SecurityPiiDetected,
    SecuritySignatureError,
    SecurityKeyRotationFailed,
    SecurityBootstrapVerificationFailed,
    SecurityBootstrapExpired,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::InitFailed => "INIT_FAILED",
            ErrorCode::InitTimeout => "INIT_TIMEOUT",
            ErrorCode::InitAlreadyInitialized => "INIT_ALREADY_INITIALIZED",
            ErrorCode::InitNotInitialized => "INIT_NOT_INITIALIZED",
            ErrorCode::AuthInvalidKey => "AUTH_INVALID_KEY",
            ErrorCode::AuthExpiredKey => "AUTH_EXPIRED_KEY",
            ErrorCode::AuthMissingKey => "AUTH_MISSING_KEY",
            ErrorCode::AuthUnauthorized => "AUTH_UNAUTHORIZED",
            ErrorCode::AuthPermissionDenied => "AUTH_PERMISSION_DENIED",
            ErrorCode::AuthIpRestricted => "AUTH_IP_RESTRICTED",
            ErrorCode::AuthOrganizationRequired => "AUTH_ORGANIZATION_REQUIRED",
            ErrorCode::AuthSubscriptionSuspended => "AUTH_SUBSCRIPTION_SUSPENDED",
            ErrorCode::NetworkError => "NETWORK_ERROR",
            ErrorCode::NetworkTimeout => "NETWORK_TIMEOUT",
            ErrorCode::NetworkRetryLimit => "NETWORK_RETRY_LIMIT",
            ErrorCode::NetworkServiceUnavailable => "NETWORK_SERVICE_UNAVAILABLE",
            ErrorCode::HttpBadRequest => "HTTP_BAD_REQUEST",
            ErrorCode::HttpUnauthorized => "HTTP_UNAUTHORIZED",
            ErrorCode::HttpForbidden => "HTTP_FORBIDDEN",
            ErrorCode::HttpNotFound => "HTTP_NOT_FOUND",
            ErrorCode::HttpRateLimited => "HTTP_RATE_LIMITED",
            ErrorCode::HttpServerError => "HTTP_SERVER_ERROR",
            ErrorCode::HttpTimeout => "HTTP_TIMEOUT",
            ErrorCode::HttpNetworkError => "HTTP_NETWORK_ERROR",
            ErrorCode::HttpInvalidResponse => "HTTP_INVALID_RESPONSE",
            ErrorCode::HttpCircuitOpen => "HTTP_CIRCUIT_OPEN",
            ErrorCode::EvalFlagNotFound => "EVAL_FLAG_NOT_FOUND",
            ErrorCode::EvalTypeMismatch => "EVAL_TYPE_MISMATCH",
            ErrorCode::EvalInvalidKey => "EVAL_INVALID_KEY",
            ErrorCode::EvalInvalidValue => "EVAL_INVALID_VALUE",
            ErrorCode::EvalDisabled => "EVAL_DISABLED",
            ErrorCode::EvalError => "EVAL_ERROR",
            ErrorCode::EvalContextError => "EVAL_CONTEXT_ERROR",
            ErrorCode::EvalDefaultUsed => "EVAL_DEFAULT_USED",
            ErrorCode::EvalStaleValue => "EVAL_STALE_VALUE",
            ErrorCode::EvalCacheMiss => "EVAL_CACHE_MISS",
            ErrorCode::EvalNetworkError => "EVAL_NETWORK_ERROR",
            ErrorCode::EvalParseError => "EVAL_PARSE_ERROR",
            ErrorCode::EvalTimeoutError => "EVAL_TIMEOUT_ERROR",
            ErrorCode::CacheReadError => "CACHE_READ_ERROR",
            ErrorCode::CacheWriteError => "CACHE_WRITE_ERROR",
            ErrorCode::CacheInvalidData => "CACHE_INVALID_DATA",
            ErrorCode::CacheExpired => "CACHE_EXPIRED",
            ErrorCode::CacheStorageError => "CACHE_STORAGE_ERROR",
            ErrorCode::EventQueueFull => "EVENT_QUEUE_FULL",
            ErrorCode::EventInvalidType => "EVENT_INVALID_TYPE",
            ErrorCode::EventInvalidData => "EVENT_INVALID_DATA",
            ErrorCode::EventSendFailed => "EVENT_SEND_FAILED",
            ErrorCode::EventFlushFailed => "EVENT_FLUSH_FAILED",
            ErrorCode::EventFlushTimeout => "EVENT_FLUSH_TIMEOUT",
            ErrorCode::CircuitOpen => "CIRCUIT_OPEN",
            ErrorCode::SdkNotInitialized => "SDK_NOT_INITIALIZED",
            ErrorCode::SdkAlreadyInitialized => "SDK_ALREADY_INITIALIZED",
            ErrorCode::SdkNotReady => "SDK_NOT_READY",
            ErrorCode::ConfigInvalidUrl => "CONFIG_INVALID_URL",
            ErrorCode::ConfigInvalidInterval => "CONFIG_INVALID_INTERVAL",
            ErrorCode::ConfigMissingRequired => "CONFIG_MISSING_REQUIRED",
            ErrorCode::ConfigInvalidApiKey => "CONFIG_INVALID_API_KEY",
            ErrorCode::ConfigInvalidPollingInterval => "CONFIG_INVALID_POLLING_INTERVAL",
            ErrorCode::ConfigInvalidCacheTtl => "CONFIG_INVALID_CACHE_TTL",
            ErrorCode::CacheEncryptionError => "CACHE_ENCRYPTION_ERROR",
            ErrorCode::CacheDecryptionError => "CACHE_DECRYPTION_ERROR",
            ErrorCode::StreamingTokenInvalid => "STREAMING_TOKEN_INVALID",
            ErrorCode::StreamingTokenExpired => "STREAMING_TOKEN_EXPIRED",
            ErrorCode::StreamingSubscriptionSuspended => "STREAMING_SUBSCRIPTION_SUSPENDED",
            ErrorCode::StreamingConnectionLimit => "STREAMING_CONNECTION_LIMIT",
            ErrorCode::StreamingUnavailable => "STREAMING_UNAVAILABLE",
            ErrorCode::SecurityLocalPortInProduction => "SECURITY_LOCAL_PORT_IN_PRODUCTION",
            ErrorCode::SecurityPiiDetected => "SECURITY_PII_DETECTED",
            ErrorCode::SecuritySignatureError => "SECURITY_SIGNATURE_ERROR",
            ErrorCode::SecurityKeyRotationFailed => "SECURITY_KEY_ROTATION_FAILED",
            ErrorCode::SecurityBootstrapVerificationFailed => "SECURITY_BOOTSTRAP_VERIFICATION_FAILED",
            ErrorCode::SecurityBootstrapExpired => "SECURITY_BOOTSTRAP_EXPIRED",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            ErrorCode::NetworkError
                | ErrorCode::NetworkTimeout
                | ErrorCode::NetworkRetryLimit
                | ErrorCode::NetworkServiceUnavailable
                | ErrorCode::CircuitOpen
                | ErrorCode::HttpCircuitOpen
                | ErrorCode::HttpTimeout
                | ErrorCode::HttpNetworkError
                | ErrorCode::HttpServerError
                | ErrorCode::HttpRateLimited
                | ErrorCode::CacheExpired
                | ErrorCode::EvalStaleValue
                | ErrorCode::EvalCacheMiss
                | ErrorCode::EvalNetworkError
                | ErrorCode::EventSendFailed
                | ErrorCode::StreamingTokenInvalid
                | ErrorCode::StreamingTokenExpired
                | ErrorCode::StreamingConnectionLimit
                | ErrorCode::StreamingUnavailable
        )
    }
}

#[derive(Error, Debug)]
#[error("[{code}] {message}")]
pub struct FlagKitError {
    pub code: ErrorCode,
    pub message: String,
    /// The original unsanitized message, if preservation is enabled.
    original_message: Option<String>,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl FlagKitError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            original_message: None,
            source: None,
        }
    }

    /// Create a new error with sanitization applied.
    pub fn new_sanitized(
        code: ErrorCode,
        message: impl Into<String>,
        config: &ErrorSanitizationConfig,
    ) -> Self {
        let msg = message.into();
        let sanitized_msg = SanitizedMessage::new(&msg, config);
        Self {
            code,
            message: sanitized_msg.sanitized,
            original_message: sanitized_msg.original,
            source: None,
        }
    }

    pub fn with_source(
        code: ErrorCode,
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            original_message: None,
            source: Some(Box::new(source)),
        }
    }

    /// Create a new error with source and sanitization applied.
    pub fn with_source_sanitized(
        code: ErrorCode,
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
        config: &ErrorSanitizationConfig,
    ) -> Self {
        let msg = message.into();
        let sanitized_msg = SanitizedMessage::new(&msg, config);
        Self {
            code,
            message: sanitized_msg.sanitized,
            original_message: sanitized_msg.original,
            source: Some(Box::new(source)),
        }
    }

    /// Get the original unsanitized message if available.
    pub fn original_message(&self) -> Option<&str> {
        self.original_message.as_deref()
    }

    /// Sanitize this error's message in place.
    pub fn sanitize(&mut self, config: &ErrorSanitizationConfig) {
        if config.enabled {
            let sanitized = SanitizedMessage::new(&self.message, config);
            if config.preserve_original && self.original_message.is_none() {
                self.original_message = Some(self.message.clone());
            }
            self.message = sanitized.sanitized;
        }
    }

    /// Create a sanitized copy of this error.
    pub fn sanitized(&self, config: &ErrorSanitizationConfig) -> Self {
        let sanitized_msg = SanitizedMessage::new(&self.message, config);
        Self {
            code: self.code,
            message: sanitized_msg.sanitized,
            original_message: if config.preserve_original {
                Some(self.message.clone())
            } else {
                None
            },
            source: None, // Cannot clone the source
        }
    }

    pub fn config_error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message)
    }

    pub fn network_error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message)
    }

    pub fn evaluation_error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message)
    }

    pub fn not_initialized() -> Self {
        Self::new(
            ErrorCode::SdkNotInitialized,
            "SDK not initialized. Call FlagKit::initialize() first.",
        )
    }

    pub fn already_initialized() -> Self {
        Self::new(ErrorCode::SdkAlreadyInitialized, "SDK already initialized.")
    }

    pub fn is_recoverable(&self) -> bool {
        self.code.is_recoverable()
    }

    pub fn is_config_error(&self) -> bool {
        matches!(
            self.code,
            ErrorCode::ConfigInvalidUrl
                | ErrorCode::ConfigInvalidInterval
                | ErrorCode::ConfigMissingRequired
                | ErrorCode::ConfigInvalidApiKey
                | ErrorCode::ConfigInvalidPollingInterval
                | ErrorCode::ConfigInvalidCacheTtl
        )
    }

    pub fn is_network_error(&self) -> bool {
        matches!(
            self.code,
            ErrorCode::NetworkError
                | ErrorCode::NetworkTimeout
                | ErrorCode::NetworkRetryLimit
                | ErrorCode::HttpBadRequest
                | ErrorCode::HttpUnauthorized
                | ErrorCode::HttpForbidden
                | ErrorCode::HttpNotFound
                | ErrorCode::HttpRateLimited
                | ErrorCode::HttpServerError
                | ErrorCode::HttpTimeout
                | ErrorCode::HttpNetworkError
                | ErrorCode::HttpInvalidResponse
                | ErrorCode::HttpCircuitOpen
        )
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type Result<T> = std::result::Result<T, FlagKitError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flagkit_error_new_sanitized() {
        let config = ErrorSanitizationConfig::default();
        let error = FlagKitError::new_sanitized(
            ErrorCode::NetworkError,
            "Failed to connect to 192.168.1.1",
            &config,
        );
        assert_eq!(error.message, "Failed to connect to [IP]");
        assert!(error.original_message().is_none());
    }

    #[test]
    fn test_flagkit_error_new_sanitized_disabled() {
        let config = ErrorSanitizationConfig::disabled();
        let error = FlagKitError::new_sanitized(
            ErrorCode::NetworkError,
            "Failed to connect to 192.168.1.1",
            &config,
        );
        assert_eq!(error.message, "Failed to connect to 192.168.1.1");
    }

    #[test]
    fn test_flagkit_error_new_sanitized_with_preservation() {
        let config = ErrorSanitizationConfig::with_preservation();
        let original = "Failed to connect to 192.168.1.1";
        let error = FlagKitError::new_sanitized(ErrorCode::NetworkError, original, &config);
        assert_eq!(error.message, "Failed to connect to [IP]");
        assert_eq!(error.original_message(), Some(original));
    }

    #[test]
    fn test_flagkit_error_sanitize_in_place() {
        let config = ErrorSanitizationConfig::default();
        let mut error = FlagKitError::new(
            ErrorCode::AuthInvalidKey,
            "Invalid API key: sdk_secret12345678",
        );
        error.sanitize(&config);
        assert_eq!(error.message, "Invalid API key: sdk_[REDACTED]");
    }

    #[test]
    fn test_flagkit_error_sanitize_in_place_with_preservation() {
        let config = ErrorSanitizationConfig::with_preservation();
        let original = "Invalid API key: sdk_secret12345678";
        let mut error = FlagKitError::new(ErrorCode::AuthInvalidKey, original);
        error.sanitize(&config);
        assert_eq!(error.message, "Invalid API key: sdk_[REDACTED]");
        assert_eq!(error.original_message(), Some(original));
    }

    #[test]
    fn test_flagkit_error_sanitized_copy() {
        let config = ErrorSanitizationConfig::default();
        let original_error =
            FlagKitError::new(ErrorCode::NetworkError, "Error at /var/log/app.log");
        let sanitized_error = original_error.sanitized(&config);
        assert_eq!(sanitized_error.message, "Error at [PATH]");
        assert_eq!(original_error.message, "Error at /var/log/app.log");
    }

    #[test]
    fn test_flagkit_error_with_source_sanitized() {
        let config = ErrorSanitizationConfig::default();
        let source_error = std::io::Error::new(std::io::ErrorKind::Other, "source");
        let error = FlagKitError::with_source_sanitized(
            ErrorCode::CacheReadError,
            "Failed reading /etc/config/secrets.json",
            source_error,
            &config,
        );
        assert_eq!(error.message, "Failed reading [PATH]");
        assert!(error.source.is_some());
    }

    #[test]
    fn test_flagkit_error_display_sanitized() {
        let config = ErrorSanitizationConfig::default();
        let error = FlagKitError::new_sanitized(
            ErrorCode::NetworkError,
            "Connection to user@example.com at 10.0.0.1 failed",
            &config,
        );
        let displayed = format!("{}", error);
        assert!(displayed.contains("[NETWORK_ERROR]"));
        assert!(displayed.contains("[EMAIL]"));
        assert!(displayed.contains("[IP]"));
        assert!(!displayed.contains("user@example.com"));
        assert!(!displayed.contains("10.0.0.1"));
    }

    #[test]
    fn test_flagkit_error_sanitize_api_keys() {
        let config = ErrorSanitizationConfig::default();
        let error = FlagKitError::new_sanitized(
            ErrorCode::AuthInvalidKey,
            "Keys: sdk_abc123xyz789, srv_server_key_test, cli_client_key_here",
            &config,
        );
        assert!(!error.message.contains("abc123xyz"));
        assert!(!error.message.contains("server_key"));
        assert!(!error.message.contains("client_key"));
        assert!(error.message.contains("sdk_[REDACTED]"));
        assert!(error.message.contains("srv_[REDACTED]"));
        assert!(error.message.contains("cli_[REDACTED]"));
    }

    #[test]
    fn test_flagkit_error_sanitize_connection_strings() {
        let config = ErrorSanitizationConfig::default();
        let error = FlagKitError::new_sanitized(
            ErrorCode::CacheStorageError,
            "Cannot connect to postgres://admin:password@db.internal:5432/production",
            &config,
        );
        assert_eq!(error.message, "Cannot connect to [CONNECTION_STRING]");
        assert!(!error.message.contains("admin:password"));
    }
}
