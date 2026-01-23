use thiserror::Error;

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

    // Network errors
    NetworkError,
    NetworkTimeout,
    NetworkRetryLimit,

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
    ConfigInvalidBaseUrl,
    ConfigInvalidPollingInterval,
    ConfigInvalidCacheTtl,
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
            ErrorCode::NetworkError => "NETWORK_ERROR",
            ErrorCode::NetworkTimeout => "NETWORK_TIMEOUT",
            ErrorCode::NetworkRetryLimit => "NETWORK_RETRY_LIMIT",
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
            ErrorCode::ConfigInvalidBaseUrl => "CONFIG_INVALID_BASE_URL",
            ErrorCode::ConfigInvalidPollingInterval => "CONFIG_INVALID_POLLING_INTERVAL",
            ErrorCode::ConfigInvalidCacheTtl => "CONFIG_INVALID_CACHE_TTL",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            ErrorCode::NetworkError
                | ErrorCode::NetworkTimeout
                | ErrorCode::NetworkRetryLimit
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
        )
    }
}

#[derive(Error, Debug)]
#[error("[{code}] {message}")]
pub struct FlagKitError {
    pub code: ErrorCode,
    pub message: String,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl FlagKitError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
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
            source: Some(Box::new(source)),
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
                | ErrorCode::ConfigInvalidBaseUrl
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
