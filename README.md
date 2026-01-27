# FlagKit Rust SDK

Official Rust SDK for [FlagKit](https://flagkit.dev) feature flag service.

## Requirements

- Rust 1.70 or later
- Tokio runtime

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
flagkit = "1.0"
tokio = { version = "1.0", features = ["rt-multi-thread", "macros"] }
```

## Features

- **Type-safe evaluation** - Boolean, string, number, and JSON flag types
- **Local caching** - Fast evaluations with configurable TTL and optional encryption
- **Background polling** - Automatic flag updates with async runtime
- **Event tracking** - Analytics with batching and crash-resilient persistence
- **Resilient** - Circuit breaker, retry with exponential backoff, offline support
- **Thread-safe** - Safe for concurrent use across threads
- **Security** - PII detection, request signing, bootstrap verification, cache encryption

## Architecture

The SDK is organized into clean, modular components:

```
flagkit/
├── lib.rs               # Public exports and FlagKit factory
├── client.rs            # FlagKitClient implementation
├── core/                # Core components
│   ├── config.rs        # FlagKitOptions configuration
│   ├── cache.rs         # In-memory cache with TTL
│   ├── context_manager.rs
│   ├── polling_manager.rs
│   └── event_queue.rs   # Event batching
├── http/                # HTTP client, circuit breaker, retry
│   ├── client.rs
│   └── circuit_breaker.rs
├── error/               # Error types and codes
│   ├── mod.rs
│   └── sanitizer.rs     # Error message sanitization
├── types/               # Type definitions
│   └── mod.rs           # EvaluationContext, EvaluationResult, FlagState
├── security.rs          # PII detection, HMAC signing, encryption
└── event_persistence.rs # Crash-resilient persistence
```

## Quick Start

```rust
use flagkit::{FlagKit, FlagKitOptions};

#[tokio::main]
async fn main() -> flagkit::Result<()> {
    // Initialize the SDK
    let options = FlagKitOptions::new("sdk_your_api_key");
    FlagKit::initialize(options)?;

    // Initialize connection
    FlagKit::instance().initialize().await?;

    // Identify user
    FlagKit::identify("user-123", None);

    // Evaluate flags
    let dark_mode = FlagKit::get_boolean_value("dark-mode", false, None);
    let theme = FlagKit::get_string_value("theme", "light", None);
    let max_items = FlagKit::get_int_value("max-items", 10, None);

    println!("Dark mode: {}", dark_mode);
    println!("Theme: {}", theme);
    println!("Max items: {}", max_items);

    Ok(())
}
```

## Configuration

```rust
use flagkit::{FlagKitOptions, FlagKit};
use std::time::Duration;

let options = FlagKitOptions::builder("sdk_your_api_key")
    .polling_interval(Duration::from_secs(60))
    .cache_ttl(Duration::from_secs(600))
    .max_cache_size(500)
    .cache_enabled(true)
    .event_batch_size(20)
    .event_flush_interval(Duration::from_secs(60))
    .events_enabled(true)
    .timeout(Duration::from_secs(30))
    .retry_attempts(5)
    .build();

FlagKit::initialize(options)?;
```

## Evaluation Context

Provide context for targeting rules:

```rust
use flagkit::{EvaluationContext, EvaluationContextBuilder, FlagKit, FlagValue};
use std::collections::HashMap;

// Using builder pattern
let context = EvaluationContextBuilder::new()
    .user_id("user-123")
    .attribute("plan", "premium")
    .attribute("beta", true)
    .attribute("score", 95.5)
    .build();

let result = FlagKit::evaluate("feature-flag", Some(&context));

// Using fluent methods
let context = EvaluationContext::with_user_id("user-123")
    .attribute("plan", "premium")
    .attribute("beta", true);
```

## Flag Evaluation

### Basic Evaluation

```rust
// Boolean flags
let enabled = FlagKit::get_boolean_value("feature-enabled", false, None);

// String flags
let variant = FlagKit::get_string_value("experiment-variant", "control", None);

// Number flags
let limit = FlagKit::get_number_value("rate-limit", 100.0, None);
let count = FlagKit::get_int_value("max-count", 10, None);

// JSON flags
let config = FlagKit::get_json_value("feature-config", None, None);
```

### Detailed Evaluation

```rust
let result = FlagKit::evaluate("feature-flag", None);

println!("Flag: {}", result.flag_key);
println!("Value: {:?}", result.value);
println!("Enabled: {}", result.enabled);
println!("Reason: {:?}", result.reason);
println!("Version: {}", result.version);
```

### Async Evaluation

```rust
// Server-side evaluation with full context
let result = FlagKit::instance()
    .evaluate_async("feature-flag", Some(&context))
    .await;
```

## User Identification

```rust
use std::collections::HashMap;
use flagkit::{FlagKit, FlagValue};

// Identify user with attributes
let mut attributes = HashMap::new();
attributes.insert("email".to_string(), FlagValue::from("user@example.com"));
attributes.insert("plan".to_string(), FlagValue::from("enterprise"));

FlagKit::identify("user-123", Some(attributes));

// Update context
FlagKit::set_context(EvaluationContext::with_user_id("user-456")
    .attribute("admin", true));

// Clear context
FlagKit::clear_context();
```

## Bootstrap Data

Initialize with local flag data for instant evaluation:

```rust
use std::collections::HashMap;
use serde_json::json;

let mut bootstrap = HashMap::new();
bootstrap.insert("dark-mode".to_string(), json!(true));
bootstrap.insert("theme".to_string(), json!("dark"));
bootstrap.insert("max-items".to_string(), json!(50));

let options = FlagKitOptions::builder("sdk_your_api_key")
    .bootstrap(bootstrap)
    .build();

FlagKit::initialize(options)?;
// Flags available immediately from bootstrap
```

## Error Handling

```rust
use flagkit::{FlagKit, FlagKitOptions, FlagKitError, ErrorCode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = FlagKitOptions::new("sdk_your_api_key");

    match FlagKit::initialize(options) {
        Ok(_) => println!("Initialized"),
        Err(e) if e.is_config_error() => {
            println!("Configuration error: {}", e);
        }
        Err(e) if e.is_network_error() => {
            println!("Network error: {}", e);
        }
        Err(e) => {
            println!("Error [{}]: {}", e.code, e.message);
        }
    }

    Ok(())
}
```

## Thread Safety

The SDK is thread-safe and can be used from multiple threads:

```rust
use std::thread;
use flagkit::FlagKit;

let handles: Vec<_> = (0..10)
    .map(|i| {
        thread::spawn(move || {
            let value = FlagKit::get_boolean_value("feature", false, None);
            println!("Thread {}: {}", i, value);
        })
    })
    .collect();

for handle in handles {
    handle.join().unwrap();
}
```

## API Reference

### FlagKit (Static Factory)

| Method | Description |
|--------|-------------|
| `initialize(options)` | Initialize SDK with options |
| `instance()` | Get client instance |
| `is_initialized()` | Check if SDK is initialized |
| `close()` | Close SDK |
| `identify(user_id, attributes)` | Set user context |
| `set_context(context)` | Set evaluation context |
| `clear_context()` | Clear evaluation context |
| `evaluate(flag_key, context)` | Evaluate a flag |
| `get_boolean_value(...)` | Get boolean flag value |
| `get_string_value(...)` | Get string flag value |
| `get_number_value(...)` | Get number flag value |
| `get_int_value(...)` | Get integer flag value |
| `get_json_value(...)` | Get JSON flag value |
| `get_all_flags()` | Get all cached flags |

### FlagKitOptions

| Property | Default | Description |
|----------|---------|-------------|
| `api_key` | (required) | API key for authentication |
| `polling_interval` | 30s | Polling interval |
| `cache_ttl` | 5min | Cache time-to-live |
| `max_cache_size` | 1000 | Maximum cache entries |
| `cache_enabled` | true | Enable caching |
| `event_batch_size` | 10 | Events per batch |
| `event_flush_interval` | 30s | Event flush interval |
| `events_enabled` | true | Enable event tracking |
| `timeout` | 10s | HTTP timeout |
| `retry_attempts` | 3 | Max retry attempts |
| `bootstrap` | None | Initial flag data |
| `local_port` | None | Local development server port (uses `http://localhost:{port}/api/v1`) |

## Local Development

When running FlagKit locally, use the `local_port` option to connect to the local development server:

```rust
let options = FlagKitOptions::builder("sdk_your_api_key")
    .local_port(8200)  // Uses http://localhost:8200/api/v1
    .build();

FlagKit::initialize(options)?;
```

## Security Features

### PII Detection

The SDK can detect and warn about potential PII (Personally Identifiable Information) in contexts and events:

```rust
use flagkit::security::{SecurityConfig, check_pii_strict, DataType};

// Enable strict PII mode - returns errors instead of warnings
let config = SecurityConfig::builder()
    .strict_pii_mode(true)
    .build();

// Attributes containing PII will return FlagKitError
let data = serde_json::json!({
    "email": "user@example.com"  // PII detected!
});

if let Err(e) = check_pii_strict(Some(&data), DataType::Context, &config) {
    println!("PII error: {}", e);
}

// Use private_attributes to mark fields as intentionally containing PII
let config = SecurityConfig::builder()
    .add_private_attribute("email")
    .add_private_attribute("phone")
    .build();
```

### Request Signing

POST requests to the FlagKit API can be signed with HMAC-SHA256 for integrity:

```rust
use flagkit::security::{sign_request, SecurityConfig};

let body = r#"{"flag_key": "my-flag"}"#;
let signature = sign_request(body, "sdk_your_api_key")?;

// Use signature headers in HTTP request:
// X-Signature: signature.signature
// X-Timestamp: signature.timestamp
// X-Key-Id: signature.key_id

// Enable request signing in config
let config = SecurityConfig::builder()
    .enable_request_signing(true)
    .build();
```

### Bootstrap Signature Verification

Verify bootstrap data integrity using HMAC signatures:

```rust
use flagkit::{FlagKitOptions, BootstrapConfig, BootstrapVerificationConfig};
use flagkit::security::sign_bootstrap;
use std::collections::HashMap;

// Create signed bootstrap data
let mut flags = HashMap::new();
flags.insert("feature-a".to_string(), serde_json::json!(true));
flags.insert("feature-b".to_string(), serde_json::json!("value"));

let timestamp = chrono::Utc::now().timestamp_millis();
let signature = sign_bootstrap(&flags, "sdk_your_api_key", timestamp)?;

// Use signed bootstrap with verification
let options = FlagKitOptions::builder("sdk_your_api_key")
    .bootstrap_with_signature(flags, signature, timestamp)
    .bootstrap_verification(BootstrapVerificationConfig::custom(
        true,           // enabled
        86400000,       // max_age: 24 hours in milliseconds
        "error"         // on_failure: "warn" (default), "error", or "ignore"
    ))
    .build();
```

### Cache Encryption

Enable AES-256-GCM encryption with PBKDF2 key derivation for cached flag data:

```rust
use flagkit::security::{EncryptedCache, SecurityConfig};

// Create encrypted cache
let cache = EncryptedCache::new("sdk_your_api_key")?;

// Encrypt/decrypt data
let encrypted = cache.encrypt(b"sensitive data")?;
let decrypted = cache.decrypt(&encrypted)?;

// Encrypt/decrypt JSON values
let value = serde_json::json!({"flags": {"feature": true}});
let encrypted_json = cache.encrypt_json(&value)?;
let decrypted_json = cache.decrypt_json(&encrypted_json)?;

// Enable in config
let config = SecurityConfig::builder()
    .enable_cache_encryption(true)
    .build();
```

### Evaluation Jitter (Timing Attack Protection)

Add random delays to flag evaluations to prevent cache timing attacks:

```rust
use flagkit::{FlagKitOptions, EvaluationJitterConfig};

let options = FlagKitOptions::builder("sdk_your_api_key")
    .evaluation_jitter(EvaluationJitterConfig::new(
        true,   // enabled
        5,      // min_ms
        15      // max_ms
    ))
    .build();

// Or use the convenience method
let options = FlagKitOptions::builder("sdk_your_api_key")
    .enable_evaluation_jitter()
    .build();
```

### Error Sanitization

Automatically redact sensitive information from error messages:

```rust
use flagkit::FlagKitOptions;
use flagkit::error::ErrorSanitizationConfig;

let options = FlagKitOptions::builder("sdk_your_api_key")
    .error_sanitization(ErrorSanitizationConfig {
        enabled: true,
        preserve_original: false,  // Set true for debugging
    })
    .build();

// Or use convenience methods
let options = FlagKitOptions::builder("sdk_your_api_key")
    .error_sanitization_with_preservation()  // Enable with preservation
    // .disable_error_sanitization()         // Disable entirely
    .build();
```

## Event Persistence

Enable crash-resilient event persistence to prevent data loss:

```rust
use flagkit::FlagKitOptions;
use std::time::Duration;

let options = FlagKitOptions::builder("sdk_your_api_key")
    .persist_events(true)
    .event_storage_path("/path/to/storage")  // Optional, defaults to temp dir
    .max_persisted_events(10000)             // Optional, default 10000
    .persistence_flush_interval(Duration::from_secs(1))  // Optional
    .build();
```

Events are written to disk before being queued for sending, and automatically recovered on restart.

## Key Rotation

Support seamless API key rotation:

```rust
use flagkit::security::ApiKeyManager;

// Using ApiKeyManager directly
let manager = ApiKeyManager::new(
    "sdk_primary_key",
    Some("sdk_secondary_key".to_string())
);

// SDK will automatically failover on 401 errors
if manager.handle_401_error()? {
    println!("Switched to secondary key");
}

// Reset to primary key
manager.reset_to_primary();
```

## All Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api_key` | String | Required | API key for authentication |
| `polling_interval` | Duration | 30s | Polling interval |
| `cache_ttl` | Duration | 300s | Cache TTL |
| `max_cache_size` | usize | 1000 | Maximum cache entries |
| `cache_enabled` | bool | true | Enable local caching |
| `events_enabled` | bool | true | Enable event tracking |
| `event_batch_size` | usize | 10 | Events per batch |
| `event_flush_interval` | Duration | 30s | Interval between flushes |
| `timeout` | Duration | 10s | Request timeout |
| `retry_attempts` | u32 | 3 | Number of retry attempts |
| `circuit_breaker_threshold` | u32 | 5 | Failures before circuit opens |
| `circuit_breaker_reset_timeout` | Duration | 30s | Time before half-open |
| `bootstrap` | HashMap? | None | Initial flag values |
| `bootstrap_config` | BootstrapConfig? | None | Signed bootstrap data |
| `bootstrap_verification` | Config | enabled | Bootstrap verification settings |
| `local_port` | u16? | None | Local development port |
| `persist_events` | bool | false | Enable event persistence |
| `event_storage_path` | PathBuf? | temp dir | Event storage directory |
| `max_persisted_events` | usize | 10000 | Max persisted events |
| `persistence_flush_interval` | Duration | 1s | Persistence flush interval |
| `evaluation_jitter` | Config | disabled | Timing attack protection |
| `error_sanitization` | Config | enabled | Sanitize error messages |

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run with all features
cargo test --all-features

# Format code
cargo fmt

# Lint
cargo clippy
```

## License

MIT License - see LICENSE file for details.
