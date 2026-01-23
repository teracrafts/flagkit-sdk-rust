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
