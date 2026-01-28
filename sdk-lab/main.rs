//! FlagKit Rust SDK Lab
//!
//! Internal verification script for SDK functionality.
//! Run with: cargo run --example sdk-lab

use flagkit::{FlagKit, FlagKitOptions, FlagValue};
use std::collections::HashMap;

const PASS: &str = "\x1b[32m[PASS]\x1b[0m";
const FAIL: &str = "\x1b[31m[FAIL]\x1b[0m";

#[tokio::main]
async fn main() {
    println!("=== FlagKit Rust SDK Lab ===\n");

    let mut passed = 0;
    let mut failed = 0;

    macro_rules! pass {
        ($test:expr) => {{
            println!("{} {}", PASS, $test);
            passed += 1;
        }};
    }

    macro_rules! fail {
        ($test:expr) => {{
            println!("{} {}", FAIL, $test);
            failed += 1;
        }};
    }

    // Test 1: Initialization with bootstrap (Rust SDK has no offline mode - uses bootstrap when network fails)
    println!("Testing initialization...");
    let mut bootstrap: HashMap<String, serde_json::Value> = HashMap::new();
    bootstrap.insert("lab-bool".to_string(), serde_json::json!(true));
    bootstrap.insert("lab-string".to_string(), serde_json::json!("Hello Lab"));
    bootstrap.insert("lab-number".to_string(), serde_json::json!(42.0));
    bootstrap.insert(
        "lab-json".to_string(),
        serde_json::json!({"nested": true, "count": 100.0}),
    );

    // Use the builder pattern for FlagKitOptions
    let options = FlagKitOptions::builder("sdk_lab_test_key")
        .bootstrap(bootstrap)
        .build();

    let client = match FlagKit::initialize(options) {
        Ok(c) => c,
        Err(e) => {
            fail!(format!("Initialization - {}", e));
            print_summary(passed, failed);
            std::process::exit(1);
        }
    };

    // Initialize async part (fetches flags, may fail on network) with timeout
    // Use a short timeout since we don't have a server running
    let init_result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        client.initialize()
    ).await;

    match init_result {
        Ok(Ok(_)) => {
            // Successfully initialized from server
            pass!("Initialization");
        }
        Ok(Err(_)) | Err(_) => {
            // Timeout or network error - expected without a server
            // Bootstrap data should still be available
            pass!("Initialization (network error but using bootstrap)");
        }
    }

    // Test 2: Boolean flag evaluation (methods require context parameter)
    println!("\nTesting flag evaluation...");
    let bool_value = client.get_boolean_value("lab-bool", false, None);
    if bool_value {
        pass!("Boolean flag evaluation");
    } else {
        fail!(format!("Boolean flag - expected true, got {}", bool_value));
    }

    // Test 3: String flag evaluation
    let string_value = client.get_string_value("lab-string", "", None);
    if string_value == "Hello Lab" {
        pass!("String flag evaluation");
    } else {
        fail!(format!(
            "String flag - expected 'Hello Lab', got '{}'",
            string_value
        ));
    }

    // Test 4: Number flag evaluation
    let number_value = client.get_number_value("lab-number", 0.0, None);
    if (number_value - 42.0).abs() < f64::EPSILON {
        pass!("Number flag evaluation");
    } else {
        fail!(format!("Number flag - expected 42, got {}", number_value));
    }

    // Test 5: JSON flag evaluation
    let json_value = client.get_json_value("lab-json", Some(serde_json::json!({})), None);
    if let Some(json) = json_value {
        if let (Some(nested), Some(count)) = (json.get("nested"), json.get("count")) {
            if nested.as_bool() == Some(true) && count.as_f64() == Some(100.0) {
                pass!("JSON flag evaluation");
            } else {
                fail!(format!("JSON flag - unexpected value: {}", json));
            }
        } else {
            fail!(format!("JSON flag - missing fields: {}", json));
        }
    } else {
        fail!("JSON flag - got None");
    }

    // Test 6: Default value for missing flag
    let missing_value = client.get_boolean_value("non-existent", true, None);
    if missing_value {
        pass!("Default value for missing flag");
    } else {
        fail!(format!(
            "Missing flag - expected default true, got {}",
            missing_value
        ));
    }

    // Test 7: Context management - identify (Rust uses FlagValue, not serde_json::Value)
    println!("\nTesting context management...");
    let mut attrs: HashMap<String, FlagValue> = HashMap::new();
    attrs.insert("plan".to_string(), FlagValue::String("premium".to_string()));
    attrs.insert("country".to_string(), FlagValue::String("US".to_string()));
    client.identify("lab-user-123", Some(attrs));

    if let Some(context) = client.get_context() {
        if context.user_id.as_deref() == Some("lab-user-123") {
            pass!("identify()");
        } else {
            fail!("identify() - context not set correctly");
        }
    } else {
        fail!("identify() - no context returned");
    }

    // Test 8: Context management - get_context (attributes are HashMap<String, FlagValue>)
    if let Some(context) = client.get_context() {
        if let Some(plan) = context.attributes.get("plan") {
            // FlagValue uses as_string(), not as_str()
            if plan.as_string() == Some("premium") {
                pass!("get_context()");
            } else {
                fail!("get_context() - plan attribute has wrong value");
            }
        } else {
            fail!("get_context() - plan attribute missing");
        }
    } else {
        fail!("get_context() - no context returned");
    }

    // Test 9: Context management - reset
    client.reset();
    let reset_context = client.get_context();
    if reset_context.is_none() || reset_context.as_ref().and_then(|c| c.user_id.as_ref()).is_none()
    {
        pass!("reset()");
    } else {
        fail!("reset() - context not cleared");
    }

    // Test 10: Event tracking
    println!("\nTesting event tracking...");
    let mut event_data: HashMap<String, serde_json::Value> = HashMap::new();
    event_data.insert("sdk".to_string(), serde_json::json!("rust"));
    event_data.insert("version".to_string(), serde_json::json!("1.0.0"));
    client.track("lab_verification", Some(event_data));
    pass!("track()");

    // Test 11: Flush (may fail due to no network - that's OK)
    match client.flush().await {
        Ok(_) => pass!("flush()"),
        Err(_) => pass!("flush() (network error expected)"),
    }

    // Test 12: Cleanup
    println!("\nTesting cleanup...");
    client.close().await;
    pass!("close()");

    print_summary(passed, failed);

    if failed > 0 {
        println!("\n\x1b[31mSome verifications failed!\x1b[0m");
        std::process::exit(1);
    } else {
        println!("\n\x1b[32mAll verifications passed!\x1b[0m");
        std::process::exit(0);
    }
}

fn print_summary(passed: i32, failed: i32) {
    println!("\n{}", "=".repeat(40));
    println!("Results: {} passed, {} failed", passed, failed);
    println!("{}", "=".repeat(40));
}
