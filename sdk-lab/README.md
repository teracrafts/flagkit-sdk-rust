# FlagKit Rust SDK Lab

Internal verification script for the Rust SDK.

## Purpose

This lab folder contains scripts to verify SDK functionality during development. It helps catch integration issues before committing changes.

## Usage

```bash
cargo run --example sdk-lab
```

## What it Tests

1. **Initialization** - Offline mode with bootstrap data
2. **Flag Evaluation** - Boolean, string, number, and JSON flags
3. **Default Values** - Returns defaults for missing flags
4. **Context Management** - identify(), get_context(), reset()
5. **Event Tracking** - track(), flush()
6. **Cleanup** - close()

## Expected Output

```
=== FlagKit Rust SDK Lab ===

Testing initialization...
[PASS] Initialization

Testing flag evaluation...
[PASS] Boolean flag evaluation
[PASS] String flag evaluation
[PASS] Number flag evaluation
[PASS] JSON flag evaluation
[PASS] Default value for missing flag

Testing context management...
[PASS] identify()
[PASS] get_context()
[PASS] reset()

Testing event tracking...
[PASS] track()
[PASS] flush()

Testing cleanup...
[PASS] close()

========================================
Results: 12 passed, 0 failed
========================================

All verifications passed!
```

## Note

This lab is defined as an example in `Cargo.toml` and is not included in the published crate.
