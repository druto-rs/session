#!/usr/bin/env just --justfile

# List every recipe.
default:
    @just --list --unsorted

# Format the crate: nightly rustfmt, sorts and groups imports.
fmt:
    cargo +nightly fmt --all

# Run tests with nextest.
test *args:
    cargo nextest run --all-features --no-tests=pass {{ args }}

# Run tests under cargo-llvm-cov, write target/lcov.info, and print the coverage table.
coverage:
    cargo llvm-cov nextest --all-features --lcov --output-path target/lcov.info --no-tests=pass
    cargo llvm-cov report

# Lint with clippy.
clippy *args:
    cargo clippy --all-targets --all-features {{ args }}
