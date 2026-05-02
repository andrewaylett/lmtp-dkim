//! CLI entry point for `cargo-run-bin`.
//!
//! This binary provides the `cargo run-bin` command, which executes binaries
//! from Cargo dependencies without requiring them to be installed globally.
//!
//! The main function delegates to [`cargo_run_bin::cli::run`], which handles
//! argument parsing and binary execution. On error, the process exits with
//! status code 1.

use std::process;

/// Entry point for the cargo-run-bin CLI tool.
///
/// Invokes the run-bin command-line interface and exits with status code 1
/// if an error occurs. On success, the process exits early from within the
/// binary execution (see [`cargo_run_bin::cli::run`]).
fn main() {
    let res = cargo_run_bin::cli::run();

    // Only reached if run-bin code fails, otherwise process exits early from within
    // binary::run.
    if let Err(res) = res {
        eprintln!("\x1b[31mrun-bin failed: {res}\x1b[0m");
        process::exit(1);
    }
}
