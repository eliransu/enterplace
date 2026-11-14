//! Core of the Gantry AI gateway. Embeddable as a library.

pub mod audit;
pub mod catalog;
pub mod chat;
pub mod config;
pub mod coverage;
pub mod eventstream;
pub mod gemini;
pub mod guard;
pub mod id;
pub mod insights;
pub mod keyfile;
pub mod kill;
pub mod litellm;
pub mod mcp;
pub mod metrics;
pub mod policy;
pub mod sigv4;
pub mod store;
pub mod translate;
pub mod usage;
pub mod vendors;
pub mod versions;

/// Version of the gateway, shared by the server and the CLI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// "1 record", "2 records": a count with its noun, for messages.
pub fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}
