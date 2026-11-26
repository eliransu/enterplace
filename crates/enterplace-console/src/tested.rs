//! The last connection test of each provider, as this gateway ran it: what Providers, Health and Start here show
//! as the provider's one status. The gateway runs the test (it holds the keys and the network); the console reads it.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// One test's outcome.
#[derive(Clone, Debug)]
pub struct Tested {
    pub ok: bool,
    /// What the page says: "Connected, 120 ms" or why it failed and what to check.
    pub text: String,
    /// What the provider was when tested (its address and key): a changed provider is tested again.
    pub fingerprint: String,
    pub at: Instant,
}

// ponytail: kept in this process only, so each gateway tests on its own and a restart tests again. A shared row in
// the store comes when gateways must agree on it.
static TESTS: Mutex<Option<HashMap<String, Tested>>> = Mutex::new(None);

/// How long a test stands before a page asking for the status tests again.
pub const FRESH: Duration = Duration::from_secs(600);

pub fn remember(provider: &str, ok: bool, text: String, fingerprint: String) {
    let mut tests = TESTS.lock().unwrap_or_else(PoisonError::into_inner);
    tests.get_or_insert_with(HashMap::new).insert(
        provider.to_string(),
        Tested {
            ok,
            text,
            fingerprint,
            at: Instant::now(),
        },
    );
}

pub fn last(provider: &str) -> Option<Tested> {
    TESTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .and_then(|t| t.get(provider).cloned())
}
