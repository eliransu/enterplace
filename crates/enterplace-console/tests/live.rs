//! The live poll in assets/console.js, run under Node against a fake page (tests/live.js).

use std::process::Command;

#[test]
fn live_poll_swaps_in_place_and_not_while_a_field_has_focus()
-> Result<(), Box<dyn std::error::Error>> {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/live.js");
    // Not skipped when Node is missing: a skipped check would pass without checking anything.
    let out = Command::new("node").arg(script).output().map_err(|e| {
        format!(
            "this test runs the console script under Node and could not start it ({e}); install Node 18 or later"
        )
    })?;
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}
