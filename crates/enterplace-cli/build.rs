//! Gives each build an identity without git: a hash of the sources it was built from, and the day it was built.
//! `enterplace version` prints both, so two builds of one version can be told apart in a bug report.
// ponytail: hashes the files on disk, so an edited, uncommitted tree gets its own hash. Use the commit hash and
// refuse a dirty tree once the repository has commits.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Every file under `dir` that goes into the binary: tests are left out, and so are hidden files such as .DS_Store,
/// which differ between a laptop and a container build of the same sources.
fn files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') || name == "tests" || name == "target" {
            continue;
        }
        if path.is_dir() {
            files(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// The civil date of a day count since 1970-01-01 (Howard Hinnant's algorithm).
fn date(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn main() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut list = vec![root.join("Cargo.toml"), root.join("Cargo.lock")];
    files(&root.join("crates"), &mut list)?;
    // The enterprise binary prints this same line, so its sources count too. A published enterplace-cli has no enterprise/.
    let enterprise = root.join("enterprise");
    if enterprise.is_dir() {
        list.push(enterprise.join("Cargo.toml"));
        files(&enterprise.join("src"), &mut list)?;
    }
    list.sort();
    let mut hash = Sha256::new();
    for path in &list {
        // The path relative to the root, so the same tree hashes the same in any folder or container.
        let name = path.strip_prefix(&root).unwrap_or(path);
        hash.update(name.to_string_lossy().as_bytes());
        hash.update([0]);
        hash.update(std::fs::read(path)?);
        hash.update([0]);
    }
    let hex: String = hash.finalize()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // SOURCE_DATE_EPOCH makes the date reproducible when a release pipeline sets it.
    let seconds = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(text) => text.trim().parse::<i64>()?,
        Err(_) => i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        )?,
    };
    println!("cargo:rustc-env=ENTERPLACE_SOURCE_HASH={hex}");
    println!(
        "cargo:rustc-env=ENTERPLACE_BUILD_DATE={}",
        date(seconds.div_euclid(86_400))
    );
    println!("cargo:rerun-if-changed={}", root.join("crates").display());
    if enterprise.is_dir() {
        println!("cargo:rerun-if-changed={}", enterprise.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        root.join("Cargo.lock").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        root.join("Cargo.toml").display()
    );
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    Ok(())
}
