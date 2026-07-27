//! Fails the build early when the `fips` feature is enabled against an OpenSSL that is too old.
//!
//! Without this the failure would surface as an unresolved `OSSL_INDICATOR_set_callback` at link
//! time (added in 3.4) or, worse, as every MLS message failing at runtime on a 3.0.x FIPS module
//! that rejects short HKDF-Expand outputs. See `src/fips.rs` for why 3.5 is the floor.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    if std::env::var_os("CARGO_FEATURE_FIPS").is_none() {
        return;
    }

    // Set by openssl-sys (a `links = "openssl"` crate) for its direct dependents.
    let Ok(raw) = std::env::var("DEP_OPENSSL_VERSION_NUMBER") else {
        println!(
            "cargo::warning=could not determine the OpenSSL version; the `fips` feature requires 3.5+"
        );
        return;
    };

    let version = u64::from_str_radix(&raw, 16).unwrap_or(0);
    if version < 0x3050_0000 {
        panic!(
            "the `fips` feature requires OpenSSL 3.5 or newer, but the build is linking \
             0x{raw} — older FIPS modules reject the short HKDF-Expand outputs that MLS uses \
             for every AEAD nonce. Point OPENSSL_DIR at a newer install (see docker/fips/)."
        );
    }
}
