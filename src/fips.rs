//! FIPS-mode activation and enforcement (feature `fips`).
//!
//! # What this does and does not claim
//!
//! `mls-tls` is **not** a FIPS-validated cryptographic module and cannot be one. The module
//! boundary is OpenSSL's. What this feature provides is *FIPS-mode operation*: every cryptographic
//! operation the crate performs is delegated to an OpenSSL FIPS provider running in its approved
//! mode, and the operations that are not approved are refused rather than silently downgraded.
//!
//! # Activation
//!
//! Call [`enable`] as the **first thing in `main()`**, before any other OpenSSL use:
//!
//! ```no_run
//! fn main() -> Result<(), mls_tls::Error> {
//!     mls_tls::fips::enable()?;
//!     // ... everything else
//!     Ok(())
//! }
//! ```
//!
//! Ordering matters and is not merely advisory. `OSSL_PROVIDER_load` only suppresses the fallback
//! default provider if nothing has already triggered an automatic load; if any crypto runs first,
//! both providers end up loaded and which implementation serves a given fetch is unspecified.
//! The guard at each connection constructor catches the common case (nothing called `enable` at
//! all) but cannot detect a library that initialised OpenSSL during static initialisation.
//!
//! [`enable`] performs four steps:
//!
//! 1. reject OpenSSL older than 3.5 (see below);
//! 2. load the `fips` and `base` providers into the default library context — `base` is required
//!    because the FIPS provider ships no encoders/decoders, and the DER key parsing in
//!    `mls-rs-crypto-openssl` needs them. Its built-in encoders carry the `fips=yes` property, so
//!    they still match the default query set in step 3, and being non-cryptographic they do not
//!    affect validation status;
//! 3. set `fips=yes` as the default property on the default library context. This is what actually
//!    routes work to the FIPS provider: `mls-rs-crypto-openssl` uses legacy static algorithm
//!    objects (`EVP_sha384()`, `EVP_aes_256_gcm()`), and those are *implicitly* fetched with a NULL
//!    property query, which merges with the context default;
//! 4. install a strict FIPS indicator callback, which turns any operation the module flags as
//!    non-approved into a hard failure instead of a silent one.
//!
//! # Why the default library context
//!
//! A private `OSSL_LIB_CTX` would be stronger isolation, but it is not reachable:
//! `mls-rs-crypto-openssl` uses `openssl::symm`, `openssl::hash` and `PkeyCtx::new` throughout,
//! none of which accept a library context. Global default properties are the only lever that
//! governs those call sites.
//!
//! # OpenSSL 3.5+
//!
//! Older validated modules reject HKDF in `EXPAND_ONLY` mode when the requested output is shorter
//! than the digest, which is exactly how MLS derives its 12-byte AEAD nonces — every message would
//! fail. The fix is in current branches but a validated module cannot be patched without
//! re-validation, so this feature refuses to run below 3.5 rather than appear to work. `build.rs`
//! also fails the build when the linked OpenSSL is too old, so the common case is caught early.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::{Mutex, OnceLock};

use openssl::provider::Provider;

use crate::error::Error;

/// OpenSSL 3.5.0, in `OPENSSL_VERSION_NUMBER` form (`MAJOR<<28 | MINOR<<20 | PATCH<<4`).
const MIN_OPENSSL_VERSION: i64 = 0x3050_0000;

/// The loaded providers, kept alive for the lifetime of the process. Dropping a [`Provider`]
/// unloads it, so these must not be released while any cryptography is still in flight.
struct LoadedProviders {
    _fips: Provider,
    _base: Provider,
}

/// Sticky, race-free one-shot init. A *failure* is cached too: if activation failed, the default
/// provider may already have auto-loaded, so the process is in an indeterminate state and retrying
/// would be misleading.
static INIT: OnceLock<Result<LoadedProviders, String>> = OnceLock::new();

/// The most recent operation the module flagged as non-approved, for error reporting.
static LAST_UNAPPROVED: Mutex<Option<String>> = Mutex::new(None);

// `OSSL_INDICATOR_set_callback` (OpenSSL 3.4+) is not bound by `openssl-sys`, so declare it.
// The callback fires whenever the FIPS provider detects a non-approved operation; returning 0
// makes the calling operation fail.
type IndicatorCallback = unsafe extern "C" fn(*const c_char, *const c_char, *const c_void) -> c_int;

unsafe extern "C" {
    fn OSSL_INDICATOR_set_callback(libctx: *mut c_void, cb: Option<IndicatorCallback>);
}

unsafe extern "C" fn on_unapproved_operation(
    kind: *const c_char,
    desc: *const c_char,
    _params: *const c_void,
) -> c_int {
    // SAFETY: OpenSSL passes NUL-terminated static strings, or NULL.
    let read = |p: *const c_char| -> String {
        if p.is_null() {
            "<unknown>".to_owned()
        } else {
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    };

    if let Ok(mut slot) = LAST_UNAPPROVED.lock() {
        *slot = Some(format!("{} ({})", read(kind), read(desc)));
    }

    // 0 => raise an error in the caller. A non-approved operation must not quietly succeed just
    // because the module was willing to perform it.
    0
}

/// Put the process into FIPS mode. Idempotent; safe to call from multiple threads.
///
/// Must be called before any other use of OpenSSL — see the module docs.
pub fn enable() -> Result<(), Error> {
    match INIT.get_or_init(load_fips_providers) {
        Ok(_) => Ok(()),
        Err(message) => Err(Error::Fips(message.clone())),
    }
}

fn load_fips_providers() -> Result<LoadedProviders, String> {
    let version = openssl::version::number();
    if version < MIN_OPENSSL_VERSION {
        return Err(format!(
            "the `fips` feature requires OpenSSL 3.5 or newer, but the linked library is {} \
             (0x{version:08x}); older FIPS modules reject the short HKDF-Expand outputs MLS needs",
            openssl::version::version()
        ));
    }

    let fips = Provider::load(None, "fips").map_err(|e| {
        format!(
            "could not load the OpenSSL FIPS provider: {e}. Check that the module is installed \
             and that `openssl fipsinstall` has been run, and that fipsmodule.cnf is included \
             from openssl.cnf (with `activate` NOT set, since it is loaded here instead)"
        )
    })?;

    // Non-cryptographic, but required: the FIPS provider has no encoders/decoders, and DER key
    // parsing needs them.
    let base = Provider::load(None, "base")
        .map_err(|e| format!("could not load the OpenSSL base provider: {e}"))?;

    // SAFETY: a null library context means the default one; `1` enables. Both plain C ints.
    let rc = unsafe { openssl_sys::EVP_default_properties_enable_fips(std::ptr::null_mut(), 1) };
    if rc != 1 {
        return Err("could not set `fips=yes` as the default property query".to_owned());
    }

    // SAFETY: null libctx = default; the callback is a plain `extern "C"` fn with no state beyond
    // a static mutex, and OpenSSL keeps the pointer for the life of the context.
    unsafe { OSSL_INDICATOR_set_callback(std::ptr::null_mut(), Some(on_unapproved_operation)) };

    Ok(LoadedProviders {
        _fips: fips,
        _base: base,
    })
}

/// Whether `fips=yes` is the default property query on the default library context.
///
/// OpenSSL's own documentation calls this "a hint of intent, but not proof" — real assurance comes
/// from the module's security policy. It is used here to catch the setup mistake of never calling
/// [`enable`], not as evidence of compliance.
pub fn is_enabled() -> bool {
    // SAFETY: a null library context means the default one.
    unsafe { openssl_sys::EVP_default_properties_is_fips_enabled(std::ptr::null_mut()) == 1 }
}

/// The most recent operation the FIPS module reported as non-approved, if any.
///
/// Populated by the indicator callback installed by [`enable`]. Useful for turning an opaque
/// OpenSSL failure into an actionable message.
pub fn last_unapproved_operation() -> Option<String> {
    LAST_UNAPPROVED.lock().ok().and_then(|slot| slot.clone())
}

/// Refuse to proceed unless FIPS mode is active. Called at every connection constructor.
pub(crate) fn assert_enabled() -> Result<(), Error> {
    if is_enabled() {
        return Ok(());
    }
    Err(Error::Fips(
        "this build requires FIPS mode, but `fips=yes` is not the default property query — \
         call `mls_tls::fips::enable()` before any other OpenSSL use"
            .to_owned(),
    ))
}
