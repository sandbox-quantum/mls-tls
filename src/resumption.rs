//! Resumption support (Phase 5).
//!
//! Two flavours:
//! - **In-session**: `ConnectionCommon::initiate_resumption()` runs a full re-key-agreement over the
//!   live group (handled automatically on the peer).
//! - **Cross-connection**: `ConnectionCommon::export_resumption_state()` snapshots the group into the
//!   config's [`SessionStore`], and `ClientConnection::resume()` rebuilds a connection from a
//!   persisted group over a fresh transport.
//!
//! The MLS group state is persisted via mls-rs' `GroupStateStorage` (`Group::write_to_storage` +
//! `Client::load_group`). A [`ResumptionState`] is a lightweight "ticket" naming the persisted group;
//! the state itself lives in the [`SessionStore`]. Reuse the same config (or share a `SessionStore`)
//! across the original and resumed connections so the group can be reloaded.
//!
//! Note: for the same-process / shared-store case a `ResumptionState` carries only the group id. Full
//! cross-*process* portability would additionally serialize the stored `GroupState`/`EpochRecord`
//! bytes; that is a documented extension.

use mls_rs::storage_provider::in_memory::InMemoryGroupStateStorage;

/// A shareable store of persisted MLS group state, used to resume connections.
///
/// Backed by mls-rs' `InMemoryGroupStateStorage`, which is `Arc`-backed: cloning shares the same
/// underlying state, so a group persisted by one connection can be reloaded by another built from the
/// same store.
#[derive(Clone, Default)]
pub struct SessionStore {
    pub(crate) storage: InMemoryGroupStateStorage,
}

impl SessionStore {
    /// Create an empty in-memory session store.
    pub fn new() -> Self {
        Self::default()
    }
}

/// A resumption "ticket": identifies the persisted MLS group to resume from.
#[derive(Clone, Debug)]
pub struct ResumptionState {
    pub(crate) group_id: Vec<u8>,
}

impl ResumptionState {
    /// Serialize the ticket (currently just the group id).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.group_id.clone()
    }

    /// Reconstruct a ticket from [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            group_id: bytes.to_vec(),
        }
    }
}
