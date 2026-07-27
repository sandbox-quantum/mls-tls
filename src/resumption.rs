//! Resumption support
//!
//! The MLS group state is persisted via mls-rs' `GroupStateStorage` (`Group::write_to_storage` +
//! `Client::load_group`). `ConnectionCommon::export_resumption_state()` writes the current group to
//! the config's [`SessionStore`] and returns a [`ResumptionState`] that names it. Pass that state to
//! `ClientConnection::resume()` with a config that shares the same store.
//!
//! A [`ResumptionState`] carries only the group id. The serialized MLS group state remains in the
//! [`SessionStore`], so resumed connections must use the same config or another config built with a
//! shared store.

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

/// A handle identifying the persisted MLS group to resume from.
#[derive(Clone, Debug)]
pub struct ResumptionState {
    pub(crate) group_id: Vec<u8>,
}

impl ResumptionState {
    /// Serialize the resumption handle.
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
