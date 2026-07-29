use std::collections::BTreeSet;

use mls_rs::{
    CipherSuite, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
    client_builder::MlsConfig,
    crypto::SignatureSecretKey,
    error::{IntoAnyError, MlsError},
    group::{GroupContext, Roster},
    identity::SigningIdentity,
    mls_rules::{CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle},
    storage_provider::in_memory::InMemoryGroupStateStorage,
};

use crate::{
    mls_config::{MlsGroup, build_mls_client},
    mls_tls_01::MlsTlsError,
    pki::{PkiError, validate_client_credential},
    tls_record::DirectionalRekey,
};

// draft-kohbrok-mls-two-party-profile-00
// https://datatracker.ietf.org/doc/draft-kohbrok-mls-two-party-profile/00/
//

// 3. Initial key agreement

// struct {
//     MLSMessage key_package;
// } ClientHello

// struct {
//     MLSMessage welcome;
// } ServerHello

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub(crate) key_package: MlsMessage,
}

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub(crate) welcome: MlsMessage,
}

pub(crate) fn initial_key_agreement_initiator_1<C: MlsConfig>(
    initiator: &Client<C>,
) -> Result<ClientHello, MlsError> {
    // > The initiator starts the key agreement part of the protocol by
    // > creating a KeyPackage and sending a ClientHello to the responder.

    let initiator_key_package_msg = initiator.generate_key_package_message(
        ExtensionList::default(),
        Default::default(),
        None,
    )?;
    Ok(ClientHello {
        key_package: initiator_key_package_msg,
    })
}

pub(crate) fn initial_key_agreement_responder_1(
    client_hello: ClientHello,
    signing_identity: SigningIdentity,
    signer: SignatureSecretKey,
    cipher_suite: CipherSuite,
    group_state_storage: InMemoryGroupStateStorage,
) -> Result<(ServerHello, MlsGroup), TwoPartyError> {
    // > The responder inspects the KeyPackage and checks whether it supports
    // > the offered ciphersuite and whether the initiator has sufficient
    // > capabilities to support the connection.
    let initiator_key_package = client_hello
        .key_package
        .as_key_package()
        .ok_or(TwoPartyError::NotAKeyPackage)?;
    let initiator_offered_ciphersuite = initiator_key_package.cipher_suite;
    // Standard suites (1–7) plus the custom X-Wing suite (0x004e) our crypto provider adds.
    let server_supported_ciphersuites = CipherSuite::all()
        .chain(std::iter::once(
            crate::crypto::MLS_256_XWING_AES256GCM_SHA512_P384,
        ))
        .collect::<BTreeSet<_>>();

    if !server_supported_ciphersuites.contains(&initiator_offered_ciphersuite) {
        return Err(TwoPartyError::UnsupportedCipherSuite(
            initiator_offered_ciphersuite,
        ));
    }

    // > The responder MUST interface with the AS to ensure that the
    // > credential in the KeyPackage is valid.
    //
    // Directional peer check on the *client's* KeyPackage credential (the group's mls-rs identity
    // provider is accept-all; real verification is manual — see `mls_config`). Accepts a Basic
    // client credential today; the X.509 arm is a stub.
    validate_client_credential(initiator_key_package.signing_identity())?;

    // > The responder then locally creates an MLS group and commits to an Add
    // > proposal containing the initiator's KeyPackage.  The responder sends
    // > the resulting Welcome message back to the initiator as part of a
    // > ServerHello message.
    let responder = build_mls_client(signing_identity, signer, cipher_suite, group_state_storage);

    let mut responder_group =
        responder.create_group(ExtensionList::default(), Default::default(), None)?;
    let responder_commit = responder_group
        .commit_builder()
        .add_member(client_hello.key_package.clone())?
        .build()?;

    let welcome = responder_commit
        .welcome_messages
        .into_iter()
        .next()
        .ok_or(TwoPartyError::MissingWelcome)?;
    let server_hello = ServerHello { welcome };
    responder_group.apply_pending_commit()?;

    Ok((server_hello, responder_group))
}

/// Join the group from the responder's Welcome. Peer verification of the responder's credential is
/// done by the *connection* layer (which holds the `ServerCertVerifier` policy + `ServerName`) —
/// this function only builds the local group state.
///
/// Named-generic over `C` (not `impl MlsConfig`) so the concrete `MlsTlsConfig` flows through to the
/// returned `Group<C>`, letting the connection own a nameable `MlsGroup`.
pub(crate) fn initial_key_agreement_initiator_2<C: MlsConfig>(
    initiator: &Client<C>,
    server_hello: ServerHello,
) -> Result<Group<C>, TwoPartyError> {
    // > The initiator uses the Welcome to create its local group state.
    let (initiator_group, _) = initiator.join_group(None, &server_hello.welcome, None)?;
    Ok(initiator_group)
}

// 4.  Continuous key agreement
//
// struct {
//     MLSMessage update
// } ConnectionUpdate
//
// struct {
//     uint64 epoch;
// } EpochKeyUpdate

#[derive(Debug, Clone)]
pub(crate) struct ConnectionUpdate {
    pub(crate) update: MlsMessage,
}

#[derive(Debug, Clone)]
pub(crate) struct EpochKeyUpdate {
    pub(crate) epoch: u64,
}

#[derive(Debug, PartialEq)]
pub(crate) enum State {
    AwaitingEpochKeyUpdate,
    Synced,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Role {
    Initiator,
    Responder,
}

#[derive(Debug, thiserror::Error)]
pub enum TwoPartyError {
    #[error("MLS operation failed")]
    Mls(#[from] MlsError),
    #[error("credential validation failed")]
    CredentialValidation(#[from] PkiError),
    #[error("unsupported cipher suite: {0:?}")]
    UnsupportedCipherSuite(CipherSuite),
    #[error("expected a KeyPackage message")]
    NotAKeyPackage,
    #[error("commit produced no Welcome message")]
    MissingWelcome,
    #[error("no member found at the expected leaf index")]
    MissingMember,
    #[error("received EpochKeyUpdate while not waiting for one")]
    UnexpectedEpochKeyUpdate,
    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },
    #[error("protocol invariant violated: {0}")]
    InvalidState(&'static str),
    #[error("traffic secret derivation failed")]
    TrafficSecret(#[from] MlsTlsError),
}

// Derive the initiator's application traffic secret (client_application_traffic_secret) from the
// group's current epoch, as the raw bytes carried in a `DirectionalRekey`.
fn derive_initiator_secret<C: CryptoProvider + Clone>(
    group: &Group<impl MlsConfig>,
    crypto: &C,
) -> Result<Vec<u8>, TwoPartyError> {
    Ok(
        crate::mls_tls_01::derive_client_application_traffic_secret(group, crypto.clone())?
            .as_bytes()
            .to_vec(),
    )
}

// Derive the responder's application traffic secret (server_application_traffic_secret) from the
// group's current epoch, as the raw bytes carried in a `DirectionalRekey`.
fn derive_responder_secret<C: CryptoProvider + Clone>(
    group: &Group<impl MlsConfig>,
    crypto: &C,
) -> Result<Vec<u8>, TwoPartyError> {
    Ok(
        crate::mls_tls_01::derive_server_application_traffic_secret(group, crypto.clone())?
            .as_bytes()
            .to_vec(),
    )
}

// Both directions' traffic secrets from the group's current epoch (used when a party merges and
// installs both send and receive keys at once).
fn both_secrets<C: CryptoProvider + Clone>(
    group: &Group<impl MlsConfig>,
    crypto: &C,
) -> Result<DirectionalRekey, TwoPartyError> {
    Ok(DirectionalRekey::BothSecrets {
        initiator: derive_initiator_secret(group, crypto)?,
        responder: derive_responder_secret(group, crypto)?,
    })
}

pub(crate) struct Mls2Party {
    state: State,
    role: Role,
}

// After the initial key agreement phase, both parties can send an MLS
// commit with UpdatePath to update their key material.  To ensure that
// both agree on the order of such commits and thus on the currently
// used key material, they must follow the following rules.

impl Mls2Party {
    pub(crate) fn new(role: Role) -> Self {
        Self {
            state: State::Synced,
            role,
        }
    }

    // Returns the ConnectionUpdate to send plus, for the initiator, the directional rekey to install
    // *after* that ConnectionUpdate has been emitted under the old key (emit-before-switch).
    pub(crate) fn create_connection_update<C: CryptoProvider + Clone>(
        &mut self,
        group: &mut Group<impl MlsConfig>,
        crypto: &C,
    ) -> Result<Option<(ConnectionUpdate, Option<DirectionalRekey>)>, TwoPartyError> {
        // *  Each party may send a ConnectionUpdate if they are not currently
        //     waiting for an EpochKeyUpdate to confirm a previous
        //     ConnectionUpdate

        match self.state {
            State::AwaitingEpochKeyUpdate => Ok(None),
            State::Synced => {
                // `path_required` also forces an UpdatePath, but the explicit proposal keeps the
                // generated commit aligned with the two-party profile's update-only rule.
                group.propose_update(vec![])?;
                let commit = group.commit(vec![])?;
                let connection_update = ConnectionUpdate {
                    update: commit.commit_message,
                };

                let rekey = match self.role {
                    // The initiator has priority and never rolls back: merge the commit immediately
                    // and install the new SEND key now. The ConnectionUpdate above is emitted (by
                    // the driver) under the OLD send key first, so the peer can still read it. The
                    // RECEIVE key stays on the old epoch until the confirming EpochKeyUpdate arrives.
                    Role::Initiator => {
                        group.apply_pending_commit()?;
                        Some(DirectionalRekey::InitiatorSecret(derive_initiator_secret(
                            group, crypto,
                        )?))
                    }
                    // The responder defers: hold the commit pending (do not merge) and rotate
                    // nothing. It merges and installs both directions only when the initiator's
                    // EpochKeyUpdate confirms the switch (see `handle_epoch_key_update`).
                    Role::Responder => None,
                };

                self.state = State::AwaitingEpochKeyUpdate;
                Ok(Some((connection_update, rekey)))
            }
        }
    }

    // Returns the directional rekey to install and the EpochKeyUpdate to send back. Per
    // emit-before-switch, the driver sends the EpochKeyUpdate under the OLD key first, then applies
    // the rekey.
    pub(crate) fn handle_connection_update<C: CryptoProvider + Clone>(
        &mut self,
        group: &mut Group<impl MlsConfig>,
        crypto: &C,
        connection_update: ConnectionUpdate,
    ) -> Result<(Option<DirectionalRekey>, Option<EpochKeyUpdate>), TwoPartyError> {
        match (&self.state, &self.role) {
            // *  If either party receives a ConnectionUpdate and they're not
            //     currently waiting for an EpochKeyUpdate, they MUST validate and
            //     apply the commit and respond with an EpochKeyUpdate, where epoch
            //     is the group's new epoch.
            //
            // The responder is receiving an initiator-initiated update. The initiator already
            // rotated its send direction before sending, so it is safe to merge and install BOTH
            // directions now. (2-message flow: this single EpochKeyUpdate confirms the switch.)
            (State::Synced, Role::Responder) => {
                group.process_incoming_message(connection_update.update)?;
                let rekey = both_secrets(group, crypto)?;
                let epoch_key_update = EpochKeyUpdate {
                    epoch: group.current_epoch(),
                };
                Ok((Some(rekey), Some(epoch_key_update)))
            }
            // The initiator is receiving a responder-initiated update. Merge and install our SEND
            // key now; the EpochKeyUpdate we return (emitted under the old key first) gates the
            // responder's receive direction. Our own RECEIVE key waits for the responder's return
            // EpochKeyUpdate (see `handle_epoch_key_update`, initiator arm). This is the middle
            // message of the 3-message responder-initiated flow.
            (State::Synced, Role::Initiator) => {
                group.process_incoming_message(connection_update.update)?;
                let rekey =
                    DirectionalRekey::InitiatorSecret(derive_initiator_secret(group, crypto)?);
                let epoch_key_update = EpochKeyUpdate {
                    epoch: group.current_epoch(),
                };
                self.state = State::AwaitingEpochKeyUpdate;
                Ok((Some(rekey), Some(epoch_key_update)))
            }
            // *  If the initiator receives a ConnectionUpdate while waiting for an
            //     EpochKeyUpdate, it MUST ignore the ConnectionUpdate and resume
            //     waiting (our own update wins).
            (State::AwaitingEpochKeyUpdate, Role::Initiator) => Ok((None, None)),
            // *  If the responder receives a ConnectionUpdate while waiting for an
            //     EpochKeyUpdate, it MUST drop its locally pending commit and validate and apply
            //     the incoming commit as if it hadn't been waiting.
            //
            // Simultaneous-update collision: the responder deferred (never rotated eagerly), so it
            // just drops its pending commit, applies the initiator's, and installs BOTH directions.
            // NOTE: this collision path is preserved for correctness of the clean flows but is not
            // exhaustively hardened/tested (see plan).
            (State::AwaitingEpochKeyUpdate, Role::Responder) => {
                group.clear_pending_commit();
                group.clear_proposal_cache();

                // Checks are implemented as part of the `TwoPartyMlsRules` MlsRules implementation
                group.process_incoming_message(connection_update.update)?;

                let rekey = both_secrets(group, crypto)?;
                let epoch_key_update = EpochKeyUpdate {
                    epoch: group.current_epoch(),
                };
                self.state = State::Synced;
                Ok((Some(rekey), Some(epoch_key_update)))
            }
        }
    }

    // Returns the directional rekey to install and, for the responder-initiated flow, a second
    // ("return") EpochKeyUpdate to send. Emit-before-switch: the driver sends any returned
    // EpochKeyUpdate under the OLD key first, then applies the rekey.
    pub(crate) fn handle_epoch_key_update<C: CryptoProvider + Clone>(
        &mut self,
        group: &mut Group<impl MlsConfig>,
        crypto: &C,
        epoch_key_update: EpochKeyUpdate,
    ) -> Result<(Option<DirectionalRekey>, Option<EpochKeyUpdate>), TwoPartyError> {
        match (&self.state, &self.role) {
            // Covers BOTH the initiator-initiated confirmation and the responder-initiated return
            // EpochKeyUpdate — identical behaviour. The initiator already merged (eagerly, at
            // create/handle time), so validate by epoch *equality* and now install the RECEIVE key,
            // discarding the old one. No message is sent back.
            (State::AwaitingEpochKeyUpdate, Role::Initiator) => {
                let expected = group.current_epoch();
                if expected != epoch_key_update.epoch {
                    return Err(TwoPartyError::EpochMismatch {
                        expected,
                        got: epoch_key_update.epoch,
                    });
                }
                let rekey =
                    DirectionalRekey::ResponderSecret(derive_responder_secret(group, crypto)?);
                self.state = State::Synced;
                Ok((Some(rekey), None))
            }
            // Responder-initiated flow: we held our commit pending. This EpochKeyUpdate confirms the
            // initiator rotated its send direction, so merge now, install BOTH directions, and send a
            // second ("return") EpochKeyUpdate so the initiator can rotate its receive key. Our
            // pending commit is unmerged, so the group is still one epoch behind — validate by
            // `current + 1`.
            //
            // This second EpochKeyUpdate is a deliberate deviation from the
            // drafts. draft-kohbrok-mls-two-party-profile-00 §4 defines a single EpochKeyUpdate per
            // ConnectionUpdate; here a responder-initiated rotation is a 3-message flow
            // (ConnectionUpdate -> EpochKeyUpdate -> EpochKeyUpdate) so each transport direction is
            // gated independently and no in-flight receive key is discarded before the peer confirms.
            (State::AwaitingEpochKeyUpdate, Role::Responder) => {
                let expected = group.current_epoch() + 1;
                if expected != epoch_key_update.epoch {
                    return Err(TwoPartyError::EpochMismatch {
                        expected,
                        got: epoch_key_update.epoch,
                    });
                }
                group.apply_pending_commit()?;
                let rekey = both_secrets(group, crypto)?;
                let return_epoch_key_update = EpochKeyUpdate {
                    epoch: group.current_epoch(),
                };
                self.state = State::Synced;
                Ok((Some(rekey), Some(return_epoch_key_update)))
            }
            (State::Synced, _) => Err(TwoPartyError::UnexpectedEpochKeyUpdate),
        }
    }
}

// ---------------------------------------------------------------------------
// MlsRules for two-party profile
// ---------------------------------------------------------------------------

// draft-kohbrok-mls-two-party-profile §4:
// > "After the initial key agreement phase, both parties can send an MLS
// >  commit with UpdatePath to update their key material."
//
// On Receive, only Update proposals are allowed. All other proposal types
// (Add, Remove, PSK, ReInit, ExternalInit, GroupContextExtensions, custom,
// and any future types) are rejected. This is a deny-by-default allow-list.
//
// On Send, proposals pass through — we control what we send.
//
// The initial Add (epoch 0→1) does not conflict because:
// - The responder creates it via commit_builder (CommitDirection::Send)
// - The initiator joins via Welcome (never goes through filter_proposals)

#[derive(Debug, thiserror::Error)]
pub enum TwoPartyRulesError {
    #[error("expected at most one update proposal and no other proposal types")]
    ExpectedOneUpdateProposal,
}

impl IntoAnyError for TwoPartyRulesError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone)]
pub struct TwoPartyMlsRules {
    commit_options: CommitOptions,
    encryption_options: EncryptionOptions,
}

impl Default for TwoPartyMlsRules {
    fn default() -> Self {
        Self {
            commit_options: CommitOptions::default(),
            // Encrypt control messages so member commits are MLS PrivateMessages (wire_format
            // 0x0002), matching the interoperable ConnectionUpdate / Resumption framing (its parser
            // rejects a PublicMessage commit). `PaddingMode::None` matches the Python framing;
            // receivers tolerate any padding regardless.
            encryption_options: EncryptionOptions::new(
                true,
                mls_rs::client_builder::PaddingMode::None,
            ),
        }
    }
}

impl mls_rs::MlsRules for TwoPartyMlsRules {
    type Error = TwoPartyRulesError;

    fn filter_proposals(
        &self,
        direction: CommitDirection,
        _source: CommitSource,
        _roster: &Roster<'_>,
        _context: &GroupContext,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error> {
        if direction == CommitDirection::Receive {
            let has_non_update = proposals.length() != proposals.update_proposals().len();
            let too_many_updates = proposals.update_proposals().len() > 1;
            if has_non_update || too_many_updates {
                return Err(TwoPartyRulesError::ExpectedOneUpdateProposal);
            }
        }
        Ok(proposals)
    }

    fn commit_options(
        &self,
        _roster: &Roster<'_>,
        _context: &GroupContext,
        _proposals: &ProposalBundle,
    ) -> Result<CommitOptions, Self::Error> {
        Ok(self.commit_options)
    }

    fn encryption_options(
        &self,
        _roster: &Roster<'_>,
        _context: &GroupContext,
    ) -> Result<EncryptionOptions, Self::Error> {
        Ok(self.encryption_options)
    }
}

// 5.  Resumption

//    Either party may resume a previously interrupted protocol session
//    based on that session's group state.  The party initiating the
//    resumption becomes the initiator.
//
//    struct {
//      MLSMessage commit;
//    } ResumptionRequest
//
//    struct {
//      MLSMessage commit;
//    } ResumptionResponse
//

// Below are not used in the reference implementation.
// #[derive(Clone, Debug)]
// pub(crate) struct ResumptionRequest {
//     pub(crate) commit: MlsMessage,
// }

// #[derive(Clone, Debug)]
// pub(crate) struct ResumptionResponse {
//     pub(crate) commit: MlsMessage,
// }

impl Mls2Party {
    /// Client resumption (the draft specs' `ConnectionConfirmation` model):
    /// create a self-update commit and **merge it immediately**, advancing to the new epoch. Returns
    /// the commit to carry in the Resumption message. The responder replies with a bare
    /// `ConnectionConfirmation` (no responder commit), so the initiator installs both new-epoch
    /// directions now (over a fresh transport there are no in-flight old-epoch records to preserve).
    pub(crate) fn create_resumption_and_merge(
        &mut self,
        group: &mut Group<impl MlsConfig>,
    ) -> Result<MlsMessage, TwoPartyError> {
        group.propose_update(vec![])?;
        let commit = group.commit(vec![])?;
        group.apply_pending_commit()?;
        self.role = Role::Initiator;
        self.state = State::Synced;
        Ok(commit.commit_message)
    }

    /// Responder resumption: validate and apply the initiator's commit, advancing to the new epoch.
    /// Returns the new epoch to announce in the `ConnectionConfirmation`.
    pub(crate) fn apply_resumption(
        &mut self,
        group: &mut Group<impl MlsConfig>,
        commit: MlsMessage,
    ) -> Result<u64, TwoPartyError> {
        group.clear_pending_commit();
        group.clear_proposal_cache();
        group.process_incoming_message(commit)?;
        self.role = Role::Responder;
        self.state = State::Synced;
        Ok(group.current_epoch())
    }
}
