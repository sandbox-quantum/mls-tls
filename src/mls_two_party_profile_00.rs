use std::collections::BTreeSet;

use mls_rs::{
    CipherSuite, Client, ExtensionList, Group, MlsMessage,
    client_builder::MlsConfig,
    crypto::SignatureSecretKey,
    error::{IntoAnyError, MlsError},
    group::{
        GroupContext, ReceivedMessage, Roster,
        proposal::{Proposal, ProposalType},
    },
    identity::SigningIdentity,
    mls_rules::{CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle},
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use rustls_pki_types::TrustAnchor;

use crate::{
    make_client, mls_two_party_profile_00::State::{NotWaitingForEpochKeyUpdate, WaitingForEpochKeyUpdate}, print_tree, tree_printer::{self, print_tree_detailed}, web_pki::{validate_client_credential, validate_server_credential},
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
    key_package: MlsMessage,
}

#[derive(Debug, Clone)]
pub struct ServerHello {
    welcome: MlsMessage,
}

pub(crate) fn initial_key_agreement_initiator_1(
    initiator: &Client<impl MlsConfig>,
) -> Result<ClientHello, MlsError> {
    // > The initiator starts the key agreement part of the protocol by
    // > creating a KeyPackage and sending a ClientHello to the responder.

    // IMPLEMENTOR_NOTE: check the timestamp. Is it expiration? Is there any requirement on the extensions?
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
) -> Result<(ServerHello, Client<impl MlsConfig>, Group<impl MlsConfig>), MlsError> {
    // > The responder inspects the KeyPackage and checks whether it supports
    // > the offered ciphersuite and whether the initiator has sufficient
    // > capabilities to support the connection.
    let initiator_key_package = client_hello.key_package.as_key_package().unwrap();
    let initiator_offered_ciphersuite = initiator_key_package.cipher_suite;
    let server_supported_ciphersuites = CipherSuite::all().collect::<BTreeSet<_>>();

    // IMPLEMENTOR NOTE: MLS 2-party profile doesn't support ciphersuite negotiation.

    if !server_supported_ciphersuites.contains(&initiator_offered_ciphersuite) {
        panic!("Unsupported ciphersuite: {initiator_offered_ciphersuite:?}");
    }

    // > The responder MUST interface with the AS to ensure that the
    // > credential in the KeyPackage is valid.
    validate_client_credential(initiator_key_package.signing_identity()).unwrap();

    // > The responder then locally creates an MLS group and commits to an Add
    // > proposal containing the initiator's KeyPackage.  The responder sends
    // > the resulting Welcome message back to the initiator as part of a
    // > ServerHello message.
    let responder = make_client(
        RustCryptoProvider::default(),
        signing_identity,
        signer,
        cipher_suite,
    )
    .unwrap();

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
        .unwrap(); // There's something to do here about commit options (yes that's the thing about ratchet tree (see at the end of this file))
    // commit options commitoptions
    let server_hello = ServerHello { welcome };
    // IMPLEMENTOR NOTE: when is the commit actually applied? I assume the server can do it right away, but it would be good to make it explicit.
    responder_group.apply_pending_commit()?;

    Ok((server_hello, responder, responder_group))
}

pub(crate) fn initial_key_agreement_initiator_2(
    initiator: &Client<impl MlsConfig>,
    trust_anchors: &[TrustAnchor<'_>],
    server_hello: ServerHello,
) -> Result<Group<impl MlsConfig>, MlsError> {
    // > The initiator uses the Welcome to create its local group state.
    let (initiator_group, _) = initiator.join_group(None, &server_hello.welcome, None)?;

    // > The initiator then inspects the group state and MUST interface with the
    // > AS to ensure that the credential of the responder is valid.

    // IMPLEMENTOR NOTE: 'inspects the use case' is too vague. What should the initiator inspect exactly?
    // Only validating the credentials?
    println!("server hello: {server_hello:?}");
    print_tree(&initiator_group);
    println!("\n\n\n");
    tree_printer::print_tree(&initiator_group);

    // IMPLEMENTOR NOTE: what is the identity. Should it be specified? How am I meant to find the identity of the server within the group?
    // validator.validate(initiator_group.member_at_index(0).unwrap());
    // This should at least be mentioned in the specs.
    // It seems like leaf index is not necessarily stable?
    //
    // From the MLS RFC https://datatracker.ietf.org/doc/rfc9420/ [5.3.3.]
    // Internally to the protocol, group members are uniquely identified by
    // their leaf index.  However, a leaf index is only valid for referring
    // to members in a given epoch.  The same leaf index may represent a
    // different member, or no member at all, in a subsequent epoch.
    let responder_member = initiator_group.member_at_index(0).unwrap();
    validate_server_credential(responder_member.signing_identity(), trust_anchors, None).unwrap();

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

// IMPLEMENTOR'S NOTE: here we're missing 'Unless it's an initiator that is waiting for an epoch key update)
#[derive(Debug, Clone)]
pub(crate) struct ConnectionUpdate {
    update: MlsMessage,
}

#[derive(Debug, Clone)]
pub(crate) struct EpochKeyUpdate {
    epoch: u64,
}

#[derive(Debug, PartialEq)]
pub(crate) enum State {
    WaitingForEpochKeyUpdate,
    NotWaitingForEpochKeyUpdate,
}

pub(crate) enum Role {
    Initiator,
    Responder,
}

#[derive(Debug)]
pub enum TwoPartyError {
    Mls(MlsError),
    UnexpectedEpochKeyUpdate,
    EpochMismatch { expected: u64, got: u64 },
}

impl From<MlsError> for TwoPartyError {
    fn from(e: MlsError) -> Self {
        TwoPartyError::Mls(e)
    }
}

impl std::fmt::Display for TwoPartyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TwoPartyError::Mls(e) => write!(f, "{e}"),
            TwoPartyError::UnexpectedEpochKeyUpdate => {
                write!(f, "received EpochKeyUpdate while not waiting for one")
            }
            TwoPartyError::EpochMismatch { expected, got } => {
                write!(f, "epoch mismatch: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for TwoPartyError {}

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
            state: State::NotWaitingForEpochKeyUpdate,
            role,
        }
    }

    pub(crate) fn create_connection_update(
        &mut self,
        group: &mut Group<impl MlsConfig>,
    ) -> Result<Option<ConnectionUpdate>, MlsError> {
        // *  Each party may send a ConnectionUpdate if they are not currently
        //     waiting for an EpochKeyUpdate to confirm a previous
        //     ConnectionUpdate

        // IMPLEMENTOR'S NOTE: the draft doesn't define what goes in the ConnectionUpdate commit message and how you generate it.
        match self.state {
            State::WaitingForEpochKeyUpdate => Ok(None),
            State::NotWaitingForEpochKeyUpdate => {
                group.propose_update(vec![])?;
                let commit = group.commit(vec![])?;
                self.state = WaitingForEpochKeyUpdate;

                Ok(Some(ConnectionUpdate {
                    update: commit.commit_message,
                }))
            }
        }
    }

    pub(crate) fn handle_connection_update(
        &mut self,
        group: &mut Group<impl MlsConfig>,
        connection_update: ConnectionUpdate,
    ) -> Result<Option<EpochKeyUpdate>, MlsError> {
        // TODO: WIP — incomplete match expression
        // match connection_update.update.into_proposal_reference(&CipherSuite::CURVE25519_AES128)
        // dbg!(&connection_update.update);
        match (&self.state, &self.role) {
            //
            // *  If either party receives a ConnectionUpdate and they're not
            //     currently waiting for an EpochKeyUpdate, they MUST validate and
            //     apply the commit and respond with an EpochKeyUpdate, where epoch
            //     is the group's new epoch
            (State::NotWaitingForEpochKeyUpdate, _) => {
                group.process_incoming_message(connection_update.update)?;

                Ok(Some(EpochKeyUpdate {
                    epoch: group.current_epoch(),
                }))
            }
            // *  If the initiator receives a ConnectionUpdate while waiting for an
            //     EpochKeyUpdate, it MUST ignore the ConnectionUpdate and resume
            //     waiting
            (State::WaitingForEpochKeyUpdate, Role::Initiator) => Ok(None),
            (State::WaitingForEpochKeyUpdate, Role::Responder) => {
                // *  If the responder receives a ConnectionUpdate while waiting for an
                //     EpochKeyUpdate, it MUST drop its locally pending commit and
                //     validate and apply the commit as if it hadn't been waiting for an
                //     EpochKeyUpdate

                group.clear_pending_commit();

                group.clear_proposal_cache(); // TODO I think this is unnecessary. To chec

                // Checks are implemented as part of the `TwoPartyMlsRules` MlsRules implementation
                let _received = group.process_incoming_message(connection_update.update)?; // TODO what happens if it errors here? Means that the we dropped a commit unnecessarily. Is this a problem or does it just mean that the other member is misbehaving so all bets are off anyway? Do we stop the conneciton in this case anyway?

                group.commit(vec![])?;
                group.apply_pending_commit()?;


                self.state = State::NotWaitingForEpochKeyUpdate;

                Ok(Some(EpochKeyUpdate {
                    epoch: group.current_epoch(),
                }))
            }
        }

        // *  A party receiving a ConnectionUpdate MUST start using the key
        //     material of the new epoch after sending the EpochKeyUpdate
    }

    pub(crate) fn handle_epoch_key_update(
        &mut self,
        group: &mut Group<impl MlsConfig>,
        epoch_key_update: EpochKeyUpdate,
    ) -> Result<(), TwoPartyError> {
        match &self.state {
            WaitingForEpochKeyUpdate => {
                // IMPLEMENTOR's note, unclear what we're meant to do here with the epoch number.
                let expected = group.current_epoch() + 1;
                if expected != epoch_key_update.epoch {
                    return Err(TwoPartyError::EpochMismatch {
                        expected,
                        got: epoch_key_update.epoch,
                    });
                }
                group.apply_pending_commit()?;
                self.state = NotWaitingForEpochKeyUpdate;
                Ok(())
            }
            State::NotWaitingForEpochKeyUpdate => {
                Err(TwoPartyError::UnexpectedEpochKeyUpdate)
            }
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

#[derive(Debug)]
pub enum TwoPartyRulesError {
    ExpectedOneUpdateProposal,
}

impl std::fmt::Display for TwoPartyRulesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TwoPartyRulesError::ExpectedOneUpdateProposal => {
                write!(f, "expected at most one update proposal and no other proposal types")
            }
        }
    }
}

impl std::error::Error for TwoPartyRulesError {}

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
            encryption_options: EncryptionOptions::default(),
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
        Ok(self.commit_options.clone())
    }

    fn encryption_options(
        &self,
        _roster: &Roster<'_>,
        _context: &GroupContext,
    ) -> Result<EncryptionOptions, Self::Error> {
        Ok(self.encryption_options.clone())
    }
}
