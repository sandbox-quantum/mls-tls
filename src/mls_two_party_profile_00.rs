use std::collections::BTreeSet;

use mls_rs::{CipherSuite, Client, ExtensionList, Group, MlsMessage, client_builder::MlsConfig, crypto::SignatureSecretKey, error::MlsError, identity::SigningIdentity};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use rustls_pki_types::TrustAnchor;

use crate::{make_client, print_tree, tree_printer, web_pki::{validate_client_credential, validate_server_credential}};

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
        .unwrap();  // There's something to do here about commit options (yes that's the thing about ratchet tree (see at the end of this file))
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