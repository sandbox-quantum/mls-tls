use std::{
    collections::BTreeSet,
    error::Error,
};

use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, IdentityProvider, MlsMessage, client_builder::MlsConfig, crypto::SignatureSecretKey, error::MlsError, group::ReceivedMessage, identity::{
        SigningIdentity, basic::{BasicCredential, BasicIdentityProvider},
    }, mls_rules::{CommitOptions, DefaultMlsRules}, storage_provider::in_memory::{
        InMemoryGroupStateStorage, InMemoryKeyPackageStorage, InMemoryPreSharedKeyStorage,
    },
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

use crate::web_pki::{PeerValidation, WebPkiIdentityProvider};

mod web_pki;

#[derive(Debug, Clone)]
struct ClientHello {
    key_package: MlsMessage,
}

#[derive(Debug, Clone)]
struct ServerHello {
    welcome: MlsMessage,
}

struct MlsTlsClient<MConf: MlsConfig, MlsIdentityProvider: IdentityProvider> {
    mls_client: Client<MConf>,
    mls_credential_validator: MlsIdentityProvider,
}

struct MlsTlsServer<MConf: MlsConfig, MlsIdentityProvider: IdentityProvider> {
    mls_client: Client<MConf>,
    mls_credential_validator: MlsIdentityProvider,
}

fn mls_two_party_profile_00_initial_key_agreement_initiator_1(
    initiator: &Client<impl MlsConfig>,
) -> Result<ClientHello, MlsError> {
    // The initiator starts the key agreement part of the protocol by
    // creating a KeyPackage and sending a ClientHello to the responder.

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

fn mls_two_party_profile_00_initial_key_agreement_responder_1(
    client_hello: ClientHello,
    identity_provider: impl IdentityProvider + Clone,
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

    // TODO check, I think this is done with the identity provider later on.

    // > The responder then locally creates an MLS group and commits to an Add
    // > proposal containing the initiator's KeyPackage.  The responder sends
    // > the resulting Welcome message back to the initiator as part of a
    // > ServerHello message.

    let crypto_provider = RustCryptoProvider::default();
    let cipher_suite_provider = crypto_provider.cipher_suite_provider(initiator_offered_ciphersuite).unwrap();
    let (secret, public) = cipher_suite_provider.signature_key_generate().unwrap();
    // IMPLEMENTOR NOTE: what is the credential for the client where there is no client authentication.
    // Is client authentication mandatory?
    //
    // // TODO: how does that work with x509?
    let signing_identity = SigningIdentity::new(BasicCredential::new(b"responder".to_vec()).into_credential(), public);


    let responder = make_client(
        crypto_provider,
        identity_provider,
        signing_identity,
        secret,
        initiator_offered_ciphersuite,
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
        .unwrap(); // There's something to do here about commit options
    let server_hello = ServerHello { welcome };
    // IMPLEMENTOR NOTE: when is the commit actually applied? I assume the server can do it right away, but it would be good to make it explicit.
    responder_group.apply_pending_commit()?;

    Ok((server_hello, responder, responder_group))
}

fn mls_two_party_profile_00_initial_key_agreement_initiator_2(
    initiator: &Client<impl MlsConfig>,
    server_hello: ServerHello,
) -> Result<Group<impl MlsConfig>, MlsError> {
    // > The initiator uses the Welcome to create its local group state.
    let (initiator_group, _) = initiator.join_group(None, &server_hello.welcome, None)?;

    // > The initiator then inspects the group state and MUST interface with the
    // > AS to ensure that the credential of the responder is valid.

    // IMPLEMENTOR NOTE: 'inspects the use case' is too vague. What should the initiator inspect exactly?
    // Only validating the credentials?
    println!("server hello: {server_hello:?}");

    // IMPLEMENTOR NOTE: what is the identity. Should it be specified? How am I meant to find the identity of the server within the group?
    // validator.validate(initiator_group.member_at_index(0).unwrap());
    // This should at least be mentioned in the specs.
    
    // TODO: I think this has been verified as part of the identity provider included with the client. To Be Checked
    

    Ok(initiator_group)
}

fn main() -> Result<(), Box<dyn Error>> {
    // draft-kohbrok-mls-two-party-profile-00
    // https://datatracker.ietf.org/doc/draft-kohbrok-mls-two-party-profile/00/
    //
    // 3. Initial key agreement
    let crypto_provider = RustCryptoProvider::default();
    let cipher_suite_provider = crypto_provider.cipher_suite_provider(CipherSuite::CURVE25519_AES128).unwrap();
    let (secret, public) = cipher_suite_provider.signature_key_generate().unwrap();
    // IMPLEMENTOR NOTE: what is the credential for the client where there is no client authentication.
    // Is client authentication mandatory?
    //
    // // TODO: how does that work with x509?
    let signing_identity = SigningIdentity::new(BasicCredential::new(b"initiator".to_vec()).into_credential(), public);


    let mls_tls_cient_mls_client = make_client(
        RustCryptoProvider::default(),
        WebPkiIdentityProvider::new(PeerValidation::NoSubjectValidation),
        signing_identity,
        secret,
        CipherSuite::CURVE25519_AES128,
    )?;
    let client_hello =
        mls_two_party_profile_00_initial_key_agreement_initiator_1(&mls_tls_cient_mls_client)?;

    let (server_hello, _server_mls_client, mut server_group) =
        mls_two_party_profile_00_initial_key_agreement_responder_1(
            client_hello,
            BasicIdentityProvider::default(),
        )?;

    let mut client_mls_group = mls_two_party_profile_00_initial_key_agreement_initiator_2(
        &mls_tls_cient_mls_client,
        server_hello,
    )?;

    let msg = server_group.encrypt_application_message(b"hello, from initiator!", vec![])?;
    let msg = client_mls_group.process_incoming_message(msg)?;

    println!("Received message {msg:?}");

    match msg {
        ReceivedMessage::ApplicationMessage(application_message_description) => {
            let msg_str = String::from_utf8_lossy(application_message_description.data());
            println!("{msg_str}");
        }
        _ => todo!(),
    }

    Ok(())
}

fn make_client<C: CryptoProvider + Clone>(
    crypto_provider: C,
    identity_provider: impl IdentityProvider + Clone,
    signing_identity: SigningIdentity,
    signer: SignatureSecretKey,
    cipher_suite: CipherSuite,
) -> Result<Client<impl MlsConfig>, MlsError> {
    let client = Client::builder()
        .identity_provider(identity_provider)
        .crypto_provider(crypto_provider)
        .signing_identity(signing_identity, signer, cipher_suite)
        .mls_rules(DefaultMlsRules::default().with_commit_options(CommitOptions::default()))
        .group_state_storage(InMemoryGroupStateStorage::default())
        .key_package_repo(InMemoryKeyPackageStorage::default())
        .psk_store(InMemoryPreSharedKeyStorage::default())
        // .extension_types([])                                           TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .crypto_provider(crypto_provider)                              TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .custom_proposal_types(types)                                  TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .extension_types(type_)                                        TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .group_state_storage(group_state_storage)                      TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .identity_provider(identity_provider)                          TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .key_package_lifetime(lifetime)                                TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .key_package_repo(key_package_repo)                            TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .mls_rules(mls_rules)                                          TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .protocol_version(version)                                     TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .protocol_versions(versions)                                   TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .psk(psk_id, psk)                                              TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .psk_store(psk_store)                                          TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .signer(signer)                                                TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .signing_identity(signing_identity, signer, cipher_suite)      TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        .build();
    Ok(client)
}
