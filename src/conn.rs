//! The sans-I/O connection core, speaking the Python `mls-tls-python-pedantic` wire protocol.
//!
//! Everything rides outer transport frames (content type `0x17`). The message sequence is:
//! 1. server → client: the server's raw signing public key (pre-handshake);
//! 2. client → server: ClientHello (`MlsTlsHandshake` envelope wrapping `MLSMessage(KeyPackage)`);
//! 3. server → client: ServerHello (a bare `MLSMessage(Welcome)`);
//! 4. both: application data (inner AEAD records) and plaintext `SignalingMessage`s (rekeys).
//!
//! The public byte pipeline is rustls-shaped: [`read_tls`]/[`write_tls`]/[`process_new_packets`]/
//! [`reader`]/[`writer`]. Sending a rekey is explicit ([`refresh_traffic_keys`]); handling inbound
//! control is automatic inside [`process_new_packets`].
//!
//! [`read_tls`]: ConnectionCommon::read_tls
//! [`write_tls`]: ConnectionCommon::write_tls
//! [`process_new_packets`]: ConnectionCommon::process_new_packets
//! [`reader`]: ConnectionCommon::reader
//! [`writer`]: ConnectionCommon::writer
//! [`refresh_traffic_keys`]: ConnectionCommon::refresh_traffic_keys

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::ops::{Deref, DerefMut};

use mls_rs::CipherSuite;
use mls_rs::MlsMessage;
use mls_rs::crypto::SignatureSecretKey;
use mls_rs::identity::SigningIdentity;
use mls_rs::storage_provider::in_memory::InMemoryGroupStateStorage;
use rustls_pki_types::ServerName;

use crate::client::ServerCertVerifier;
use crate::create_record_layer;
use crate::crypto::provider::MlsTlsCryptoProvider;
use crate::deframer::{Envelope, MessageDeframer, Signaling, frame_transport, is_app_data};
use crate::error::Error;
use crate::mls_config::{MlsClient, MlsGroup};
use crate::mls_two_party_profile_00::{
    ClientHello, ConnectionUpdate, EpochKeyUpdate, Mls2Party, Role, ServerHello,
    initial_key_agreement_initiator_2, initial_key_agreement_responder_1,
};
use crate::resumption::ResumptionState;
use crate::server::ClientCertVerifier;
use crate::tls_record::{ContentType, DirectionalRekey, RecordLayer, Role as Side, TlsPlaintext};
use crate::web_pki::validate_server_credential;

/// Summary of the connection's I/O state after [`ConnectionCommon::process_new_packets`].
#[derive(Debug, Clone, Copy)]
pub struct IoState {
    /// Bytes buffered for [`ConnectionCommon::write_tls`].
    pub tls_bytes_to_write: usize,
    /// Decrypted plaintext bytes available via [`ConnectionCommon::reader`].
    pub plaintext_bytes_to_read: usize,
    /// Whether the peer has signalled close.
    pub peer_has_closed: bool,
}

/// Handshake progress of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HsState {
    /// Client: waiting for the server's pre-handshake public key.
    ClientAwaitingServerPubkey,
    /// Client: sent ClientHello, waiting for the ServerHello (Welcome).
    ClientAwaitingServerHello,
    /// Server: sent its public key, waiting for the ClientHello.
    ServerAwaitingClientHello,
    /// The initial key agreement is complete.
    Established,
}

/// Client handshake context, retained until the handshake completes.
pub(crate) struct ClientCtx {
    pub(crate) client: MlsClient,
    pub(crate) verifier: ServerCertVerifier,
    pub(crate) server_name: ServerName<'static>,
    /// The ClientHello (KeyPackage) to send once the server pubkey arrives.
    pub(crate) pending_client_hello: MlsMessage,
    /// The server's pre-handshake signing public key, once received.
    pub(crate) server_pubkey: Option<Vec<u8>>,
}

/// Server handshake context, retained until the ClientHello is processed.
pub(crate) struct ServerCtx {
    pub(crate) signing_identity: SigningIdentity,
    pub(crate) signer: SignatureSecretKey,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) storage: InMemoryGroupStateStorage,
    pub(crate) client_verifier: ClientCertVerifier,
}

/// The role-agnostic connection core. `ClientConnection`/`ServerConnection` `Deref` to this.
pub struct ConnectionCommon {
    side: Side,
    state: HsState,
    group: Option<MlsGroup>,
    record: Option<RecordLayer>,
    two_party: Option<Mls2Party>,
    client_ctx: Option<ClientCtx>,
    server_ctx: Option<ServerCtx>,
    deframer: MessageDeframer,
    received_plaintext: VecDeque<u8>,
    sendable_tls: VecDeque<u8>,
    peer_closed: bool,
}

impl ConnectionCommon {
    /// Construct a fresh client core. It waits for the server's pre-handshake public key before
    /// sending its ClientHello (matching the Python peer's ordering).
    pub(crate) fn new_client(
        client: MlsClient,
        verifier: ServerCertVerifier,
        server_name: ServerName<'static>,
        client_hello_kp: MlsMessage,
    ) -> Result<Self, Error> {
        Ok(Self {
            side: Side::Client,
            state: HsState::ClientAwaitingServerPubkey,
            group: None,
            record: None,
            two_party: None,
            client_ctx: Some(ClientCtx {
                client,
                verifier,
                server_name,
                pending_client_hello: client_hello_kp,
                server_pubkey: None,
            }),
            server_ctx: None,
            deframer: MessageDeframer::new(),
            received_plaintext: VecDeque::new(),
            sendable_tls: VecDeque::new(),
            peer_closed: false,
        })
    }

    /// Construct a server core: queue the server's public key and await the ClientHello.
    pub(crate) fn new_server(server_ctx: ServerCtx) -> Result<Self, Error> {
        let pubkey = server_ctx.signing_identity.signature_key.as_bytes().to_vec();
        let mut sendable_tls = VecDeque::new();
        sendable_tls.extend(frame_transport(&pubkey));
        Ok(Self {
            side: Side::Server,
            state: HsState::ServerAwaitingClientHello,
            group: None,
            record: None,
            two_party: None,
            client_ctx: None,
            server_ctx: Some(server_ctx),
            deframer: MessageDeframer::new(),
            received_plaintext: VecDeque::new(),
            sendable_tls,
            peer_closed: false,
        })
    }

    // --- rustls-shaped byte pipeline ---

    /// Read raw TLS bytes from `rd`. Call [`process_new_packets`](Self::process_new_packets) after.
    pub fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        let mut buf = [0u8; 8192];
        let n = rd.read(&mut buf)?;
        self.deframer.push(&buf[..n]);
        Ok(n)
    }

    /// Write buffered outgoing TLS bytes to `wr`.
    pub fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        if self.sendable_tls.is_empty() {
            return Ok(0);
        }
        self.sendable_tls.make_contiguous();
        let (front, _) = self.sendable_tls.as_slices();
        let n = wr.write(front)?;
        self.sendable_tls.drain(..n);
        Ok(n)
    }

    /// Process buffered inbound frames: advance the handshake, decrypt application data, and handle
    /// in-band control (auto-queuing any replies).
    pub fn process_new_packets(&mut self) -> Result<IoState, Error> {
        while let Some(payload) = self.deframer.pop()? {
            self.process_payload(payload)?;
        }
        Ok(IoState {
            tls_bytes_to_write: self.sendable_tls.len(),
            plaintext_bytes_to_read: self.received_plaintext.len(),
            peer_has_closed: self.peer_closed,
        })
    }

    /// Read decrypted application plaintext.
    pub fn reader(&mut self) -> Reader<'_> {
        Reader { conn: self }
    }

    /// Write application plaintext to be encrypted and sent.
    pub fn writer(&mut self) -> Writer<'_> {
        Writer { conn: self }
    }

    /// True if the caller should read more TLS bytes.
    pub fn wants_read(&self) -> bool {
        !self.peer_closed && self.received_plaintext.is_empty()
    }

    /// True if there are buffered TLS bytes to write.
    pub fn wants_write(&self) -> bool {
        !self.sendable_tls.is_empty()
    }

    /// True until the initial key agreement completes.
    pub fn is_handshaking(&self) -> bool {
        self.state != HsState::Established
    }

    /// Snapshot the current group for cross-connection resumption.
    pub fn export_resumption_state(&mut self) -> Result<ResumptionState, Error> {
        let group = self
            .group
            .as_mut()
            .ok_or(Error::UnexpectedMessage("no group to export"))?;
        group.write_to_storage()?;
        Ok(ResumptionState {
            group_id: group.group_id().to_vec(),
        })
    }

    // --- handshake / control dispatch ---

    fn process_payload(&mut self, payload: Vec<u8>) -> Result<(), Error> {
        match self.state {
            HsState::ClientAwaitingServerPubkey => self.client_on_server_pubkey(payload),
            HsState::ClientAwaitingServerHello => self.client_on_server_hello(payload),
            HsState::ServerAwaitingClientHello => self.server_on_client_hello(payload),
            HsState::Established => self.on_established(payload),
        }
    }

    fn client_on_server_pubkey(&mut self, payload: Vec<u8>) -> Result<(), Error> {
        let ctx = self
            .client_ctx
            .as_mut()
            .ok_or(Error::UnexpectedMessage("no client context"))?;
        ctx.server_pubkey = Some(payload);
        let bytes = Envelope::ClientHello(ctx.pending_client_hello.clone()).encode()?;
        self.sendable_tls.extend(frame_transport(&bytes));
        self.state = HsState::ClientAwaitingServerHello;
        Ok(())
    }

    fn client_on_server_hello(&mut self, payload: Vec<u8>) -> Result<(), Error> {
        let welcome = MlsMessage::from_bytes(&payload)?;
        let ctx = self
            .client_ctx
            .take()
            .ok_or(Error::UnexpectedMessage("unexpected ServerHello"))?;

        let mut group =
            initial_key_agreement_initiator_2(&ctx.client, ServerHello { welcome })?;

        verify_server(&group, &ctx.verifier, &ctx.server_name, ctx.server_pubkey.as_deref())?;

        let record = create_record_layer(&group, Side::Client);
        group.write_to_storage()?;

        self.group = Some(group);
        self.record = Some(record);
        self.two_party = Some(Mls2Party::new(Role::Initiator));
        self.state = HsState::Established;
        Ok(())
    }

    fn server_on_client_hello(&mut self, payload: Vec<u8>) -> Result<(), Error> {
        let envelope = Envelope::decode(&payload)?;
        let ctx = self
            .server_ctx
            .take()
            .ok_or(Error::UnexpectedMessage("no server context"))?;

        match envelope {
            Envelope::ClientHello(key_package) => {
                if let ClientCertVerifier::WebPki { .. } = ctx.client_verifier {
                    return Err(Error::Unsupported("client certificate verification"));
                }
                let (server_hello, mut group) = initial_key_agreement_responder_1(
                    ClientHello { key_package },
                    ctx.signing_identity,
                    ctx.signer,
                    ctx.cipher_suite,
                    ctx.storage,
                )?;
                let record = create_record_layer(&group, Side::Server);
                group.write_to_storage()?;

                // ServerHello is a bare MLSMessage(Welcome) — no envelope.
                let welcome_bytes = server_hello.welcome.to_bytes()?;
                self.sendable_tls.extend(frame_transport(&welcome_bytes));

                self.group = Some(group);
                self.record = Some(record);
                self.two_party = Some(Mls2Party::new(Role::Responder));
                self.state = HsState::Established;
                Ok(())
            }
            Envelope::Resumption(_) => {
                Err(Error::Unsupported("resumption not yet wired to the new framing"))
            }
        }
    }

    fn on_established(&mut self, payload: Vec<u8>) -> Result<(), Error> {
        if is_app_data(&payload) {
            let record = self
                .record
                .as_mut()
                .ok_or(Error::UnexpectedMessage("application data before handshake"))?;
            let plaintext: TlsPlaintext = record.decrypt(&payload)?;
            match plaintext.content_type {
                ContentType::ApplicationData => {
                    self.received_plaintext.extend(plaintext.fragment);
                    Ok(())
                }
                ContentType::Alert => {
                    self.peer_closed = true;
                    Ok(())
                }
                _ => Err(Error::UnexpectedMessage("unexpected inner content type")),
            }
        } else {
            let signaling = Signaling::decode(&payload)?;
            self.process_signaling(signaling)
        }
    }

    // --- explicit control ---

    /// Explicitly initiate a rekey by sending a `ConnectionUpdate` (analog of rustls'
    /// `refresh_traffic_keys`). Inbound handling of the resulting control is automatic.
    pub fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        let crypto = MlsTlsCryptoProvider::new();
        let group = self
            .group
            .as_mut()
            .ok_or(Error::UnexpectedMessage("rekey before handshake"))?;
        let two_party = self
            .two_party
            .as_mut()
            .ok_or(Error::UnexpectedMessage("rekey before handshake"))?;
        if let Some((connection_update, rekey)) =
            two_party.create_connection_update(group, &crypto)?
        {
            self.send_signaling(Signaling::ConnectionUpdate {
                update_requested: false,
                commit: connection_update.update,
            })?;
            if let Some(rekey) = rekey {
                self.apply_directional_rekey(rekey)?;
            }
        }
        Ok(())
    }

    /// In-band control handling (automatic).
    fn process_signaling(&mut self, signaling: Signaling) -> Result<(), Error> {
        let crypto = MlsTlsCryptoProvider::new();
        match signaling {
            Signaling::ConnectionUpdate { commit, .. } => {
                let (rekey, reply) = {
                    let group = self
                        .group
                        .as_mut()
                        .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                    let two_party = self
                        .two_party
                        .as_mut()
                        .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                    two_party.handle_connection_update(
                        group,
                        &crypto,
                        ConnectionUpdate { update: commit },
                    )?
                };
                if let Some(eku) = reply {
                    self.send_signaling(Signaling::EpochKeyUpdate(eku.epoch))?;
                }
                if let Some(rekey) = rekey {
                    self.apply_directional_rekey(rekey)?;
                }
                Ok(())
            }
            Signaling::EpochKeyUpdate(epoch) => {
                let (rekey, reply) = {
                    let group = self
                        .group
                        .as_mut()
                        .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                    let two_party = self
                        .two_party
                        .as_mut()
                        .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                    two_party.handle_epoch_key_update(group, &crypto, EpochKeyUpdate { epoch })?
                };
                if let Some(eku) = reply {
                    self.send_signaling(Signaling::EpochKeyUpdate(eku.epoch))?;
                }
                if let Some(rekey) = rekey {
                    self.apply_directional_rekey(rekey)?;
                }
                Ok(())
            }
            Signaling::ConnectionConfirmation(_) => Err(Error::Unsupported(
                "resumption not yet wired to the new framing",
            )),
        }
    }

    fn send_signaling(&mut self, signaling: Signaling) -> Result<(), Error> {
        let bytes = signaling.encode()?;
        self.sendable_tls.extend(frame_transport(&bytes));
        Ok(())
    }

    fn apply_directional_rekey(&mut self, rekey: DirectionalRekey) -> Result<(), Error> {
        let side = self.side;
        self.record_mut()?.apply_rekey(rekey, side);
        if let Some(group) = self.group.as_mut() {
            group.write_to_storage().ok();
        }
        Ok(())
    }

    fn record_mut(&mut self) -> Result<&mut RecordLayer, Error> {
        self.record
            .as_mut()
            .ok_or(Error::UnexpectedMessage("record layer not established"))
    }

    fn encrypt_app_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let record = self
            .record
            .as_mut()
            .ok_or(Error::UnexpectedMessage("cannot send before handshake"))?;
        for inner in record.encrypt(ContentType::ApplicationData, data)? {
            self.sendable_tls.extend(frame_transport(&inner));
        }
        Ok(())
    }
}

/// Verify the server's credential per policy plus the pre-handshake public-key binding.
fn verify_server(
    group: &MlsGroup,
    verifier: &ServerCertVerifier,
    server_name: &ServerName<'_>,
    pre_handshake_pubkey: Option<&[u8]>,
) -> Result<(), Error> {
    let member = group
        .member_at_index(0)
        .ok_or(Error::UnexpectedMessage("responder member missing"))?;
    let signing_identity = member.signing_identity();

    // Bind the joined group's responder key to the key the server presented pre-handshake.
    if let Some(expected) = pre_handshake_pubkey
        && signing_identity.signature_key.as_bytes() != expected
    {
        return Err(Error::PeerAuth("server key does not match presented key"));
    }

    match verifier {
        ServerCertVerifier::None => Ok(()),
        ServerCertVerifier::WebPki { trust_anchors } => {
            validate_server_credential(signing_identity, trust_anchors, Some(server_name))?;
            Ok(())
        }
    }
}

/// `io::Read` over decrypted application plaintext.
pub struct Reader<'a> {
    conn: &'a mut ConnectionCommon,
}

impl Read for Reader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.conn.received_plaintext.len().min(buf.len());
        for (slot, byte) in buf.iter_mut().zip(self.conn.received_plaintext.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }
}

/// `io::Write` that encrypts application plaintext into the outgoing record buffer.
pub struct Writer<'a> {
    conn: &'a mut ConnectionCommon,
}

impl Write for Writer<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.conn
            .encrypt_app_data(buf)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A connection of either role, unified behind [`ConnectionCommon`] via `Deref`.
pub enum Connection {
    Client(crate::client::ClientConnection),
    Server(crate::server::ServerConnection),
}

impl Connection {
    /// True for a client (initiator) connection.
    pub fn is_client(&self) -> bool {
        matches!(self, Connection::Client(_))
    }
}

impl From<crate::client::ClientConnection> for Connection {
    fn from(c: crate::client::ClientConnection) -> Self {
        Connection::Client(c)
    }
}

impl From<crate::server::ServerConnection> for Connection {
    fn from(s: crate::server::ServerConnection) -> Self {
        Connection::Server(s)
    }
}

impl Deref for Connection {
    type Target = ConnectionCommon;
    fn deref(&self) -> &ConnectionCommon {
        match self {
            Connection::Client(c) => c,
            Connection::Server(s) => s,
        }
    }
}

impl DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut ConnectionCommon {
        match self {
            Connection::Client(c) => c,
            Connection::Server(s) => s,
        }
    }
}
