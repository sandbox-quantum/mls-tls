//! The sans-I/O connection core.
//!
//! [`ConnectionCommon`] owns the MLS group, the TLS 1.3 record layer, and the two-party state
//! machine, and exposes the rustls-shaped byte pipeline: feed ciphertext with [`read_tls`], drive
//! processing with [`process_new_packets`], exchange plaintext via [`reader`]/[`writer`], and drain
//! ciphertext with [`write_tls`]. Application data *and* in-band control both ride this one pipeline.
//!
//! [`read_tls`]: ConnectionCommon::read_tls
//! [`write_tls`]: ConnectionCommon::write_tls
//! [`process_new_packets`]: ConnectionCommon::process_new_packets
//! [`reader`]: ConnectionCommon::reader
//! [`writer`]: ConnectionCommon::writer

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::ops::{Deref, DerefMut};

use mls_rs::MlsMessage;
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use rustls_pki_types::ServerName;

use crate::client::ServerCertVerifier;
use crate::create_record_layer;
use crate::deframer::{Frame, HandshakePayload, MessageDeframer, frame_plaintext_handshake};
use crate::error::Error;
use crate::mls_config::{MlsClient, MlsGroup};
use crate::resumption::ResumptionState;
use crate::mls_two_party_profile_00::{
    ConnectionUpdate, EpochKeyUpdate, Mls2Party, ResumptionRequest, ResumptionResponse, Role,
    ServerHello, initial_key_agreement_initiator_2,
};
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

/// Client-side context retained until the `ServerHello` completes the handshake.
pub(crate) struct ClientCtx {
    pub(crate) client: MlsClient,
    pub(crate) verifier: ServerCertVerifier,
    pub(crate) server_name: ServerName<'static>,
}

/// The role-agnostic connection core. `ClientConnection`/`ServerConnection` `Deref` to this.
pub struct ConnectionCommon {
    side: Side,
    // Established protocol state (present once the handshake has produced a group).
    group: Option<MlsGroup>,
    record: Option<RecordLayer>,
    two_party: Option<Mls2Party>,
    // Client handshake context (present only while a client awaits the ServerHello).
    client_ctx: Option<ClientCtx>,
    // I/O plumbing.
    deframer: MessageDeframer,
    received_plaintext: VecDeque<u8>,
    sendable_tls: VecDeque<u8>,
    handshake_done: bool,
    peer_closed: bool,
    // True for a client mid cross-connection resumption (awaiting a plaintext ResumptionResponse).
    resuming_client: bool,
}

impl ConnectionCommon {
    /// Construct a client core that has queued its ClientHello and awaits the ServerHello.
    pub(crate) fn new_client(
        client: MlsClient,
        verifier: ServerCertVerifier,
        server_name: ServerName<'static>,
        client_hello_kp: MlsMessage,
    ) -> Result<Self, Error> {
        let payload = HandshakePayload::ClientHello(client_hello_kp).encode()?;
        let mut sendable_tls = VecDeque::new();
        sendable_tls.extend(frame_plaintext_handshake(&payload));
        Ok(Self {
            side: Side::Client,
            group: None,
            record: None,
            two_party: None,
            client_ctx: Some(ClientCtx {
                client,
                verifier,
                server_name,
            }),
            deframer: MessageDeframer::new(),
            received_plaintext: VecDeque::new(),
            sendable_tls,
            handshake_done: false,
            peer_closed: false,
            resuming_client: false,
        })
    }

    /// Construct an established server core that has queued its ServerHello.
    pub(crate) fn new_server_established(
        group: MlsGroup,
        record: RecordLayer,
        server_hello_welcome: MlsMessage,
    ) -> Result<Self, Error> {
        let payload = HandshakePayload::ServerHello(server_hello_welcome).encode()?;
        let mut sendable_tls = VecDeque::new();
        sendable_tls.extend(frame_plaintext_handshake(&payload));
        Ok(Self {
            side: Side::Server,
            group: Some(group),
            record: Some(record),
            two_party: Some(Mls2Party::new(Role::Responder)),
            client_ctx: None,
            deframer: MessageDeframer::new(),
            received_plaintext: VecDeque::new(),
            sendable_tls,
            handshake_done: true,
            peer_closed: false,
            resuming_client: false,
        })
    }

    /// Construct a client core resuming from a reloaded group over a fresh transport. The
    /// ResumptionRequest is queued as a *plaintext* frame (no record layer exists yet); the record
    /// layer is built when the plaintext ResumptionResponse arrives.
    pub(crate) fn new_client_resuming(
        group: MlsGroup,
        two_party: Mls2Party,
        request_commit: MlsMessage,
    ) -> Result<Self, Error> {
        let payload = HandshakePayload::ResumptionRequest(request_commit).encode()?;
        let mut sendable_tls = VecDeque::new();
        sendable_tls.extend(frame_plaintext_handshake(&payload));
        Ok(Self {
            side: Side::Client,
            group: Some(group),
            record: None,
            two_party: Some(two_party),
            client_ctx: None,
            deframer: MessageDeframer::new(),
            received_plaintext: VecDeque::new(),
            sendable_tls,
            handshake_done: false,
            peer_closed: false,
            resuming_client: true,
        })
    }

    /// Construct a resumed server core: the group is reloaded and already advanced to the resumed
    /// epoch, the record layer is rebuilt, and the ResumptionResponse is queued as a plaintext frame.
    pub(crate) fn new_server_resumed(
        group: MlsGroup,
        record: RecordLayer,
        two_party: Mls2Party,
        response_commit: MlsMessage,
    ) -> Result<Self, Error> {
        let payload = HandshakePayload::ResumptionResponse(response_commit).encode()?;
        let mut sendable_tls = VecDeque::new();
        sendable_tls.extend(frame_plaintext_handshake(&payload));
        Ok(Self {
            side: Side::Server,
            group: Some(group),
            record: Some(record),
            two_party: Some(two_party),
            client_ctx: None,
            deframer: MessageDeframer::new(),
            received_plaintext: VecDeque::new(),
            sendable_tls,
            handshake_done: true,
            peer_closed: false,
            resuming_client: false,
        })
    }

    // --- rustls-shaped byte pipeline ---

    /// Read raw TLS bytes from `rd` into the internal buffer. Does not process them; call
    /// [`process_new_packets`](Self::process_new_packets) afterwards.
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
        // Make the buffer contiguous so a single write can flush everything available.
        self.sendable_tls.make_contiguous();
        let (front, _) = self.sendable_tls.as_slices();
        let n = wr.write(front)?;
        self.sendable_tls.drain(..n);
        Ok(n)
    }

    /// Process buffered inbound records: advance the handshake, decrypt application data, and handle
    /// in-band control messages (auto-queueing any replies).
    pub fn process_new_packets(&mut self) -> Result<IoState, Error> {
        while let Some(frame) = self.deframer.pop()? {
            self.process_frame(frame)?;
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

    /// True until the *initial* key agreement completes (ongoing rekeys are invisible here).
    pub fn is_handshaking(&self) -> bool {
        !self.handshake_done
    }

    // --- internals ---

    fn process_frame(&mut self, frame: Frame) -> Result<(), Error> {
        if frame.outer_type == ContentType::Handshake as u8 {
            // Phase A: plaintext handshake frame.
            let payload = HandshakePayload::decode(frame.body())?;
            self.process_plaintext_handshake(payload)
        } else if frame.outer_type == ContentType::ApplicationData as u8 {
            // Phase B: encrypted record.
            let record = self
                .record
                .as_mut()
                .ok_or(Error::UnexpectedMessage("application data before handshake"))?;
            let plaintext = record.decrypt(&frame.record)?;
            self.process_decrypted(plaintext)
        } else {
            Err(Error::UnexpectedMessage("unexpected outer record type"))
        }
    }

    fn process_plaintext_handshake(&mut self, payload: HandshakePayload) -> Result<(), Error> {
        match payload {
            HandshakePayload::ServerHello(welcome) => self.complete_client_handshake(welcome),
            HandshakePayload::ResumptionResponse(commit) if self.resuming_client => {
                self.complete_client_resume(commit)
            }
            _ => Err(Error::UnexpectedMessage(
                "unexpected plaintext handshake message",
            )),
        }
    }

    fn complete_client_resume(&mut self, commit: MlsMessage) -> Result<(), Error> {
        {
            let group = self
                .group
                .as_mut()
                .ok_or(Error::UnexpectedMessage("resume without group"))?;
            let two_party = self
                .two_party
                .as_mut()
                .ok_or(Error::UnexpectedMessage("resume without state"))?;
            two_party.handle_resumption_response(group, ResumptionResponse { commit })?;
        }
        self.rebuild_record_layer()?;
        self.group.as_mut().unwrap().write_to_storage()?;
        self.handshake_done = true;
        self.resuming_client = false;
        Ok(())
    }

    fn complete_client_handshake(&mut self, welcome: MlsMessage) -> Result<(), Error> {
        let ctx = self
            .client_ctx
            .take()
            .ok_or(Error::UnexpectedMessage("unexpected ServerHello"))?;

        let server_hello = ServerHello { welcome };
        let mut group = initial_key_agreement_initiator_2(&ctx.client, server_hello)?;

        // Manual, directional peer check: verify the *server's* credential from the joined group,
        // threading the requested ServerName (the group's mls-rs provider is accept-all).
        verify_server_credential(&group, &ctx.verifier, &ctx.server_name)?;

        let record = create_record_layer(&group, Side::Client, RustCryptoProvider::default());
        group.write_to_storage()?; // persist for resumption

        self.group = Some(group);
        self.record = Some(record);
        self.two_party = Some(Mls2Party::new(Role::Initiator));
        self.handshake_done = true;
        Ok(())
    }

    fn process_decrypted(&mut self, plaintext: TlsPlaintext) -> Result<(), Error> {
        match plaintext.content_type {
            ContentType::ApplicationData => {
                self.received_plaintext.extend(plaintext.fragment);
                Ok(())
            }
            ContentType::Handshake => {
                let payload = HandshakePayload::decode(&plaintext.fragment)?;
                self.process_control(payload)
            }
            ContentType::Alert => {
                self.peer_closed = true;
                Ok(())
            }
            _ => Err(Error::UnexpectedMessage("unexpected inner content type")),
        }
    }

    /// Explicitly initiate a rekey by sending a `ConnectionUpdate` (the analog of rustls'
    /// `refresh_traffic_keys`). Inbound handling of the resulting control messages is automatic
    /// inside [`process_new_packets`](Self::process_new_packets).
    pub fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        let crypto = RustCryptoProvider::default();
        let group = self
            .group
            .as_mut()
            .ok_or(Error::UnexpectedMessage("rekey before handshake"))?;
        let two_party = self
            .two_party
            .as_mut()
            .ok_or(Error::UnexpectedMessage("rekey before handshake"))?;
        if let Some((connection_update, rekey)) = two_party.create_connection_update(group, &crypto)?
        {
            self.emit_then_rekey(
                HandshakePayload::ConnectionUpdate(connection_update.update),
                rekey,
            )?;
        }
        Ok(())
    }

    /// Explicitly initiate an in-session resumption (a full re-key-agreement over the live group via
    /// a `ResumptionRequest`). Inbound handling of the response is automatic in
    /// [`process_new_packets`](Self::process_new_packets).
    pub fn initiate_resumption(&mut self) -> Result<(), Error> {
        let group = self
            .group
            .as_mut()
            .ok_or(Error::UnexpectedMessage("resume before handshake"))?;
        let two_party = self
            .two_party
            .as_mut()
            .ok_or(Error::UnexpectedMessage("resume before handshake"))?;
        let request = two_party.create_resumption_request(group)?;
        self.emit_then_rekey(HandshakePayload::ResumptionRequest(request.commit), None)?;
        Ok(())
    }

    /// Snapshot the current group for later cross-connection resumption: persist it to the session
    /// store and return a [`ResumptionState`] that names it.
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

    /// In-band control handling (automatic): dispatch a decoded control message to the two-party
    /// state machine, then emit any reply under the old key and rotate (emit-before-switch).
    fn process_control(&mut self, payload: HandshakePayload) -> Result<(), Error> {
        let crypto = RustCryptoProvider::default();
        match payload {
            HandshakePayload::ConnectionUpdate(update) => {
                let group = self
                    .group
                    .as_mut()
                    .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                let two_party = self
                    .two_party
                    .as_mut()
                    .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                let (rekey, reply) =
                    two_party.handle_connection_update(group, &crypto, ConnectionUpdate { update })?;
                self.emit_reply_then_rekey(reply, rekey)
            }
            HandshakePayload::EpochKeyUpdate(epoch) => {
                let group = self
                    .group
                    .as_mut()
                    .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                let two_party = self
                    .two_party
                    .as_mut()
                    .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                let (rekey, reply) = two_party.handle_epoch_key_update(
                    group,
                    &crypto,
                    EpochKeyUpdate { epoch },
                )?;
                self.emit_reply_then_rekey(reply, rekey)
            }
            HandshakePayload::ResumptionRequest(commit) => {
                // Responder handling an in-session resumption request.
                let group = self
                    .group
                    .as_mut()
                    .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                let two_party = self
                    .two_party
                    .as_mut()
                    .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                let response =
                    two_party.handle_resumption_request(group, ResumptionRequest { commit })?;
                // The group is now at the resumed epoch. Emit the response under the OLD key first,
                // then rebuild both record-layer directions for the new epoch.
                if let Some(resp) = response {
                    self.emit_then_rekey(HandshakePayload::ResumptionResponse(resp.commit), None)?;
                }
                self.rebuild_record_layer()
            }
            HandshakePayload::ResumptionResponse(commit) => {
                // Initiator applying the resumption response.
                let group = self
                    .group
                    .as_mut()
                    .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                let two_party = self
                    .two_party
                    .as_mut()
                    .ok_or(Error::UnexpectedMessage("control before handshake"))?;
                two_party.handle_resumption_response(group, ResumptionResponse { commit })?;
                self.rebuild_record_layer()
            }
            HandshakePayload::ClientHello(_) | HandshakePayload::ServerHello(_) => Err(
                Error::UnexpectedMessage("unexpected hello message in steady state"),
            ),
        }
    }

    /// Rebuild both record-layer directions from the group's current epoch (used after resumption,
    /// which rotates the whole key schedule wholesale rather than one direction at a time).
    fn rebuild_record_layer(&mut self) -> Result<(), Error> {
        let side = self.side;
        let group = self
            .group
            .as_ref()
            .ok_or(Error::UnexpectedMessage("no group to rebuild record layer"))?;
        self.record = Some(create_record_layer(group, side, RustCryptoProvider::default()));
        Ok(())
    }

    /// Emit an optional reply `EpochKeyUpdate` under the old key, then apply the rekey.
    fn emit_reply_then_rekey(
        &mut self,
        reply: Option<EpochKeyUpdate>,
        rekey: Option<DirectionalRekey>,
    ) -> Result<(), Error> {
        match reply {
            Some(eku) => {
                self.emit_then_rekey(HandshakePayload::EpochKeyUpdate(eku.epoch), rekey)
            }
            None => {
                if let Some(rekey) = rekey {
                    self.apply_directional_rekey(rekey)?;
                }
                Ok(())
            }
        }
    }

    /// Encrypt a control message under the CURRENT (old) send key into the outgoing buffer, *then*
    /// rotate the record layer — the emit-before-switch invariant.
    fn emit_then_rekey(
        &mut self,
        payload: HandshakePayload,
        rekey: Option<DirectionalRekey>,
    ) -> Result<(), Error> {
        let bytes = payload.encode()?;
        for r in self
            .record_mut()?
            .encrypt(ContentType::Handshake, &bytes)?
        {
            self.sendable_tls.extend(r);
        }
        if let Some(rekey) = rekey {
            self.apply_directional_rekey(rekey)?;
        }
        Ok(())
    }

    fn apply_directional_rekey(&mut self, rekey: DirectionalRekey) -> Result<(), Error> {
        let side = self.side;
        self.record_mut()?.apply_rekey(rekey, side);
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
        for r in record.encrypt(ContentType::ApplicationData, data)? {
            self.sendable_tls.extend(r);
        }
        Ok(())
    }
}

/// Verify the server's credential per the configured policy (see [`ServerCertVerifier`]).
fn verify_server_credential(
    group: &MlsGroup,
    verifier: &ServerCertVerifier,
    server_name: &ServerName<'_>,
) -> Result<(), Error> {
    match verifier {
        ServerCertVerifier::None => Ok(()),
        ServerCertVerifier::WebPki { trust_anchors } => {
            // The responder created the group, so it is leaf index 0 from the initiator's view.
            let member = group
                .member_at_index(0)
                .ok_or(Error::UnexpectedMessage("responder member missing"))?;
            validate_server_credential(member.signing_identity(), trust_anchors, Some(server_name))?;
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
