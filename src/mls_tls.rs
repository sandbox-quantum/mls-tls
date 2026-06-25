

// https://www.ietf.org/archive/id/draft-kohbrok-mls-tls-00.html


// > 6. Deriving keys for record layer protection
// > Both after the initial key agreement phase and the resumption phase, initiator and responder derive key material from the MLS group created during the initial key agreement phase.
// > 
// > The client_application_traffic_secret and the server_application_traffic_secret required by the record layer are derived as follows.
// > 
// > server_application_traffic_secret =
// >   MLS-Exporter("MLS-TLS s ap traffic", [], Length)
// > 
// > client_application_traffic_secret =
// >   MLS-Exporter("MLS-TLS c ap traffic", [], Length)
// > 
// > Where MLS-Exporter is defined in [RFC9420] and Length is the size of the secret required by the TLS record layer.

use mls_rs::{Group, client_builder::MlsConfig};

pub(crate) fn deriving_keys_for_record_layer_protection_server(client_group: &Group<impl MlsConfig>) {
    client_group.export_secret(label, context, len)
}