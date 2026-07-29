"""Argument validation and the exception hierarchy.

The Rust config builders are typestate: they make an incomplete or contradictory configuration a
compile error. Python has no equivalent, so the same conditions have to be caught as `ValueError`
at construction — these tests are what keeps that mapping honest.
"""

from __future__ import annotations

import pytest

import mls_tls
from _helpers import drive

ALL_SUITES = [
    mls_tls.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519,
    mls_tls.MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    mls_tls.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519,
    mls_tls.MLS_256_DHKEMX448_AES256GCM_SHA512_ED448,
    mls_tls.MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    mls_tls.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448,
    mls_tls.MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    mls_tls.MLS_256_XWING_AES256GCM_SHA512_P384,
]


# -- exception hierarchy ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "subclass",
    [
        mls_tls.WantReadError,
        mls_tls.WantWriteError,
        mls_tls.CertificateError,
        mls_tls.HandshakeError,
        mls_tls.UnsupportedError,
        mls_tls.RaggedEOF,
    ],
)
def test_every_error_is_catchable_as_the_base(subclass):
    assert issubclass(subclass, mls_tls.MLSTLSError)
    assert issubclass(mls_tls.MLSTLSError, Exception)


# -- credential validation -------------------------------------------------------------------


def test_no_credential_is_rejected():
    with pytest.raises(ValueError, match="credential is required"):
        mls_tls.ClientConfig(verify=False)


def test_two_credentials_are_rejected():
    with pytest.raises(ValueError, match="not both"):
        mls_tls.ClientConfig(
            basic_credential=b"alice", cert_chain=[b"\x30\x00"], verify=False
        )


def test_cert_chain_without_private_key_is_rejected():
    with pytest.raises(ValueError, match="requires private_key"):
        mls_tls.ClientConfig(cert_chain=[b"\x30\x00"], verify=False)


def test_empty_cert_chain_is_rejected():
    with pytest.raises(ValueError, match="must not be empty"):
        mls_tls.ClientConfig(cert_chain=[], private_key=b"\x00" * 32, verify=False)


@pytest.mark.parametrize(
    "bad_key",
    [
        pytest.param(b"-----BEGIN PRIVATE KEY-----", id="pem"),
        pytest.param(b"", id="empty"),
        pytest.param(b"\x00" * 10, id="too-short"),
        pytest.param(b"\xff" * 200, id="too-long"),
        # RustCrypto's P-384 accepts a short left-padded scalar, so a truncated key file would
        # otherwise be taken as a valid — and very weak — identity rather than reported.
        pytest.param(b"\x11" * 27, id="truncated-but-parseable"),
    ],
)
def test_malformed_private_key_names_the_expected_encoding(bad_key):
    """The raw encoding is scheme-specific, so the error has to say what was expected."""
    with pytest.raises(ValueError, match="not PKCS#8 or PEM"):
        mls_tls.ClientConfig(
            basic_credential=b"alice", private_key=bad_key, verify=False
        )


def test_public_key_mismatch_is_rejected():
    suite = mls_tls.DEFAULT_CIPHER_SUITE
    private, public = mls_tls.generate_signature_key(suite)
    _, other_public = mls_tls.generate_signature_key(suite)
    assert public != other_public

    with pytest.raises(ValueError, match="does not match private_key"):
        mls_tls.ClientConfig(
            basic_credential=b"alice",
            private_key=private,
            public_key=other_public,
            verify=False,
        )


def test_supplied_keypair_is_used_verbatim():
    private, public = mls_tls.generate_signature_key(mls_tls.DEFAULT_CIPHER_SUITE)
    config = mls_tls.ClientConfig(
        basic_credential=b"alice", private_key=private, public_key=public, verify=False
    )
    assert config.public_key == public


# -- verifier validation ---------------------------------------------------------------------


def test_roots_with_verification_off_is_rejected():
    """Silently ignoring the roots would look like verification was happening."""
    with pytest.raises(ValueError, match="meaningless with verify=False"):
        mls_tls.ClientConfig(
            basic_credential=b"alice", root_certificates=[b"\x30\x00"], verify=False
        )


def test_basic_credential_peer_needs_verification_off(server_config):
    """A Basic server credential has no chain, so the default verifier must reject it."""
    verifying = mls_tls.ClientConfig(basic_credential=b"client")  # verify=True by default
    client = mls_tls.ClientConnection(verifying, "localhost")
    server = mls_tls.ServerConnection(server_config)

    with pytest.raises(mls_tls.CertificateError):
        drive(client, server)


# -- cipher suites ---------------------------------------------------------------------------


def test_unsupported_suite_is_rejected():
    """Every registry suite this build cannot serve must fail at config construction."""
    unsupported = [s for s in ALL_SUITES if s not in mls_tls.SUPPORTED_CIPHER_SUITES]
    if not unsupported:
        pytest.skip(f"the {mls_tls.BACKEND} backend serves every suite in the table")

    for suite in unsupported:
        with pytest.raises(mls_tls.UnsupportedError):
            mls_tls.ClientConfig(
                basic_credential=b"alice", verify=False, cipher_suite=suite
            )


def test_xwing_availability_tracks_the_backend():
    """X-Wing has no byte-compatible OpenSSL path, so it exists only under rustcrypto."""
    xwing = mls_tls.MLS_256_XWING_AES256GCM_SHA512_P384
    if mls_tls.BACKEND == "rustcrypto":
        assert xwing in mls_tls.SUPPORTED_CIPHER_SUITES
        assert mls_tls.DEFAULT_CIPHER_SUITE == xwing
    else:
        assert xwing not in mls_tls.SUPPORTED_CIPHER_SUITES


def test_every_supported_suite_completes_a_handshake():
    for suite in mls_tls.SUPPORTED_CIPHER_SUITES:
        client_config = mls_tls.ClientConfig(
            basic_credential=b"client", verify=False, cipher_suite=suite
        )
        server_config = mls_tls.ServerConfig(
            basic_credential=b"server", cipher_suite=suite
        )
        client = mls_tls.ClientConnection(client_config, "localhost")
        server = mls_tls.ServerConnection(server_config)
        drive(client, server)
        assert not client.is_handshaking(), f"suite 0x{suite:04x} did not complete"
        assert client.cipher() == suite


def test_cipher_suite_name_round_trip():
    for suite in mls_tls.SUPPORTED_CIPHER_SUITES:
        name = mls_tls.cipher_suite_name(suite)
        assert name is not None
        assert getattr(mls_tls, name) == suite
    assert mls_tls.cipher_suite_name(0xFFFF) is None


# -- connection-level errors -------------------------------------------------------------------


def test_invalid_server_hostname(client_config):
    with pytest.raises(ValueError, match="not a valid server name"):
        mls_tls.ClientConnection(client_config, "not a hostname!")


def test_write_before_handshake_is_an_error(client_config):
    """Unlike rustls, plaintext is not buffered before the record layer exists."""
    client = mls_tls.ClientConnection(client_config, "localhost")
    with pytest.raises(mls_tls.HandshakeError):
        client.write(b"too early")


def test_close_notify_before_handshake_is_an_error(client_config):
    client = mls_tls.ClientConnection(client_config, "localhost")
    with pytest.raises(mls_tls.HandshakeError):
        client.send_close_notify()


def test_session_before_handshake_is_an_error(client_config):
    client = mls_tls.ClientConnection(client_config, "localhost")
    with pytest.raises(mls_tls.HandshakeError):
        client.session()


def test_getpeercert_requires_binary_form(established):
    client, _ = established
    with pytest.raises(ValueError, match="binary_form=True"):
        client.getpeercert()


def test_garbage_on_the_wire_is_a_handshake_error(client_config, server_config):
    server = mls_tls.ServerConnection(server_config)
    server.read_tls(b"\x00\x01\x02\x03\x04\x05\x06\x07")
    with pytest.raises(mls_tls.HandshakeError):
        server.process_new_packets()


def test_error_messages_carry_the_cause(client_config, server_config):
    """The crate's top-level messages are terse; the exception should show the chain."""
    server = mls_tls.ServerConnection(server_config)
    server.read_tls(b"\xff" * 8)
    with pytest.raises(mls_tls.HandshakeError) as caught:
        server.process_new_packets()
    # "malformed wire message: <what exactly>" rather than a bare category.
    assert ":" in str(caught.value)
    assert len(str(caught.value)) > 20
