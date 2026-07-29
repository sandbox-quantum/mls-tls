"""Fixtures shared across the suite. The loopback pump itself lives in `_helpers`."""

from __future__ import annotations

import pytest

import mls_tls
from _helpers import drive


@pytest.fixture
def client_config() -> mls_tls.ClientConfig:
    """A client using a Basic credential, which has no chain to verify."""
    return mls_tls.ClientConfig(basic_credential=b"client", verify=False)


@pytest.fixture
def server_config() -> mls_tls.ServerConfig:
    return mls_tls.ServerConfig(basic_credential=b"server")


@pytest.fixture
def established(client_config, server_config):
    """An established client/server pair, handshake already complete."""
    client = mls_tls.ClientConnection(client_config, "localhost")
    server = mls_tls.ServerConnection(server_config)
    drive(client, server)
    assert not client.is_handshaking(), "client still handshaking"
    assert not server.is_handshaking(), "server still handshaking"
    return client, server
