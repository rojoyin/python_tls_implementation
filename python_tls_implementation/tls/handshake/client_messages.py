from typing import Type

from python_tls_implementation.tls.handshake.extensions.base import Extension
from python_tls_implementation.tls.handshake.messages import HandshakeMessage, T, HandshakeType
from python_tls_implementation.tls.record import ProtocolVersion


class ClientHello(HandshakeMessage):
    legacy_version: ProtocolVersion = ProtocolVersion.TLS_1_2
    random_value: bytes
    legacy_session_id: bytes = b''
    cipher_suites: list[int]
    legacy_compression_methods: list[int] = [0]
    extensions: list[Extension] = []

    def __init__(self):
        super().__init__()
        self.msg_type = HandshakeType.client_hello

    def _body_bytes(self) -> bytes:
        pass

    @classmethod
    def parse(cls: Type[T], body: bytes) -> T:
        pass
