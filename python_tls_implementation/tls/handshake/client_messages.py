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
        version_bytes = self.legacy_version.value.to_bytes(2, byteorder='big')
        session_id_bytes = bytes([len(self.legacy_session_id)]) + self.legacy_session_id
        cipher_suites_bytes = b''.join(cs.to_bytes(2, byteorder='big') for cs in self.cipher_suites)
        cipher_suites_bytes = len(cipher_suites_bytes).to_bytes(2, byteorder='big') + cipher_suites_bytes
        compression_bytes = bytes([len(self.legacy_compression_methods)]) + bytes(self.legacy_compression_methods)

        extensions_bytes = b''
        if self.extensions:
            all_ext_bytes = b''.join(ext.to_bytes() for ext in self.extensions)
            extensions_bytes = len(all_ext_bytes).to_bytes(2, byteorder='big') + all_ext_bytes
        else:
            extensions_bytes = (0).to_bytes(2, byteorder='big')

        return version_bytes + self.random_value + session_id_bytes + cipher_suites_bytes + compression_bytes + extensions_bytes

    @classmethod
    def parse(cls: Type[T], body: bytes) -> T:
        pass
