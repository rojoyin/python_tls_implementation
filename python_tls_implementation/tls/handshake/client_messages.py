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
        if len(body) < 38:
            raise ValueError("ClientHello message too short")

        offset = 0
        legacy_version = ProtocolVersion(int.from_bytes(body[offset:offset + 2], byteorder='big'))
        offset += 2
        random_value = body[offset:offset + 32]
        offset += 32
        session_id_len = body[offset]
        offset += 1
        legacy_session_id = body[offset:offset + session_id_len]
        offset += session_id_len
        cipher_suites_len = int.from_bytes(body[offset:offset + 2], byteorder='big')
        offset += 2

        if cipher_suites_len % 2 != 0:
            raise ValueError("Cipher suites length must be even")

        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            if offset + i + 1 >= len(body):
                raise ValueError("Message truncated in cipher suites")
            cipher_suite = int.from_bytes(body[offset:offset + 2], byteorder='big')
            cipher_suites.append(cipher_suite)

        offset += cipher_suites_len
        compression_len = body[offset]
        offset += 1
        compression_methods = list(body[offset:offset + compression_len])
        offset += compression_len

        extensions = []
        if offset < len(body):
            extensions_len = int.from_bytes(body[offset:offset + 2], byteorder='big')
            offset += 2

            extensions_end = offset + extensions_len
            while offset < extensions_end:
                from python_tls_implementation.tls.handshake.extensions.base import ExtensionRegistry
                extension, remaining = ExtensionRegistry.parse(body[offset:extensions_end])
                if extension is None:
                    break
                extensions.append(extension)
                offset = extensions_end - len(remaining)

        client_hello = cls()
        client_hello.legacy_version = legacy_version
        client_hello.random_value = random_value
        client_hello.legacy_session_id = legacy_session_id
        client_hello.cipher_suites = cipher_suites
        client_hello.legacy_compression_methods = compression_methods
        client_hello.extensions = extensions

        return client_hello
