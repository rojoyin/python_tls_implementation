from typing import Type

from python_tls_implementation.tls.handshake.messages import HandshakeMessage, T


class ServerHello(HandshakeMessage):
    def _body_bytes(self) -> bytes:
        pass

    @classmethod
    def parse(cls: Type[T], body: bytes) -> T:
        pass
