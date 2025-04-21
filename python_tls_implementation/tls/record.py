from enum import Enum

class ContentType(Enum):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23

class ProtocolVersion(Enum):
    TLS_1_0 = (3, 1)
    TLS_1_1 = (3, 2)
    TLS_1_2 = (3, 3)
    TLS_1_3 = (3, 4)

    @classmethod
    def to_bytes(cls, version):
        """Convert version tuple to bytes."""
        return bytes(version)
