from __future__ import annotations

import struct
from enum import Enum

from pydantic import BaseModel, field_validator


# Implementation based on RFC8446
# https://datatracker.ietf.org/doc/html/rfc8446#page-77

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
    def to_bytes(cls, version: tuple[int, int]) -> bytes:
        """Convert version tuple to bytes."""
        return bytes(version)

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple[int, int] | None:
        if len(data)<2:
            return None

        return data[0], data[1]

class TLSPlaintext(BaseModel):
    type: ContentType
    legacy_record_version: ProtocolVersion = ProtocolVersion.TLS_1_2
    fragment: bytes = b''

    @property
    def length(self) -> int:
        return len(self.fragment)

    MAX_FRAGMENT_LENGTH: int = 2**14

    @field_validator('fragment')
    def validate_fragment(self, v: bytes) -> bytes:
        if len(v) > self.MAX_FRAGMENT_LENGTH:
            raise ValueError(f"Fragment length must be less than {self.MAX_FRAGMENT_LENGTH} bytes")
        return v

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple[TLSPlaintext, bytes]:
        # data =
        # bytes(
        # content_type, [0]
        # version_1, version_2, [1, 2]
        # length_1, length_2, [3, 4]
        # fragment... [5, 5 + length]
        # )
        if len(data)<5:
            raise ValueError("Data too short for TLS record header")

        content_type = ContentType(data[0])
        version_tuple = (data[1], data[2])
        version = ProtocolVersion(version_tuple)
        length_byte = data[3:5]
        length = struct.unpack("!H",length_byte)[0]

        if len(data) < 5 + length:
            raise ValueError(f"Incomplete TLS record: expected {length} bytes, got {len(data) - 5}")

        fragment = data[5:5+length]
        remainder = data[5+length:]
        return cls(
            type=content_type,
            legacy_record_version=version,
            fragment=fragment,
        ), remainder

    def to_bytes(self) -> bytes:
        return (
                bytes([self.type.value]) +
                ProtocolVersion.to_bytes(self.legacy_record_version.value) +
                struct.pack("!H",self.length) +
                self.fragment
        )

    class Config:
        arbitrary_types_allowed = True
