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
    @classmethod
    def validate_fragment(cls, v: bytes) -> bytes:
        if len(v) > cls.MAX_FRAGMENT_LENGTH:
            raise ValueError(f"Fragment length must be less than {cls.MAX_FRAGMENT_LENGTH} bytes")
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

class TLSInnerPlaintext(BaseModel):
    content: bytes = b''
    type: ContentType
    zeros_padding_length: int = 0

    @field_validator('zeros_padding_length')
    @classmethod
    def validate_zeros_padding_length(cls, v):
        if v<0:
            raise ValueError("Padding length cannot be negative")
        return v

    @classmethod
    def from_bytes(cls, data: bytes) -> TLSInnerPlaintext:
        if not data:
            raise ValueError("Empty data provided to TLSInnerPlaintext.from_bytes")

        for i in range(len(data)-1, -1, -1):
            if (content_type_byte := data[i]) != 0:
                try:
                    content_type = ContentType(content_type_byte)
                    content = data[:i]
                    zeros_padding_length = len(data[i+1:])
                    return cls(
                        content=content,
                        type=content_type,
                        zeros_padding_length=zeros_padding_length
                    )
                except ValueError:
                    continue

        raise ValueError("Invalid TLSInnerPlaintext: no content type found")

    def to_bytes(self) -> bytes:
        return (
            self.content +
            bytes([self.type.value]) +
            bytes([0] * self.zeros_padding_length)
        )

    class Config:
        arbitrary_types_allowed = True
