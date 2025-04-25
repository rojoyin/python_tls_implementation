from __future__ import annotations

import struct
from abc import ABC, abstractmethod
from collections import defaultdict
from enum import Enum
from typing import Type, TypeVar

from pydantic import BaseModel


# Implementation based on RFC8446
#https://datatracker.ietf.org/doc/html/rfc8446#page-24

class HandshakeType(Enum):
    client_hello = 1
    server_hello = 2
    new_session_ticket = 4
    end_of_early_data = 5
    encrypted_extensions = 8
    certificate = 11
    certificate_request = 13
    certificate_verify = 15
    finished = 20
    key_update = 24
    message_hash = 254

T = TypeVar('T', bound="HandshakeMessage")

class HandshakeMessage(BaseModel, ABC):
    msg_type: HandshakeType
    _subclass_registry: dict[HandshakeType, Type[HandshakeMessage]] = defaultdict(lambda: None)

    def to_bytes(self) -> bytes:
        body = self._body_bytes()
        length_bytes = struct.pack('!I', len(body))[1:]
        headers = bytes([self.msg_type.value]) + length_bytes
        return headers + body

    @abstractmethod
    def _body_bytes(self) -> bytes:
        ...

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple[HandshakeMessage, bytes]:
        if len(data) < 5:
            raise ValueError("Data too short for handshake message header")
        try:
            parsed_message_type = HandshakeType(data[0])
        except ValueError:
            raise ValueError(f"Invalid handshake message type: {data[0]}")

        parsed_message_length = struct.unpack(
            '!I',
            b"\x00" # Add 0x00 because in the format used to decode ('I' = unsigned int) the data must be 4-bytes long
            + data[1:4])[0]

        if len(data) < 5+parsed_message_length:
            raise ValueError(f"Incomplete handshake message: expected {parsed_message_length} bytes, got {len(data) - 5}")

        payload = data[4:4+parsed_message_length]
        remainder = data[4+parsed_message_length:]

        if (specific_subclass := cls._subclass_registry[parsed_message_type]) is None:
            raise ValueError(f"Unknown handshake message type: {parsed_message_type}")

        return specific_subclass.parse(payload), remainder


    @classmethod
    @abstractmethod
    def parse(cls: Type[T], body: bytes) -> T:
        ...
