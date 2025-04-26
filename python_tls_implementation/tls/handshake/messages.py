from __future__ import annotations

import struct
from abc import ABC, abstractmethod
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

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        HandshakeMessageRegistry.register_class(cls)


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
        specific_subclass = HandshakeMessageRegistry.get_handler(parsed_message_type)
        return specific_subclass.parse(payload), remainder

    @classmethod
    @abstractmethod
    def parse(cls: Type[T], body: bytes) -> T:
        ...

    class Config:
        arbitrary_types_allowed = True


class HandshakeMessageRegistry:
    _message_registry: dict[HandshakeType, Type[HandshakeMessage]] = {}

    @classmethod
    def register_class(cls, handler_class: Type[HandshakeMessage], message_type: HandshakeType | None = None) -> None:
        if not issubclass(handler_class, HandshakeMessage):
            raise TypeError(f"Handler must be a subclass of HandshakeMessage, got {handler_class}")
        if hasattr(handler_class, "msg_type"):
            cls._message_registry[handler_class.msg_type] = handler_class
        else:
            if not message_type:
                raise ValueError("Message type was not provided")
            cls._message_registry[message_type] = handler_class

    @classmethod
    def get_handler(cls, message_type: HandshakeType) -> Type[HandshakeMessage]:
        handler = cls._message_registry.get(message_type)
        if handler is None:
            raise ValueError(f"No handler registered for message type: {message_type}")
        return handler
