from __future__ import annotations

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

    def to_bytes(self) -> bytes:
        ...

    @abstractmethod
    def _body_bytes(self) -> bytes:
        ...

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple[HandshakeMessage, bytes]:
        ...

    @classmethod
    @abstractmethod
    def parse(cls: Type[T], body: bytes) -> T:
        ...
