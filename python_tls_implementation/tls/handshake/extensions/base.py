from __future__ import annotations

from enum import IntEnum
from typing import ClassVar, Type, Any

from pydantic import BaseModel


class ExtensionType(IntEnum):
    server_name = 0
    max_fragment_length = 1
    status_request = 5
    supported_groups = 10
    signature_algorithms = 13
    use_srtp = 14
    heartbeat = 15
    application_layer_protocol_negotiation = 16
    signed_certificate_timestamp = 18
    client_certificate_type = 19
    server_certificate_type = 20
    padding = 21
    pre_shared_key = 41
    early_data = 42
    supported_versions = 43
    cookie = 44
    psk_key_exchange_modes = 45
    certificate_authorities = 47
    oid_filters = 48
    post_handshake_auth = 49
    signature_algorithms_cert = 50
    key_share = 51

class ExtensionRegistry:
    _handlers: dict[ExtensionType, Type[Extension]] = {}

    @classmethod
    def register(cls, extension_type: ExtensionType, handler_class: Type[Extension]) -> None:
        if not issubclass(handler_class, Extension):
            raise TypeError(f"Handler must be a subclass of Extension, got {handler_class}")
        cls._handlers[extension_type] = handler_class

    @classmethod
    def get_handler(cls, extension_type: ExtensionType) -> Type[Extension] | None:
        return cls._handlers.get(extension_type)

    @classmethod
    def parse(cls, data: bytes) -> tuple[Extension | None, bytes]:
        if len(data) < 4:
            return None, data

        extension_type = ExtensionType(int.from_bytes(data[0:2], byteorder='big'))
        length = int.from_bytes(data[2:4], byteorder='big')

        if len(data) < 4 + length:
            return None, data

        extension_data = data[4:4 + length]
        remaining_data = data[4 + length:]

        handler_class = cls.get_handler(extension_type)
        if handler_class is None:
            extension = Extension(extension_type=extension_type, data=extension_data)
            return extension, remaining_data

        extension = handler_class.parse_from_bytes(extension_data)
        return extension, remaining_data


class Extension(BaseModel):
    extension_type: ExtensionType
    data: bytes | None = None
    extension_type_value: ClassVar[ExtensionType] = None

    class Config:
        arbitrary_types_allowed = True

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.extension_type_value is not None:
            ExtensionRegistry.register(cls.extension_type_value, cls)

    def to_bytes(self) -> bytes:
        if hasattr(self, '_extension_bytes'):
            extension_data = self._extension_bytes()
        else:
            extension_data = self.data or b''

        extension_type_bytes = int(self.extension_type).to_bytes(2, byteorder='big')
        length_bytes = len(extension_data).to_bytes(2, byteorder='big')

        return extension_type_bytes + length_bytes + extension_data

    @classmethod
    def parse_from_bytes(cls, data: bytes) -> Extension:
        return cls(extension_type=cls.extension_type_value, data=data)

    def _extension_bytes(self) -> bytes:
        return self.data or b''
