import json
from typing import TypeVar, Type

Self = TypeVar("Self", bound="Serializable")


class Serializable:

    @classmethod
    def from_bytes(cls, data: bytes) -> object:
        return cls.from_json(data.decode())

    @classmethod
    def from_json(cls: Type[Self], data: str) -> Self:
        return cls(**json.loads(data))

    def to_json(self) -> str:
        return json.dumps(self, default=vars, separators=(',', ':'))

    def to_bytes(self) -> bytes:
        return self.to_json().encode()

    def __str__(self):
        return str(self.__class__) + json.dumps(self, default=vars, indent=4)
