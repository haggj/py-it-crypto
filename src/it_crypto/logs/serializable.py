import json

class Serializable:

    @classmethod
    def from_bytes(cls, data: bytes) -> object:
        return cls.from_json(data.decode())

    @classmethod
    def from_json(cls, data: str) -> object:
        return cls(**json.loads(data))

    def to_json(self) -> str:
        return json.dumps(self, default=vars, separators=(',', ':'))

    def to_bytes(self) -> bytes:
        return self.to_json().encode()