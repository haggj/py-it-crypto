import base64

from logs.serializable import Serializable




class AccessLog(Serializable):
    def __init__(self, monitor: str, owner: str, tool: str, justification: str, timestamp: int, accessKind: str,
                 dataType: list[str]):
        self.monitor = monitor,
        self.owner = owner
        self.tool = tool
        self.justification = justification
        self.timestamp = timestamp
        self.accessKind = accessKind
        self.dataType = dataType

    @staticmethod
    def generate():
        return AccessLog("monitor", "owner", "tool", "just", 1234, "kind", ["data", "datat more"])

    @staticmethod
    def from_signed_log(log: 'SignedAccessLog'):
        data = base64.b64decode(log.payload.encode() + b"==")
        return AccessLog.from_json(data)


class SignedAccessLog(Serializable):
    def __init__(self, payload: str, protected: str, signature: str):
        self.payload = payload
        self.protected = protected
        self.signature = signature
