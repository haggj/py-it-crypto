from py_it_crypto.logs.serializable import Serializable
from py_it_crypto.utils import b64decode


class AccessLog(Serializable):
    """
    Represents a raw AccessLog, which is not signed by a monitor.
    """
    def __init__(self, monitor: str, owner: str, tool: str, justification: str, timestamp: int,
                 accessKind: str,
                 dataType: list[str]):
        self.monitor = monitor
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
    def from_signed_log(log) -> 'AccessLog':
        data = b64decode(log.payload)
        return AccessLog.from_json(data.decode())