from py_it_crypto.logs.access_log import AccessLog
from py_it_crypto.logs.serializable import Serializable


class SignedLog(Serializable):
    """
    Represents a singed log. A log must always be singed by a monitor.
    """
    def __init__(self, payload: str, protected: str, signature: str):
        self.payload = payload
        self.protected = protected
        self.signature = signature

    def extract(self) -> AccessLog:
        return AccessLog.from_signed_log(self)