from typing import List

from py_it_crypto.logs.serializable import Serializable


class SharedLog(Serializable):
    """
    Represents a shared log. It contains a nested log (which is singed by a monitor) and information
    about the creator and intended receivers.
    A json-encoded SharedLog is encrypted within a JWE token.
    """
    def __init__(self, log: dict, recipients: List[str], creator: str):
        self.log = log
        self.recipients = recipients
        self.creator = creator
