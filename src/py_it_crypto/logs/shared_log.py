from typing import List

from py_it_crypto.logs.serializable import Serializable


class SharedLog(Serializable):
    def __init__(self, log: dict, recipients: List[str], creator: str):
        self.log = log
        self.recipients = recipients
        self.creator = creator
