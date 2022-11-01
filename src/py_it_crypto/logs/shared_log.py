from py_it_crypto.logs.serializable import Serializable


class SharedLog(Serializable):
    def __init__(self, log: dict, shareId: str, creator: str):
        self.log = log
        self.shareId = shareId
        self.creator = creator
