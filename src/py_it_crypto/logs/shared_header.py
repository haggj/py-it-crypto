from py_it_crypto.logs.serializable import Serializable


class SharedHeader(Serializable):
    def __init__(self, shareId: str, owner: str, receivers: list[str]):
        self.shareId = shareId
        self.owner = owner
        self.receivers = receivers
