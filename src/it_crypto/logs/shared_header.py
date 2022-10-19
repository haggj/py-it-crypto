from logs.serializable import Serializable


class SharedHeader(Serializable):
    def __init__(self, share_id: str, owner: str, receivers: list[str]):
        self.shareId = share_id
        self.owner = owner
        self.receivers = receivers