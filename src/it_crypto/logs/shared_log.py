import json

from logs.access_log import SignedAccessLog
from logs.serializable import Serializable


class SharedLog(Serializable):
    def __init__(self, log: SignedAccessLog, share_id: str, creator: str):
        self.log = log
        self.share_id = share_id
        self.creator = creator

    @classmethod
    def from_json(cls, data: str) -> object:
        dic = json.loads(data)
        dic["log"] = SignedAccessLog.from_json(dic["log"])
        return cls(**dic)

    def to_json(self) -> str:
        dic = {
            "log": vars(self.log),
            "shareId": self.share_id,
            "creator": self.creator
        }
        return json.dumps(dic, separators=(',', ':'))
