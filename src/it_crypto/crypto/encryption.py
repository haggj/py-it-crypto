import base64
import json
import uuid

from jwcrypto.jwe import JWE

from logs.access_log import SignedAccessLog, AccessLog
from logs.shared_header import SharedHeader
from logs.shared_log import SharedLog
from user.remoteUser import RemoteUser


class EncryptionService:

    @staticmethod
    def encrypt(jwsAccessLog: SignedAccessLog, sender, receivers: list[RemoteUser]):
        share_id = str(uuid.uuid4())

        shared_log = SharedLog(log=jwsAccessLog, share_id=share_id, creator=sender.id)
        jws_shared_log = sender.sign_data(shared_log.to_bytes())

        receiver_ids = [receiver.id for receiver in receivers]
        shared_header = SharedHeader(share_id=share_id,
                                     owner=AccessLog.from_signed_log(jwsAccessLog).owner,
                                     receivers=receiver_ids)
        jws_shared_header = sender.sign_data(shared_header.to_bytes())

        protected = {
            "alg": "ECDH-ES+A256KW",
            "enc": "A256GCM",
            "sharedHeader": json.loads(jws_shared_header)
        }
        jwetoken = JWE(plaintext=jws_shared_log.encode(),protected=protected)

        for receiver in receivers:
             jwetoken.add_recipient(receiver.encryption_certificate)
             jwetoken.add_recipient(receiver.encryption_certificate)

        return jwetoken.serialize()
