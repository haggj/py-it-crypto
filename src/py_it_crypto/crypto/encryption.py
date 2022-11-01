import json
import uuid

from jwcrypto.jwe import JWE

from py_it_crypto.logs.access_log import SignedAccessLog, AccessLog
from py_it_crypto.logs.shared_header import SharedHeader
from py_it_crypto.logs.shared_log import SharedLog
from py_it_crypto.user.remoteUser import RemoteUser


class EncryptionService:

    @staticmethod
    def encrypt(jwsAccessLog: SignedAccessLog, sender, receivers: list[RemoteUser]) -> str:
        share_id = str(uuid.uuid4())

        # Embed signed AccessLog into a SharedLog object and sign the object -> jws_shared_log
        shared_log = SharedLog(log=jwsAccessLog.__dict__, shareId=share_id, creator=sender.id)
        jws_shared_log = sender.sign_data(shared_log.to_bytes())

        # Sender creates and signs the header -> jws_shared_header
        receiver_ids = [receiver.id for receiver in receivers]
        shared_header = SharedHeader(shareId=share_id,
                                     owner=AccessLog.from_signed_log(jwsAccessLog).owner,
                                     receivers=receiver_ids)
        jws_shared_header = sender.sign_data(shared_header.to_bytes())

        # Sender creates the encrypted JWE
        protected = {
            "alg": "ECDH-ES+A256KW",
            "enc": "A256GCM",
            "sharedHeader": json.loads(jws_shared_header)
        }
        jwetoken = JWE(plaintext=jws_shared_log.encode(), protected=protected)

        for receiver in receivers:
            jwetoken.add_recipient(receiver.encryption_certificate)

        return jwetoken.serialize()
