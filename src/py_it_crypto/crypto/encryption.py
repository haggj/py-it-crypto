
from jwcrypto.jwe import JWE

from py_it_crypto.logs.access_log import SignedAccessLog, AccessLog
from py_it_crypto.logs.shared_log import SharedLog
from py_it_crypto.user.remoteUser import RemoteUser


class EncryptionService:

    @staticmethod
    def encrypt(jwsAccessLog: SignedAccessLog, sender, receivers: list[RemoteUser]) -> str:

        receiver_ids = [receiver.id for receiver in receivers]

        # Embed signed AccessLog into a SharedLog object and sign the object -> jws_shared_log
        shared_log = SharedLog(log=jwsAccessLog.__dict__, recipients=receiver_ids, creator=sender.id)
        jws_shared_log = sender.sign_data(shared_log.to_bytes())

        # Sender creates the encrypted JWE
        protected = {
            "alg": "ECDH-ES+A256KW",
            "enc": "A256GCM",
            "recipients": receiver_ids,
            "owner": AccessLog.from_signed_log(jwsAccessLog).owner
        }
        jwetoken = JWE(plaintext=jws_shared_log.encode(), protected=protected)

        for receiver in receivers:
            jwetoken.add_recipient(receiver.encryption_certificate)

        return jwetoken.serialize()
