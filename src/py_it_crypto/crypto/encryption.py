
from jwcrypto.jwe import JWE
from py_it_crypto.globals import KEY_WRAP_ALG, ENCRYPTION_ALG

from py_it_crypto.logs.access_log import AccessLog
from py_it_crypto.logs.signed_log import SignedLog
from py_it_crypto.logs.shared_log import SharedLog
from py_it_crypto.user.remoteUser import RemoteUser


class EncryptionService:

    @staticmethod
    def encrypt(jwsSingedLog: SignedLog, sender, receivers: list[RemoteUser]) -> str:
        """
        Encrypts a given SingedLog for the specified set of receivers in the name of the passed sender.
        This function might be used either by a monitor (which initially encrypts the log for the owner)
        or by the owner (which wants to share the AccessLog with others).
        The provided SingedLog is assumed to be signed by a monitor.
        :param jwsSingedLog: The SingedLog which needs to be encrypted.
        :param sender: The user which encrypts the data.
        :param receivers: The set of receivers the data is encrypted for.
        :return: The encrypted JWE token encoded as string.
        """

        receiver_ids = [receiver.id for receiver in receivers]

        # Embed signed AccessLog into a SharedLog object and sign the object -> jws_shared_log
        shared_log = SharedLog(log=jwsSingedLog.__dict__, recipients=receiver_ids, creator=sender.id)
        jws_shared_log = sender.sign_data(shared_log.to_bytes())

        # Sender creates the encrypted JWE
        protected = {
            "alg": KEY_WRAP_ALG,
            "enc": ENCRYPTION_ALG,
            "recipients": receiver_ids,
            "owner": AccessLog.from_signed_log(jwsSingedLog).owner
        }
        jwetoken = JWE(plaintext=jws_shared_log.encode(), protected=protected)

        for receiver in receivers:
            jwetoken.add_recipient(receiver.encryption_certificate)

        return jwetoken.serialize()
