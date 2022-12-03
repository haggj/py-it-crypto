from typing import Callable

from jwcrypto import jws
from jwcrypto.common import json_encode
from jwcrypto.jwk import JWK

from py_it_crypto.crypto.decryption import DecryptionService
from py_it_crypto.crypto.encryption import EncryptionService
from py_it_crypto.globals import SIGNING_ALG
from py_it_crypto.logs.access_log import AccessLog
from py_it_crypto.logs.signed_log import SignedLog
from py_it_crypto.user.remoteUser import RemoteUser


class AuthenticatedUser(RemoteUser):
    """
    Represents an authenticated user, which has access to all private and public keys.
    Thus, this user has all capabilities of a RemoteUser.
    This user is additionally able to:
    - sign data using its signing_key
    - decrypt data using its decryption_key
    """
    decryption_key: JWK
    signing_key: JWK

    def __init__(self, id: str, encryption_certificate: JWK, verification_certificate: JWK,
                 decryption_key: JWK, signing_key: JWK):
        super().__init__(id, encryption_certificate, verification_certificate)
        self.decryption_key = decryption_key
        self.signing_key = signing_key

    def encrypt_log(self, log: SignedLog, receivers: list[RemoteUser]) -> str:
        """
        Encrypt a SignedLog for the given set of receivers.
        :param log:  A signed access log object which needs to be encrypted.
        :param receivers:  List of receivers which can decrypt the cipher.
        :return: Returns the JWE token encoded as string.
        """
        return EncryptionService.encrypt(jwsSingedLog=log, sender=self, receivers=receivers)

    def decrypt_log(self, jwe: str, fetch_user: Callable[[str], RemoteUser]) -> SignedLog:
        """
        Decrypt a given JWE token.
        :param jwe: The JWE token to decrypt.
        :param fetch_user: A function which maps the ID of a user to a RemoteUser object.
        :return: Returns the decrypted SignedLog object.
        """
        return DecryptionService.decrypt(jwe=jwe, receiver=self, fetch_user=fetch_user)

    def sign_data(self, data: bytes) -> str:
        """
        Cryptographically sign the provided data.
        :param data: The data which needs to be signed.
        :return: Returns the signed data as string-encoded JWS token.
        """
        token = jws.JWS(data)
        token.add_signature(self.signing_key, None, json_encode({"alg": SIGNING_ALG}))
        return token.serialize()

    def sign_log(self, log: AccessLog) -> SignedLog:
        """
        Cryptographically sign a raw AccessLog object.
        :param log: The AccessLog to sign.
        :return: Returns the signed AccessLog.
        """
        singed = self.sign_data(log.to_bytes())
        return SignedLog.from_json(singed)
