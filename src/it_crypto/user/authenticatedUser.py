from typing import Callable

from jwcrypto import jws
from jwcrypto.common import json_encode
from jwcrypto.jwk import JWK

from crypto.decryption import DecryptionService
from crypto.encryption import EncryptionService
from globals import SIGNING_ALG
from logs.access_log import AccessLog, SignedAccessLog
from user.remoteUser import RemoteUser


class AuthenticatedUser(RemoteUser):
    decryption_key: JWK
    signing_key: JWK

    def __init__(self, id: str, encryption_certificate: JWK, verification_certificate: JWK,
                 decryption_key: JWK, signing_key: JWK):
        super().__init__(id, encryption_certificate, verification_certificate)
        self.decryption_key = decryption_key
        self.signing_key = signing_key

    def encrypt(self, log: SignedAccessLog, receivers: list[RemoteUser]) -> str:
        return EncryptionService.encrypt(jwsAccessLog=log, sender=self, receivers=receivers)

    def decrypt(self, jwe: str, fetch_user: Callable[[str], RemoteUser]) -> SignedAccessLog:
        return DecryptionService.decrypt(jwe=jwe, receiver=self, fetch_user=fetch_user)

    def sign_data(self, data: bytes) -> str:
        token = jws.JWS(data)
        token.add_signature(self.signing_key, None, json_encode({"alg": SIGNING_ALG}))
        return token.serialize()

    def sign_access_log(self, log: AccessLog) -> SignedAccessLog:
        singed = self.sign_data(log.to_bytes())
        return SignedAccessLog.from_json(singed)
