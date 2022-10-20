import uuid
from typing import Callable

from jwcrypto import jws
from jwcrypto.common import json_encode, json_decode
from jwcrypto.jwk import JWK

from crypto.decryption import DecryptionService
from crypto.encryption import EncryptionService
from globals import SIGNING_ALG
from logs.access_log import AccessLog, SignedAccessLog
from user.remoteUser import RemoteUser


class AuthenticatedUser(RemoteUser):
    decryption_key: JWK
    signing_key: JWK

    def __init__(self,
                 id: str,
                 encryption_certificate: JWK,
                 verification_certificate: JWK,
                 decryption_key: JWK,
                 signing_key: JWK):
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

    @staticmethod
    def from_pem(id: str,
                 encryption_certificate: str,
                 verification_certificate: str,
                 decryption_key: str,
                 signing_key: str) -> 'AuthenticatedUser':
        return AuthenticatedUser(id=id, encryption_certificate=JWK.from_pem(encryption_certificate.encode()),
                                 verification_certificate=JWK.from_pem(verification_certificate.encode()),
                                 decryption_key=JWK.from_pem(decryption_key.encode()),
                                 signing_key=JWK.from_pem(signing_key.encode()))

    @staticmethod
    def generate() -> 'AuthenticatedUser':
        decryption_key = JWK.generate(kty='EC', crv='P-256')
        encryption_certificate = JWK()
        encryption_certificate.import_key(**json_decode(decryption_key.export_public()))

        signing_key = JWK.generate(kty='EC', crv='P-256')
        verification_certificate = JWK()
        verification_certificate.import_key(**json_decode(signing_key.export_public()))

        return AuthenticatedUser(id=str(uuid.uuid4()),
                                 encryption_certificate=encryption_certificate,
                                 verification_certificate=verification_certificate,
                                 decryption_key=decryption_key,
                                 signing_key=signing_key)
