import uuid

from jwcrypto.common import json_decode
from jwcrypto.jwk import JWK

from utils import verifiy_certificate


class RemoteUser:
    id: str
    encryption_certificate: JWK
    verification_certificate: JWK

    def __init__(self, id: str, encryption_certificate: JWK, verification_certificate: JWK):
        self.id = id
        self.encryption_certificate = encryption_certificate
        self.verification_certificate = verification_certificate

    @staticmethod
    def generate() -> 'RemoteUser':
        decryption_key = JWK.generate(kty='EC', crv='P-256')
        encryption_certificate = JWK()
        encryption_certificate.import_key(**json_decode(decryption_key.export_public()))

        signing_key = JWK.generate(kty='EC', crv='P-256')
        verification_certificate = JWK()
        verification_certificate.import_key(**json_decode(signing_key.export_public()))

        return RemoteUser(id=str(uuid.uuid4()),
                          encryption_certificate=encryption_certificate,
                          verification_certificate=verification_certificate)

    @staticmethod
    def from_pem(id: str,
                 encryption_certificate: str,
                 verification_certificate: str,
                 trusted_certificate: str) -> 'RemoteUser':

        if not verifiy_certificate(trusted_certificate, encryption_certificate):
            raise Exception("Could not verify encryption certificate")
        if not verifiy_certificate(trusted_certificate, verification_certificate):
            raise Exception("Could not verify verification certificate")

        return RemoteUser(id=id, encryption_certificate=JWK.from_pem(encryption_certificate.encode()),
                          verification_certificate=JWK.from_pem(verification_certificate.encode()))
