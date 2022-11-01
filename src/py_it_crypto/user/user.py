import uuid

from jwcrypto.common import json_decode
from jwcrypto.jwk import JWK

from py_it_crypto.user.authenticatedUser import AuthenticatedUser
from py_it_crypto.user.remoteUser import RemoteUser
from py_it_crypto.utils import verifiy_certificate


class UserManagement:

    @staticmethod
    def generateAuthenticatedUser() -> AuthenticatedUser:
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

    @staticmethod
    def importAuthenticatedUser(id: str, encryption_certificate: str, verification_certificate: str,
                                decryption_key: str, signing_key: str) -> AuthenticatedUser:
        enc_cert = JWK.from_pem(encryption_certificate.encode())
        vrf_cert = JWK.from_pem(verification_certificate.encode())
        dec_key = JWK.from_pem(decryption_key.encode())
        sign_key = JWK.from_pem(signing_key.encode())

        return AuthenticatedUser(id=id, encryption_certificate=enc_cert,
                                 verification_certificate=vrf_cert, decryption_key=dec_key,
                                 signing_key=sign_key)

    @staticmethod
    def generateRemoteUser() -> RemoteUser:
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
    def importRemoteUser(id: str,
                         encryption_certificate: str,
                         verification_certificate: str,
                         trusted_certificate: str) -> RemoteUser:
        if not verifiy_certificate(trusted_certificate, encryption_certificate):
            raise Exception("Could not verify encryption certificate")
        if not verifiy_certificate(trusted_certificate, verification_certificate):
            raise Exception("Could not verify verification certificate")

        enc_cert = JWK.from_pem(encryption_certificate.encode())
        vrf_cert = JWK.from_pem(verification_certificate.encode())

        return RemoteUser(id=id,
                          encryption_certificate=enc_cert,
                          verification_certificate=vrf_cert)
