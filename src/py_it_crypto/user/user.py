import uuid

from jwcrypto.common import json_decode
from jwcrypto.jwk import JWK

from py_it_crypto.user.authenticatedUser import AuthenticatedUser
from py_it_crypto.user.remoteUser import RemoteUser
from py_it_crypto.utils import verify_certificate


class UserManagement:
    """
    Provides convenient functions to simplify the handling of users.
    """

    @staticmethod
    def generateAuthenticatedUser(id = None) -> AuthenticatedUser:
        """
        This function generates a random AuthenticatedUser. It is used during testing.
        :param id: Optional identity of the generated user.
        :return: The generated AuthenticatedUser object.
        """
        decryption_key = JWK.generate(kty='EC', crv='P-256')
        encryption_certificate = JWK()
        encryption_certificate.import_key(**json_decode(decryption_key.export_public()))

        signing_key = JWK.generate(kty='EC', crv='P-256')
        verification_certificate = JWK()
        verification_certificate.import_key(**json_decode(signing_key.export_public()))

        return AuthenticatedUser(id=id if id else str(uuid.uuid4()),
                                 encryption_certificate=encryption_certificate,
                                 verification_certificate=verification_certificate,
                                 decryption_key=decryption_key,
                                 signing_key=signing_key)

    @staticmethod
    def importAuthenticatedUser(id: str, encryption_certificate: str, verification_certificate: str,
                                decryption_key: str, signing_key: str) -> AuthenticatedUser:
        """
        Import a user based on its certificates and keys.
        The returned user can be used to sign and encrypt logs.
        :param id: The identity of the imported user.
        :param encryption_certificate: The encryption certificate of the user.
        :param verification_certificate: The verification certificate of the user.
        :param decryption_key: The decryption key of the user.
        :param signing_key: The signing key of the user.
        :return: The imported AuthenticatedUser object.
        """
        enc_cert = JWK.from_pem(encryption_certificate.encode())
        vrf_cert = JWK.from_pem(verification_certificate.encode())
        dec_key = JWK.from_pem(decryption_key.encode())
        sign_key = JWK.from_pem(signing_key.encode())

        return AuthenticatedUser(id=id, encryption_certificate=enc_cert,
                                 verification_certificate=vrf_cert, decryption_key=dec_key,
                                 signing_key=sign_key)

    @staticmethod
    def generateRemoteUser(id = None) -> RemoteUser:
        """
        This function generates a random RemoteUser. It is used during testing.
        :param id: Optional identity of the generated user.
        :return: The generated RemoteUser object.
        """
        decryption_key = JWK.generate(kty='EC', crv='P-256')
        encryption_certificate = JWK()
        encryption_certificate.import_key(**json_decode(decryption_key.export_public()))

        signing_key = JWK.generate(kty='EC', crv='P-256')
        verification_certificate = JWK()
        verification_certificate.import_key(**json_decode(signing_key.export_public()))

        return RemoteUser(id=id if id else str(uuid.uuid4()),
                          encryption_certificate=encryption_certificate,
                          verification_certificate=verification_certificate)

    @staticmethod
    def importRemoteUser(id: str,
                         encryption_certificate: str,
                         verification_certificate: str,
                         is_monitor: bool,
                         trusted_certificate: str) -> RemoteUser:
        """
        Import a user based on its public certificates. This function also verifies if the provided
        certificates are singed by the trusted certificate authority.
        :param id: The identity of the imported user.
        :param encryption_certificate: The encryption certificate of the user.
        :param verification_certificate: The verification certificate of the user.
        :param is_monitor: Indicates if the imported user is a monitor.
        :param trusted_certificate: The certificate of the trusted certificate authority.
        :return: The imported RemoteUser object.
        """
        if not verify_certificate(trusted_certificate, encryption_certificate):
            raise Exception("Could not verify encryption certificate")
        if not verify_certificate(trusted_certificate, verification_certificate):
            raise Exception("Could not verify verification certificate")

        enc_cert = JWK.from_pem(encryption_certificate.encode())
        vrf_cert = JWK.from_pem(verification_certificate.encode())

        return RemoteUser(id=id,
                          encryption_certificate=enc_cert,
                          verification_certificate=vrf_cert,
                          is_monitor=is_monitor)
