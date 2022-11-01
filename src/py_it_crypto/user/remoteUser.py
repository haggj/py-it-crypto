from jwcrypto.jwk import JWK


class RemoteUser:
    id: str
    encryption_certificate: JWK
    verification_certificate: JWK

    def __init__(self, id: str, encryption_certificate: JWK, verification_certificate: JWK):
        self.id = id
        self.encryption_certificate = encryption_certificate
        self.verification_certificate = verification_certificate
