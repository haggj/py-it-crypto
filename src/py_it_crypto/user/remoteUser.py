from jwcrypto.jwk import JWK


class RemoteUser:
    id: str
    encryption_certificate: JWK
    verification_certificate: JWK
    is_monitor: bool = False

    def __init__(self, id: str, encryption_certificate: JWK, verification_certificate: JWK, is_monitor: bool=False):
        self.id = id
        self.encryption_certificate = encryption_certificate
        self.verification_certificate = verification_certificate
        self.is_monitor = is_monitor
