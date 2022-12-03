from jwcrypto.jwk import JWK


class RemoteUser:
    """
    Represents a remote User, which has access to the certificates of the user.
    The certificates can be used to:
    - encrypt data for this user (encryption_certificate)
    - verify data which was signed by this user (verification_certificate)

    **NOTE**: Do not instantiate this interface by yourself since the provided
    certificate need to be validated against a trusted CA.
    Use the *User.importRemoteUser()* function instead.
    """
    id: str
    encryption_certificate: JWK
    verification_certificate: JWK
    is_monitor: bool = False

    def __init__(self, id: str, encryption_certificate: JWK, verification_certificate: JWK, is_monitor: bool=False):
        self.id = id
        self.encryption_certificate = encryption_certificate
        self.verification_certificate = verification_certificate
        self.is_monitor = is_monitor
