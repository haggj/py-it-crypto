from typing import Callable, List, Optional

from py_it_crypto.logs.access_log import AccessLog
from py_it_crypto.logs.signed_log import SignedLog
from py_it_crypto.user.remoteUser import RemoteUser
from py_it_crypto.user.authenticatedUser import AuthenticatedUser
from py_it_crypto.user.user import UserManagement


class ItCrypto:
    """
    The ItCrypto class provides convenient wrappers around the internal crypto operations.
    It can be used to sign, encrypt and decrypt logs.
    """
    def __init__(self, fetch_user: Callable[[str], RemoteUser]):
        self.fetchUser = fetch_user
        self.user: Optional[AuthenticatedUser] = None

    def login(self,
              id: str,
              encryption_certificate: str,
              verification_certificate: str,
              decryption_key: str,
              signing_key: str) -> None:
        """
        Login a user with its keys and certificates.
        This is required to sign, encrypt or decrypt data.
        :param id: Identity of th user.
        :param encryption_certificate: Encryption Certificate of the user.
        :param verification_certificate: Verification Certificate of the user.
        :param decryption_key: Decryption key of the user.
        :param signing_key: Signing key of the user.
        :return: The function returns None.
        """
        self.user = UserManagement.importAuthenticatedUser(
            id,
            encryption_certificate,
            verification_certificate,
            decryption_key,
            signing_key
        )

    def encrypt_log(self, log: SignedLog, receivers: List[RemoteUser]) -> str:
        """
        Encrypt a log for the given receivers. The log must be singed by a monitor.
        This requires a logged-in user.
        :param log: The SignedLog is a log which is signed by a monitor.
        :param receivers: The list of receivers who can decrypt the log.
        :return: JWE token encoded as string.
        """
        if not self.user:
            raise ValueError("Before you can encrypt you need to login a user.")
        return self.user.encrypt_log(log, receivers)

    def decrypt_log(self, jwe: str) -> SignedLog:
        """
        Decrypt the given JWE token. This requires a logged-in user.
        :param jwe: JWE token to decrypt.
        :return: Returns the SingedLog which is stored within the JWE token.
        """
        if not self.user:
            raise ValueError("Before you can decrypt you need to login a user.")
        return self.user.decrypt_log(jwe, self.fetchUser)

    def sign_log(self, log: AccessLog) -> SignedLog:
        """
        Sign the provided raw log data (encoded as AccessLog). This requires a logged-in user.
        :param log:  AccessLog which needs to be signed.
        :return: Returns a SignedLog object (which contains the AccessLog)
        """
        if not self.user:
            raise ValueError("Before you can sign data you need to login a user.")
        return self.user.sign_log(log)