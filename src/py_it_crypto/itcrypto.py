from typing import Callable, List, Optional

from py_it_crypto.logs.access_log import SignedAccessLog, AccessLog
from py_it_crypto.user.remoteUser import RemoteUser
from py_it_crypto.user.authenticatedUser import AuthenticatedUser
from py_it_crypto.user.user import UserManagement


class ItCrypto:
    def __init__(self, fetch_user: Callable[[str], RemoteUser]):
        self.fetchUser = fetch_user
        self.authenticatedUser : Optional[AuthenticatedUser] = None

    def login(self,
              id: str,
              encryption_certificate: str,
              verification_certificate: str,
              decryption_key: str,
              signing_key: str) -> None:
        self.authenticatedUser = UserManagement.importAuthenticatedUser(
            id,
            encryption_certificate,
            verification_certificate,
            decryption_key,
            signing_key
        )

    def encrypt(self, log: SignedAccessLog, receivers: List[RemoteUser]) -> str:
        if not self.authenticatedUser:
            raise ValueError("Before you can encrypt you need to login a user.")
        return self.authenticatedUser.encrypt(log, receivers)

    def decrypt(self, jwe: str) -> SignedAccessLog:
        if not self.authenticatedUser:
            raise ValueError("Before you can decrypt you need to login a user.")
        return self.authenticatedUser.decrypt(jwe, self.fetchUser)

    def sign_access_log(self, log: AccessLog) -> SignedAccessLog:
        if not self.authenticatedUser:
            raise ValueError("Before you can sign data you need to login a user.")
        return self.authenticatedUser.sign_access_log(log)