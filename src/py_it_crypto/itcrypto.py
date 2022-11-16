from typing import Callable, List, Optional

from py_it_crypto.logs.access_log import SignedAccessLog, AccessLog
from py_it_crypto.user.remoteUser import RemoteUser
from py_it_crypto.user.authenticatedUser import AuthenticatedUser
from py_it_crypto.user.user import UserManagement


class ItCrypto:
    def __init__(self, fetch_user: Callable[[str], RemoteUser]):
        self.fetchUser = fetch_user
        self.user: Optional[AuthenticatedUser] = None

    def login(self,
              id: str,
              encryption_certificate: str,
              verification_certificate: str,
              decryption_key: str,
              signing_key: str) -> None:
        self.user = UserManagement.importAuthenticatedUser(
            id,
            encryption_certificate,
            verification_certificate,
            decryption_key,
            signing_key
        )

    def encrypt_log(self, log: SignedAccessLog, receivers: List[RemoteUser]) -> str:
        if not self.user:
            raise ValueError("Before you can encrypt you need to login a user.")
        return self.user.encrypt_log(log, receivers)

    def decrypt_log(self, jwe: str) -> SignedAccessLog:
        if not self.user:
            raise ValueError("Before you can decrypt you need to login a user.")
        return self.user.decrypt_log(jwe, self.fetchUser)

    def sign_log(self, log: AccessLog) -> SignedAccessLog:
        if not self.user:
            raise ValueError("Before you can sign data you need to login a user.")
        return self.user.sign_log(log)