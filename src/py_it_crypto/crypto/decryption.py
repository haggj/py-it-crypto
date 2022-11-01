import json
from typing import Callable

from jwcrypto.jwe import JWE
from jwcrypto.jws import JWS

from py_it_crypto.logs.access_log import SignedAccessLog, AccessLog
from py_it_crypto.logs.shared_header import SharedHeader
from py_it_crypto.logs.shared_log import SharedLog
from py_it_crypto.user.remoteUser import RemoteUser
from py_it_crypto.utils import b64decode


class DecryptionFailure(Exception):
    """Raised when the decryption of a JWE fails"""
    pass


class DecryptionService:

    @staticmethod
    def decrypt(jwe: str, receiver, fetch_user: Callable[[str], RemoteUser]) -> SignedAccessLog:
        # Parse and decrypt the given JWE
        decryption_result = JWE()
        decryption_result.deserialize(jwe, key=receiver.decryption_key)
        payload = decryption_result.plaintext.decode()

        # Parse the included jwsSharedHeader and jwsSharedLog objects
        protected = decryption_result.objects.pop('protected')
        jws_shared_header: dict = json.loads(protected).get('sharedHeader')
        jws_shared_log: dict = json.loads(payload)

        # Extract the creator specified within the SharedLog
        # Both, the SharedLog and the SharedHeader, are expected to be signed by this creator
        creator = fetch_user(DecryptionService._claimed_creator(jws_shared_log))
        shared_header = DecryptionService._verify_shared_header(jws_shared_header, creator)
        shared_log = DecryptionService._verify_shared_log(jws_shared_log, creator)

        # Extract the monitor specified within the AccessLog
        # The AccessLog is expected to be signed by this monitor
        jws_access_log: dict = shared_log.log
        monitor = fetch_user(DecryptionService._claimed_monitor(jws_access_log))
        access_log = DecryptionService._verify_access_log(jws_access_log, monitor)

        """
        Invariants, which need to hold:
        1. AccessLog.owner == SharedHeader.owner
        2. SharedLog.creator == AccessLog.monitor || SharedLog.creator == AccessLog.owner
        3. SharedHeader.shareId = SharedLog.shareId
        """

        # Verify if shareIds are identical
        if shared_header.shareId != shared_log.shareId:
            raise DecryptionFailure("Malformed data: ShareIds do not match!")

        # Verify if sharedHeader contains correct owner
        if access_log.owner != shared_header.owner:
            raise DecryptionFailure("Malformed data: The owner of the AccessLog "
                                    "is not specified as owner in the SharedHeader")

        # Verify if either access_log.owner or access_log.monitor shared the log
        if not (shared_log.creator == access_log.monitor or shared_log.creator == access_log.owner):
            raise DecryptionFailure("Malformed data: Only the owner or the "
                                    "monitor of the AccessLog are allowed to share.")
        if shared_log.creator == access_log.monitor:
            if shared_header.receivers != [access_log.owner]:
                raise DecryptionFailure("Malformed data: Monitors can only"
                                        " share the data with the owner of the log.")

        return SignedAccessLog.from_json(json.dumps(jws_access_log))

    @staticmethod
    def _claimed_creator(jws_shared_log: dict) -> str:
        raw_json = b64decode(str(jws_shared_log.get('payload')))
        shared_log: SharedLog = SharedLog.from_json(raw_json.decode())
        return shared_log.creator

    @staticmethod
    def _claimed_monitor(jws_shared_log: dict) -> str:
        raw_json = b64decode(str(jws_shared_log.get('payload')))
        access_log: AccessLog = AccessLog.from_json(raw_json.decode())
        return access_log.monitor

    @staticmethod
    def _verify_shared_header(jws_shared_header: dict, sender: RemoteUser) -> SharedHeader:
        try:
            jws = JWS()
            jws.deserialize(json.dumps(jws_shared_header))
            jws.verify(sender.verification_certificate)
            return SharedHeader.from_json(jws.payload)
        except Exception:
            raise DecryptionFailure("Could not verify SharedHeader")

    @staticmethod
    def _verify_shared_log(jws_shared_log: dict, sender: RemoteUser) -> SharedLog:
        try:
            jws = JWS()
            jws.deserialize(json.dumps(jws_shared_log))
            jws.verify(sender.verification_certificate)
            return SharedLog.from_json(jws.payload)
        except Exception:
            raise DecryptionFailure("Could not verify SharedLog")

    @staticmethod
    def _verify_access_log(jws_access_log: dict, sender: RemoteUser) -> AccessLog:
        try:
            jws = JWS()
            jws.deserialize(json.dumps(jws_access_log))
            jws.verify(sender.verification_certificate)
            return AccessLog.from_json(jws.payload)
        except Exception:
            raise DecryptionFailure("Could not verify AccessLog")
