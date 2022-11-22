import json
from typing import Callable

from jwcrypto.jwe import JWE
from jwcrypto.jws import JWS

from py_it_crypto.logs.access_log import SignedAccessLog, AccessLog
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
        protected : dict = json.loads(decryption_result.objects.pop('protected'))

        # Parse the included jwsSharedLog objects
        jws_shared_log: dict = json.loads(payload)

        # Extract the creator specified within the SharedLog
        # The SharedLog is expected to be signed by this creator
        creator = fetch_user(DecryptionService._claimed_creator(jws_shared_log))
        shared_log = DecryptionService._verify_shared_log(jws_shared_log, creator)

        # Extract the monitor specified within the AccessLog
        # The AccessLog is expected to be signed by this monitor
        jws_access_log: dict = shared_log.log
        monitor = fetch_user(DecryptionService._claimed_monitor(jws_access_log))
        access_log = DecryptionService._verify_access_log(jws_access_log, monitor)

        # Verify that the recipients in the SharedLog is equal to the recipients in the metadata
        meta_recipients = protected.get('recipients')
        if shared_log.recipients != meta_recipients:
            raise DecryptionFailure("Malformed data: Sets of recipients are not equal!")

        # Verify that the decrypting user is part of the recipients
        if receiver.id not in shared_log.recipients:
            raise DecryptionFailure("Malformed data: Decrypting user not specified in recipients!")

        # Verify that the owner in the AccessLog is equal to the owner in the metadata
        meta_owner = protected.get('owner')
        if access_log.owner != meta_owner:
            raise DecryptionFailure("Malformed data: The specified owners are not equal!")

        # Verify if either access_log.owner or access_log.monitor shared the log
        if not (shared_log.creator == access_log.monitor or shared_log.creator == access_log.owner):
            raise DecryptionFailure("Malformed data: Only the owner or the "
                                    "monitor of the AccessLog are allowed to share.")
        if shared_log.creator == access_log.monitor:
            if shared_log.recipients != [access_log.owner]:
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
        if not sender.is_monitor:
            raise DecryptionFailure("Claimed monitor is not authorized to sign logs.")

        try:
            jws = JWS()
            jws.deserialize(json.dumps(jws_access_log))
            jws.verify(sender.verification_certificate)
            return AccessLog.from_json(jws.payload)
        except Exception:
            raise DecryptionFailure("Could not verify AccessLog")
