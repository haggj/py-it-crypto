import json
from typing import Callable

from jwcrypto.jwe import JWE
from jwcrypto.jws import JWS, InvalidJWSSignature

from logs.access_log import SignedAccessLog, AccessLog
from logs.shared_header import SharedHeader
from logs.shared_log import SharedLog
from user.remoteUser import RemoteUser
from utils import b64decode


class DecryptionService:

    @staticmethod
    def decrypt(jwe: str, receiver, fetch_user: Callable[[str], RemoteUser]) -> SignedAccessLog:
        decryption_result = JWE()
        decryption_result.deserialize(jwe, key=receiver.decryption_key)
        payload = decryption_result.plaintext.decode()

        jws_shared_header: dict = json.loads(decryption_result.objects.pop('protected')).get('sharedHeader')
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

        # Verify if shareIds are identical
        if shared_header.shareId != shared_log.shareId:
            raise Exception("Malformed data: ShareIds do not match!")

        # Verify if sharedHeader contains correct owner
        if access_log.owner != shared_header.owner:
            raise Exception("Malformed data: The owner of the AccessLog is not specified as owner in the SharedHeader")

        # Verify if either access_log.owner or access_log.monitor shared the log
        if not (shared_log.creator == access_log.monitor or shared_log.creator == access_log.owner):
            raise Exception("Malformed data: Only the owner or the monitor of the AccessLog are allowed to share.")
        if shared_log.creator == access_log.monitor:
            if shared_header.receivers != [access_log.owner]:
                raise Exception("Malformed data: Monitors can only share the data with the owner of the log.")

        return SignedAccessLog.from_json(json.dumps(jws_access_log))

    @staticmethod
    def _claimed_creator(jws_shared_log: dict) -> str:
        raw_json = b64decode(jws_shared_log.get('payload')).decode()
        shared_log: SharedLog = SharedLog.from_json(raw_json)
        return shared_log.creator

    @staticmethod
    def _claimed_monitor(jws_shared_log: dict) -> str:
        raw_json = b64decode(jws_shared_log.get('payload')).decode()
        access_log: AccessLog = AccessLog.from_json(raw_json)
        return access_log.monitor

    @staticmethod
    def _verify_shared_header(jws_shared_header: dict, sender: RemoteUser) -> SharedHeader:
        try:
            jws = JWS()
            jws.deserialize(json.dumps(jws_shared_header))
            jws.verify(sender.verification_certificate)
            return SharedHeader.from_json(jws.payload)
        except Exception:
            raise Exception("Could not verify SharedHeader")

    @staticmethod
    def _verify_shared_log(jws_shared_log: dict, sender: RemoteUser) -> SharedLog:
        try:
            jws = JWS()
            jws.deserialize(json.dumps(jws_shared_log))
            jws.verify(sender.verification_certificate)
            return SharedLog.from_json(jws.payload)
        except Exception:
            raise Exception("Could not verify SharedLog")

    @staticmethod
    def _verify_access_log(jws_access_log: SignedAccessLog, sender: RemoteUser) -> AccessLog:
        try:
            jws = JWS()
            jws.deserialize(json.dumps(jws_access_log))
            jws.verify(sender.verification_certificate)
            return AccessLog.from_json(jws.payload)
        except Exception:
            raise Exception("Could not verify AccessLog")

