import base64
import cProfile
import json
from unittest import TestCase

from py_it_crypto.logs.access_log import AccessLog
from testutils import create_fetch_sender, verify_access_logs, pub_A, priv_A, pub_B, priv_B, pub_ca, \
    invalid_pub_ca
from py_it_crypto.user.user import UserManagement


class TestUser(TestCase):

    def test_encrypt_single(self):
        """Generate users and encrypt/decrypt data for single receiver"""
        sender = UserManagement.generateAuthenticatedUser()
        receiver = UserManagement.generateAuthenticatedUser()
        fetch_user = create_fetch_sender([sender, receiver])

        access_log = AccessLog.generate()
        access_log.owner = receiver.id
        access_log.monitor = sender.id

        sender.is_monitor = True
        signed_log = sender.sign_log(access_log)
        cipher = sender.encrypt_log(signed_log, [receiver])
        received_signed_log = receiver.decrypt_log(cipher, fetch_user)

        verify_access_logs(access_log, received_signed_log.extract())

    def test_encrypt_multiple(self):
        """Generate users and encrypt/decrypt data for single receiver"""

        # Setup users
        monitor = UserManagement.generateAuthenticatedUser()
        owner = UserManagement.generateAuthenticatedUser()
        receiver = UserManagement.generateAuthenticatedUser()
        no_receiver = UserManagement.generateAuthenticatedUser()
        fetch_user = create_fetch_sender([owner, monitor, no_receiver, receiver])

        # 1. Step: Monitor creates log and encrypts it for owner
        access_log = AccessLog.generate()
        access_log.owner = owner.id
        access_log.monitor = monitor.id

        monitor.is_monitor = True
        signed_log = monitor.sign_log(access_log)
        cipher = monitor.encrypt_log(signed_log, [owner])

        # 2. Step: Owner can decrypt log
        received_signed_log1 = owner.decrypt_log(cipher, fetch_user)

        # 3. Step: Owner shares with receiver
        cipher = owner.encrypt_log(signed_log, [owner, receiver])

        # 4. Step: Owner and receiver can decrypt
        received_signed_log2 = owner.decrypt_log(cipher, fetch_user)
        received_signed_log3 = receiver.decrypt_log(cipher, fetch_user)

        verify_access_logs(access_log, received_signed_log1.extract())
        verify_access_logs(received_signed_log1.extract(), received_signed_log2.extract())
        verify_access_logs(received_signed_log2.extract(), received_signed_log3.extract())

    def test_import_user(self):
        """Import users based on X509 certificates and PCKS8 private keys"""
        sender = UserManagement.importAuthenticatedUser('sender', pub_A, pub_A, priv_A, priv_A)
        receiver = UserManagement.importAuthenticatedUser('receiver', pub_B, pub_B, priv_B, priv_B)
        fetch_user = create_fetch_sender([sender, receiver])

        access_log = AccessLog.generate()
        access_log.owner = receiver.id
        access_log.monitor = sender.id

        sender.is_monitor = True
        signed_log = sender.sign_log(access_log)
        cipher = sender.encrypt_log(signed_log, [receiver])
        received_signed_log = receiver.decrypt_log(cipher, fetch_user)

        verify_access_logs(access_log, received_signed_log.extract())

    def test_import_user_signed(self):
        """Import users with CA signed keys"""
        sender = UserManagement.importAuthenticatedUser('sender', pub_A, pub_A, priv_A, priv_A)
        receiver = UserManagement.importRemoteUser('receiver', pub_B, pub_B, False, pub_ca)
        fetch_user = create_fetch_sender([sender])

        access_log = AccessLog.generate()
        access_log.owner = receiver.id
        access_log.monitor = sender.id

        signed_log = sender.sign_log(access_log)
        cipher = sender.encrypt_log(signed_log, [receiver])

    def test_import_user_signed_fails(self):
        """Import users with CA signed keys fails"""
        sender = UserManagement.importAuthenticatedUser('sender', pub_A, pub_A, priv_A, priv_A)

        with self.assertRaises(Exception) as context:
            UserManagement.importRemoteUser('receiver', pub_B, pub_B, False, invalid_pub_ca)
        self.assertTrue('Could not verify encryption certificate' in str(context.exception))
