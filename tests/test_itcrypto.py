from unittest import TestCase

from py_it_crypto.itcrypto import ItCrypto
from py_it_crypto.logs.access_log import AccessLog
from testutils import create_fetch_sender, pub_A, priv_A, priv_B, pub_B, verify_access_logs
from py_it_crypto.user.user import UserManagement


class TestItCrypto(TestCase):
    def test_missing_login(self):
        """No user has logged in. No crypto tasks can be performed."""
        sender = UserManagement.generateAuthenticatedUser()
        receiver = UserManagement.generateAuthenticatedUser()

        fetch_sender = create_fetch_sender([sender, receiver])
        log = sender.sign_log(AccessLog.generate())
        jwe = sender.encrypt_log(log, [receiver])

        it_crypto = ItCrypto(fetch_sender)

        with self.assertRaises(ValueError) as context:
            it_crypto.encrypt_log(log, [receiver])
        self.assertTrue(
            'Before you can encrypt you need to login a user.' in str(context.exception))

        with self.assertRaises(ValueError) as context:
            it_crypto.sign_log(log)
        self.assertTrue(
            'Before you can sign data you need to login a user.' in str(context.exception))

        with self.assertRaises(ValueError) as context:
            it_crypto.decrypt_log(jwe)
        self.assertTrue(
            'Before you can decrypt you need to login a user.' in str(context.exception))

    def test_valid_login(self):
        """User is logged in and can encrypt, decrypt and sign data."""
        monitor = UserManagement.importAuthenticatedUser("monitor", pub_A, pub_A, priv_A, priv_A)
        owner = UserManagement.importAuthenticatedUser("receiver", pub_B, pub_B, priv_B, priv_B)
        receiver = UserManagement.generateAuthenticatedUser()
        fetch_sender = create_fetch_sender([monitor, owner, receiver])

        # Log is signed by a monitor
        log = AccessLog(monitor.id, owner.id, "tool", "just", 30, 'aggr', ["email", "address"])
        monitor.is_monitor = True
        singed_log = monitor.sign_log(log)

        # Login as owner and send log to receiver
        it_crypto = ItCrypto(fetch_sender)
        it_crypto.login(owner.id, pub_B, pub_B, priv_B, priv_B)
        jwe = it_crypto.encrypt_log(singed_log, [owner, receiver])

        # Owner can decrypt
        received_signed_log1 = it_crypto.decrypt_log(jwe)

        # Receiver can decrypt
        received_signed_log2 = receiver.decrypt_log(jwe, fetch_sender)

        # Verify decrypted logs
        verify_access_logs(log, received_signed_log1.extract())
        verify_access_logs(received_signed_log1.extract(), received_signed_log2.extract())

