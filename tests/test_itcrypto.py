from unittest import TestCase

from itcrypto import ItCrypto
from logs.access_log import AccessLog
from testutils import create_fetch_sender, pub_A, priv_A, priv_B, pub_B
from user.user import UserManagement


class TestItCrypto(TestCase):
    def test_missing_login(self):
        """No user has logged in. No crypto tasks can be performed."""
        sender = UserManagement.generateAuthenticatedUser()
        receiver = UserManagement.generateAuthenticatedUser()

        fetch_sender = create_fetch_sender([sender, receiver])
        log = sender.sign_access_log(AccessLog.generate())
        jwe = sender.encrypt(log, [receiver])

        it_crypto = ItCrypto(fetch_sender)

        with self.assertRaises(ValueError) as context:
            it_crypto.encrypt(log, [receiver])
        self.assertTrue(
            'Before you can encrypt you need to login a user.' in str(context.exception))

        with self.assertRaises(ValueError) as context:
            it_crypto.sign_access_log(log)
        self.assertTrue(
            'Before you can sign data you need to login a user.' in str(context.exception))

        with self.assertRaises(ValueError) as context:
            it_crypto.decrypt(jwe)
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
        singed_log = monitor.sign_access_log(log)

        # Login as owner and send log receiver
        it_crypto = ItCrypto(fetch_sender)
        it_crypto.login(owner.id, pub_B, pub_B, priv_B, priv_B)
        jwe = it_crypto.encrypt(singed_log, [owner, receiver])

        # Owner can decrypt
        dec_log1 = it_crypto.decrypt(jwe)

        # Receiver can decrypt
        dec_log2 = receiver.decrypt(jwe, fetch_sender)

        # Verify decrypted logs
        for dec_log in [dec_log1.extract(), dec_log2.extract()]:
            self.assertEqual(log.owner, dec_log.owner)
            self.assertEqual(log.monitor, dec_log.monitor)
            self.assertEqual(log.tool, dec_log.tool)
            self.assertEqual(log.justification, dec_log.justification)
            self.assertEqual(log.timestamp, dec_log.timestamp)
            self.assertEqual(log.accessKind, dec_log.accessKind)
            self.assertEqual(log.dataType, dec_log.dataType)

