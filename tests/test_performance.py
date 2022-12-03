import time
from unittest import TestCase

from py_it_crypto.logs.access_log import AccessLog
from testutils import create_fetch_sender, verify_access_logs, pub_A, priv_A, pub_B, priv_B, pub_ca, \
    invalid_pub_ca
from py_it_crypto.user.user import UserManagement


class TestPerformance(TestCase):

    def test_performance(self):
        """Generate users and encrypt/decrypt data for single receiver"""
        sender = UserManagement.generateAuthenticatedUser("owner")
        monitor = UserManagement.generateAuthenticatedUser("monitor")

        monitor.is_monitor = True
        access_log = AccessLog.generate()
        signed_log = monitor.sign_log(access_log)

        receivers = [sender] + [UserManagement.generateRemoteUser() for _ in range(99)]
        fetch_user = create_fetch_sender([monitor]+receivers)

        sender.encrypt_log(signed_log, receivers[:1]) # First encryption is slower than others

        iterations = [1, 2, 3, 5, 10]

        for i in iterations:
            enc_sum = 0.0
            dec_sum = 0.0
            rounds = 100
            for _ in range(rounds):
                start = time.time()
                cipher = sender.encrypt_log(signed_log, receivers[:i])
                end = time.time()
                enc_sum += (end - start)*1000

                start = time.time()
                sender.decrypt_log(cipher, fetch_user)
                end = time.time()
                dec_sum += (end - start)*1000

            result = round(enc_sum/rounds,2)
            # print(result)
