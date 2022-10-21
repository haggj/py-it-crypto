from unittest import TestCase

from user.authenticatedUser import AuthenticatedUser


class TestAuthenticatedUser(TestCase):
    def test_any(self):
        AuthenticatedUser.generate()
