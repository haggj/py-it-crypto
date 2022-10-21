from unittest import TestCase

from user.user import UserManagement


class TestAuthenticatedUser(TestCase):
    def test_any(self):
        UserManagement.generateAuthenticatedUser()
