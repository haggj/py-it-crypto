from py_it_crypto.itcrypto import ItCrypto
from py_it_crypto.logs.access_log import AccessLog
from py_it_crypto.user.remoteUser import RemoteUser
from py_it_crypto.user.user import UserManagement

pub_ca = """-----BEGIN CERTIFICATE-----
MIIBITCByAIJAJTQXJMDfhh5MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTAxMDE1MzUzM1oXDTIzMTAxMDE1MzUzM1owGTEXMBUG
A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0
aTZBEZFtalbSmc8tNjh2UED6s09U4ZNM3fEA7AAOawH6RgQ1LjDtTFSAi0pO9YH4
SVinZn6m4OwhGaoNZt0sMAoGCCqGSM49BAMCA0gAMEUCIQDtK9bAkAQHrAKmGPfV
vg87jEqogKq85/q5V6jHZjawhwIgRUKldOc4fTa5/diT1OHKXLUW8uaDjZVNgv8Z
HRVyXPs=
-----END CERTIFICATE-----"""

pub_A = """-----BEGIN CERTIFICATE-----
MIIBIDCByQIJAOuo8ugAq2wUMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv
cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD
VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
YlFye+p72EZ2z9xeBO9JAttfa/dhD6IhS6YpL1OixTkwiNA7CRU/tvGwlgdkVJPh
QLhKldBRk37co8zLv3naszAJBgcqhkjOPQQBA0cAMEQCIDnDoDAmt4x7SSWVmYEs
+JwLesjmZTkw0KaiZa+2E6ocAiBzPKTBADCCWDCGbiJg4V/7KV1tSiOYC9EpFOrk
kyxIiA==
-----END CERTIFICATE-----"""

priv_A = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAfMysADImEAjdKcY
2sAIulabkZDyLdShbh+etB+RlZShRANCAARiUXJ76nvYRnbP3F4E70kC219r92EP
oiFLpikvU6LFOTCI0DsJFT+28bCWB2RUk+FAuEqV0FGTftyjzMu/edqz
-----END PRIVATE KEY-----"""


def fetch_user(id: str) -> RemoteUser:
    """
    Resolve id to RemoteUser object.
    Usually this function requests your API to fetch user keys.
    """
    if id == "monitor":
        return UserManagement.importRemoteUser("monitor", pub_A, pub_A, True, pub_ca)
    raise Exception("User not found")


# This code initializes the it-crypto library with the private key pub_A and secret key priv_A.
it_crypto = ItCrypto(fetch_user)
it_crypto.login("monitor", pub_A, pub_A, priv_A, priv_A)

# The logged-in user can create singed access logs.
log = AccessLog("monitor", "owner", "tool", "just", 1234, "kind", ["data", "datat more"])
signed_log = it_crypto.sign_log(log)

# The logged-in user can encrypt the logs for others.
owner = UserManagement.generateAuthenticatedUser("owner")
jwe = it_crypto.encrypt_log(signed_log, [owner])

# The logged-in user can decrypt logs intended for him
it_crypto.user = owner
received_signed_log = it_crypto.decrypt_log(jwe)
received_log = received_signed_log.extract()
print(received_log)


