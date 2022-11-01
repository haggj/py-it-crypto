from typing import List, Callable
from unittest import TestCase

from py_it_crypto.user.remoteUser import RemoteUser


def create_fetch_sender(users: List[RemoteUser]) -> Callable[[str], RemoteUser]:
    def _fetch_sender(id: str) -> RemoteUser:
        for user in users:
            if user.id == id:
                return user
        raise ValueError("Could not find user " + id + "...")

    return _fetch_sender

def verify_access_logs(first, second):
    # Verify decrypted logs
    test = TestCase()
    test.assertEqual(first.owner, second.owner)
    test.assertEqual(first.monitor, second.monitor)
    test.assertEqual(first.tool, second.tool)
    test.assertEqual(first.justification, second.justification)
    test.assertEqual(first.timestamp, second.timestamp)
    test.assertEqual(first.accessKind, second.accessKind)
    test.assertEqual(first.dataType, second.dataType)

invalid_pub_ca = """-----BEGIN CERTIFICATE-----
MIIBIDCByAIJAOGzO/GXoxxnMAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTAyMDEyNTM1M1oXDTIzMTAyMDEyNTM1M1owGTEXMBUG
A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ6
/g/D3megZw6gssZIltWsk9CmqlqBNutzLjriJmTOGODHwHrTfdWIz8O161QB46jQ
qEgQrqzZK5H7X77BOlKwMAoGCCqGSM49BAMCA0cAMEQCICNvrFhNWpvO6vJAYGup
KiKEtPpfv6Rxe/Psq2XYy+H2AiA7fQHzny5CFJn4WsDDJGsgVOlnSD3gfLJ63uqq
M3s6nA==
-----END CERTIFICATE-----"""

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

pub_B = """-----BEGIN CERTIFICATE-----
MIIBITCByQIJAOuo8ugAq2wVMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv
cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD
VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
ELWdCySVeYt89xdfnUfbAh79CXk/gFvU8U988UpSLEAGx30aJ0ZecVpdKhlXO1G4
yiyL8Sl6dypeN8iH7g3EtTAJBgcqhkjOPQQBA0gAMEUCIQCFDtrX9Mog3KA904Yp
XduiWCtxVbGYGkSviklavTsNnAIgI8h9WNqHZdPJDVyhPwwS5oggTkGZah0LYfc3
8qphvbY=
-----END CERTIFICATE-----"""

priv_B ="""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9XQgYCk62PfcaOKE
OlAerYQAx0EWg4eVfqMc1amEu0ehRANCAAQQtZ0LJJV5i3z3F1+dR9sCHv0JeT+A
W9TxT3zxSlIsQAbHfRonRl5xWl0qGVc7UbjKLIvxKXp3Kl43yIfuDcS1
-----END PRIVATE KEY-----"""