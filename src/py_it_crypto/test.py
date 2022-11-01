

from py_it_crypto.logs.access_log import AccessLog
from py_it_crypto.user.user import UserManagement


def proof_of_concept():
    invalid_ca_pem = """-----BEGIN CERTIFICATE-----
MIIBIDCByAIJAOGzO/GXoxxnMAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTAyMDEyNTM1M1oXDTIzMTAyMDEyNTM1M1owGTEXMBUG
A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ6
/g/D3megZw6gssZIltWsk9CmqlqBNutzLjriJmTOGODHwHrTfdWIz8O161QB46jQ
qEgQrqzZK5H7X77BOlKwMAoGCCqGSM49BAMCA0cAMEQCICNvrFhNWpvO6vJAYGup
KiKEtPpfv6Rxe/Psq2XYy+H2AiA7fQHzny5CFJn4WsDDJGsgVOlnSD3gfLJ63uqq
M3s6nA==
-----END CERTIFICATE-----"""

    ca_pem = '-----BEGIN CERTIFICATE-----\n' + \
             'MIIBITCByAIJAJTQXJMDfhh5MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs\n' + \
             'b3BtZW50IENBMB4XDTIyMTAxMDE1MzUzM1oXDTIzMTAxMDE1MzUzM1owGTEXMBUG\n' + \
             'A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0\n' + \
             'aTZBEZFtalbSmc8tNjh2UED6s09U4ZNM3fEA7AAOawH6RgQ1LjDtTFSAi0pO9YH4\n' + \
             'SVinZn6m4OwhGaoNZt0sMAoGCCqGSM49BAMCA0gAMEUCIQDtK9bAkAQHrAKmGPfV\n' + \
             'vg87jEqogKq85/q5V6jHZjawhwIgRUKldOc4fTa5/diT1OHKXLUW8uaDjZVNgv8Z\n' + \
             'HRVyXPs=\n' + \
             '-----END CERTIFICATE-----'

    keyA_pub = '-----BEGIN CERTIFICATE-----\n' + \
               'MIIBIDCByQIJAOuo8ugAq2wUMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv\n' + \
               'cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD\n' + \
               'VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n' + \
               'YlFye+p72EZ2z9xeBO9JAttfa/dhD6IhS6YpL1OixTkwiNA7CRU/tvGwlgdkVJPh\n' + \
               'QLhKldBRk37co8zLv3naszAJBgcqhkjOPQQBA0cAMEQCIDnDoDAmt4x7SSWVmYEs\n' + \
               '+JwLesjmZTkw0KaiZa+2E6ocAiBzPKTBADCCWDCGbiJg4V/7KV1tSiOYC9EpFOrk\n' + \
               'kyxIiA==\n' + \
               '-----END CERTIFICATE-----\n'

    keyA_priv = '-----BEGIN PRIVATE KEY-----\n' + \
                'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAfMysADImEAjdKcY\n' + \
                '2sAIulabkZDyLdShbh+etB+RlZShRANCAARiUXJ76nvYRnbP3F4E70kC219r92EP\n' + \
                'oiFLpikvU6LFOTCI0DsJFT+28bCWB2RUk+FAuEqV0FGTftyjzMu/edqz\n' + \
                '-----END PRIVATE KEY-----'

    keyB_pub = '-----BEGIN CERTIFICATE-----\n' + \
               'MIIBITCByQIJAOuo8ugAq2wVMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv\n' + \
               'cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD\n' + \
               'VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n' + \
               'ELWdCySVeYt89xdfnUfbAh79CXk/gFvU8U988UpSLEAGx30aJ0ZecVpdKhlXO1G4\n' + \
               'yiyL8Sl6dypeN8iH7g3EtTAJBgcqhkjOPQQBA0gAMEUCIQCFDtrX9Mog3KA904Yp\n' + \
               'XduiWCtxVbGYGkSviklavTsNnAIgI8h9WNqHZdPJDVyhPwwS5oggTkGZah0LYfc3\n' + \
               '8qphvbY=\n' + \
               '-----END CERTIFICATE-----'

    keyB_priv = '-----BEGIN PRIVATE KEY-----\n' + \
                'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9XQgYCk62PfcaOKE\n' + \
                'OlAerYQAx0EWg4eVfqMc1amEu0ehRANCAAQQtZ0LJJV5i3z3F1+dR9sCHv0JeT+A\n' + \
                'W9TxT3zxSlIsQAbHfRonRl5xWl0qGVc7UbjKLIvxKXp3Kl43yIfuDcS1\n' + \
                '-----END PRIVATE KEY-----'

    sender = UserManagement.importAuthenticatedUser("sender", keyA_pub, keyA_pub, keyA_priv,
                                                    keyA_priv)
    receiver = UserManagement.importAuthenticatedUser("receiver", keyB_pub, keyB_pub, keyB_priv,
                                                      keyB_priv)
    log_in = AccessLog.generate()
    log_in.monitor = sender.id
    log_in.owner = receiver.id
    log_in.justification = "py-it-crypto"
    singed_log = sender.sign_access_log(log_in)
    jwe = receiver.encrypt(singed_log, [receiver, sender])

    print(jwe)

    def fetchUser(id: str):
        return receiver

    signed_log = receiver.decrypt(jwe, fetchUser)
    log_out = signed_log.extract()
    print(log_in)
    print(log_out)
    # print(json.dumps(json.loads(jwe), indent=4))

    # root_cert = load_certificate(FILETYPE_PEM, ca_pem.encode())
    # untrusted_cert = load_certificate(FILETYPE_PEM, keyA_pub.encode())
    # store = X509Store()
    # store.add_cert(root_cert)
    # store_ctx = X509StoreContext(store, untrusted_cert)
    # print(store_ctx.verify_certificate())
    # return
    #
    # ca_key = load_pem_public_key(ca_pem.encode())
    # cert_to_check = x509.load_pem_x509_certificate(keyA_pub.encode())




proof_of_concept()
