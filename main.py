from jwcrypto import jwk, jwe
from jwcrypto.common import json_decode


def proof_of_concept():
    # Use a breakpoint in the code line below to debug your script.

    public_key = jwk.JWK()
    private_key = jwk.JWK.generate(kty='RSA', size=2048)
    public_key.import_key(**json_decode(private_key.export_public()))

    public_key2 = jwk.JWK()
    private_key2 = jwk.JWK.generate(kty='RSA', size=2048)
    public_key2.import_key(**json_decode(private_key2.export_public()))

    ca_pem = '-----BEGIN CERTIFICATE-----\n' + \
             'MIIBITCByAIJAJTQXJMDfhh5MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs\n' + \
             'b3BtZW50IENBMB4XDTIyMTAxMDE1MzUzM1oXDTIzMTAxMDE1MzUzM1owGTEXMBUG\n' + \
             'A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0\n' + \
             'aTZBEZFtalbSmc8tNjh2UED6s09U4ZNM3fEA7AAOawH6RgQ1LjDtTFSAi0pO9YH4\n' + \
             'SVinZn6m4OwhGaoNZt0sMAoGCCqGSM49BAMCA0gAMEUCIQDtK9bAkAQHrAKmGPfV\n' + \
             'vg87jEqogKq85/q5V6jHZjawhwIgRUKldOc4fTa5/diT1OHKXLUW8uaDjZVNgv8Z\n' + \
             'HRVyXPs=\n' + \
             '-----END CERTIFICATE-----';

    keyA_pub = '-----BEGIN CERTIFICATE-----\n' + \
               'MIIBIDCByQIJAOuo8ugAq2wUMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv\n' + \
               'cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD\n' + \
               'VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n' + \
               'YlFye+p72EZ2z9xeBO9JAttfa/dhD6IhS6YpL1OixTkwiNA7CRU/tvGwlgdkVJPh\n' + \
               'QLhKldBRk37co8zLv3naszAJBgcqhkjOPQQBA0cAMEQCIDnDoDAmt4x7SSWVmYEs\n' + \
               '+JwLesjmZTkw0KaiZa+2E6ocAiBzPKTBADCCWDCGbiJg4V/7KV1tSiOYC9EpFOrk\n' + \
               'kyxIiA==\n' + \
               '-----END CERTIFICATE-----\n';

    keyA_priv = '-----BEGIN PRIVATE KEY-----\n' + \
                'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAfMysADImEAjdKcY\n' + \
                '2sAIulabkZDyLdShbh+etB+RlZShRANCAARiUXJ76nvYRnbP3F4E70kC219r92EP\n' + \
                'oiFLpikvU6LFOTCI0DsJFT+28bCWB2RUk+FAuEqV0FGTftyjzMu/edqz\n' + \
                '-----END PRIVATE KEY-----';

    keyB_pub = '-----BEGIN CERTIFICATE-----\n' + \
               'MIIBITCByQIJAOuo8ugAq2wVMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv\n' + \
               'cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD\n' + \
               'VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n' + \
               'ELWdCySVeYt89xdfnUfbAh79CXk/gFvU8U988UpSLEAGx30aJ0ZecVpdKhlXO1G4\n' + \
               'yiyL8Sl6dypeN8iH7g3EtTAJBgcqhkjOPQQBA0gAMEUCIQCFDtrX9Mog3KA904Yp\n' + \
               'XduiWCtxVbGYGkSviklavTsNnAIgI8h9WNqHZdPJDVyhPwwS5oggTkGZah0LYfc3\n' + \
               '8qphvbY=\n' + \
               '-----END CERTIFICATE-----';


    keyB_priv = '-----BEGIN PRIVATE KEY-----\n' + \
                'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9XQgYCk62PfcaOKE\n' + \
                'OlAerYQAx0EWg4eVfqMc1amEu0ehRANCAAQQtZ0LJJV5i3z3F1+dR9sCHv0JeT+A\n' + \
                'W9TxT3zxSlIsQAbHfRonRl5xWl0qGVc7UbjKLIvxKXp3Kl43yIfuDcS1\n' + \
                '-----END PRIVATE KEY-----';

    pub_A = jwk.JWK.from_pem(keyA_pub.encode())
    priv_A = jwk.JWK.from_pem(keyA_priv.encode())

    pub_B = jwk.JWK.from_pem(keyB_pub.encode())
    priv_B = jwk.JWK.from_pem(keyB_priv.encode())

    payload = "My Encrypted message"
    protected_header = {
        "alg": "ECDH-ES+A256KW",
        "enc": "A256GCM",
        "typ": "JWE",
        "kid": public_key.thumbprint(),
    }
    jwetoken = jwe.JWE(payload.encode('utf-8'),
                       protected=protected_header)
    enc = jwetoken.add_recipient(pub_B)
    enc = jwetoken.add_recipient(pub_B)
    enc = jwetoken.serialize()
    print(enc)

    jwetoken = jwe.JWE()
    jwetoken.deserialize(enc, key=priv_B)
    payload = jwetoken.payload
    print(payload)

    token = '{"ciphertext":"rYQeJ7SnoNp6uXHm0uZc7Lk","iv":"ZJ57a0JQ5q8zXPMZ","recipients":[{"encrypted_key":"XBfbB9pO7zrvHQzv6bEEDpiof8zRWKXpKQI4eWh5dsDLSMBJE2Nbrw","header":{"alg":"ECDH-ES+A256KW"}}],"tag":"2BVvyUfFhXr_d_qq_meu6Q","protected":"eyJlbmMiOiJBMjU2R0NNIiwiZXBrIjp7IngiOiJpb0U5UWY4TmRaX3N6RnJiWkEzZ1VuakJiRFhkbllrc2M4LUxsUFVYbWZZIiwiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsInkiOiJ1cGptUjdnb29zTkhITWpwS0FQNk9QVThjX3htOFVoSWJrQ28wSGN4cW1jIn19"}'
    jwetoken = jwe.JWE()
    jwetoken.deserialize(token, key=priv_B)
    payload = jwetoken.payload
    print(payload)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    proof_of_concept()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
