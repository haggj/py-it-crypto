# Py-It-Crypto

This typescript module implements end-to-end encryption (E2EE) functionality for the inverse transparency toolchain [[1]](#1).
It was developed in the scope of my [master thesis at TUM](https://github.com/haggj/Masterarbeit). 
It is fully compatible with the corresponding Typescript library [ts-it-crypto](https://github.com/haggj/ts-it-crypto) and Golang library [go-it-crypto](https://github.com/haggj/go-it-crypto).
The module was published to the [python package index](https://pypi.org/project/py-it-crypto).

For a detailed description of the implemented protocol, security considerations and software architecture have a look to the thesis.

## Installation
To use the go-it-crypto module you can install it with:

`pip install py_it_crypto`

## Usage

The functionality of this library requires a function that resolves the identity of users to a `RemoteUser` object.
This objects holds the public keys of a user.
This function is mandatory for decryption since it dynamically resolves the identities to the cryptographic keys
of a user.
Usually the function requests your API to fetch public keys of a user.
The function needs to implement the following method signature:
`RemoteUser fetchUser(string)`

Assuming `pub_A` and `priv_A` are PEM-encoded public/private keys of a user, the following code is a complete example of how to use the library:

 ```python3
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


def fetch_sender(id: str) -> RemoteUser:
    """
    Resolve id to RemoteUser object.
    Usually this function requests your API to fetch user keys.
    """
    if id == "monitor":
        return UserManagement.importRemoteUser("monitor", pub_A, pub_A, pub_ca)


# This code initializes the it-crypto library with the private key pub_A and secret key priv_A.
it_crypto = ItCrypto(fetch_sender)
it_crypto.login("monitor", pub_A, pub_A, priv_A, priv_A)

# The logged-in user can create singed access logs.
log = AccessLog(it_crypto.user.id, "owner", "tool", "just", 1234, "kind", ["data", "datat more"])
signed_log = it_crypto.sign_log(log)

# The logged-in user can encrypt the logs for others.
owner = UserManagement.generateAuthenticatedUser("owner")
jwe = it_crypto.encrypt_log(signed_log, [owner])

# The logged-in user can decrypt logs intended for him
it_crypto.user = owner
received_signed_log = it_crypto.decrypt_log(jwe)
received_log = received_signed_log.extract()
print(received_log)
 ```

# Development

## Running static analysis
Make sure you are in the root directory of this repo. Then simply run
```mypy .```

## Running tests
Make sure you are in the root directory of this repo. Then simply run
```pytest .```

## Build and Upload package

### Build
Update the verion in 
`pyproject.toml`. 
Then you can build the package:
```python3 -m build```

### Upload Package to test.pypi
```python3 -m twine upload --repository pypi dist/py_it_crypto-0.0.1*```

## References
<a id="1">[1]</a>
Zieglmeier, Valentin and Pretschner, Alexander (2021).
Trustworthy transparency by design (2021).
https://arxiv.org/pdf/2103.10769.pdf