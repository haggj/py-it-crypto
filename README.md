# Py-It-Crypto

This python package implements E2EE encryption functionality for the inverse transparency toolchain [[1]](#1).
It was developed in the scope of my [master thesis at TUM](https://github.com/haggj/Masterarbeit). 
It is fully compatible with the corresponding Typescript library [ts-it-crypto](https://github.com/haggj/ts-it-crypto) and Golang library [go-it-crypto](https://github.com/haggj/go-it-crypto).
The module was published to the [python package index](https://pypi.org/project/py-it-crypto).

For a detailed description of the implemented protocol, security considerations and software architecture have a look to the thesis.

## Installation
To use the go-it-crypto module you can install it with:
`pip install py-it-crypto`

## Usage

The functionality of this library requires a function that resolves the identity of users to a `RemoteUser` object.
This objects holds the public keys of a user.
This function is mandatory for decryption since it dynamically resolves the identities to the cryptographic keys
of a user.
This function needs to implement the following signature:
`RemoteUser fetchUser(string)`

Assuming `pub_A` and `priv_A` are PEM-encoded public/private keys of a user, the following code
initializes the it-crypto library for the owner of this keypair.

 ```
it_crypto = ItCrypto(fetch_sender)
it_crypto.login(owner.id, pub_A, pub_A, priv_A, priv_A)
 ```
The logged-in user can sign AccessLogs:

 ```
signedLog = it_crypto.sign_access_log(access_log)
 ```

The logged-in user can encrypt SignedAccessLogs for other users:

 ```
cipher = it_crypto.encrypt(singed_log, [receiver1, receiver2])
 ```

The logged-in user can decrypt tokens (this only succeeds if this user was specified as receiver during encryption):

 ```
received_signed_log = it_crypto.decrypt(cipher)
received_access_log = received_signed_log.extract()
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
```python3 -m build```

### Upload Package to test.pypi
```python3 -m twine upload --repository pypi dist/py_it_crypto-0.0.1*```
