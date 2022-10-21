import base64

from OpenSSL.crypto import load_certificate, FILETYPE_PEM, X509Store, X509StoreContext, \
    X509StoreContextError


def verifiy_certificate(trusted_certificate: str, untrusted_certificate: str) -> bool:
    """
    Verifiy if a untrusted certificate is signed by a trusted certificate.
    :param trusted_certificate: The trusted root certificate.
    :param untrusted_certificate: The untrusted certificate.
    :return: True, if the untrusted certificate was signed by the trusted certificate.
    """
    root_cert = load_certificate(FILETYPE_PEM, trusted_certificate.encode())
    untrusted_cert = load_certificate(FILETYPE_PEM, untrusted_certificate.encode())
    store = X509Store()
    store.add_cert(root_cert)
    store_ctx = X509StoreContext(store, untrusted_cert)
    try:
        store_ctx.verify_certificate()
        return True
    except X509StoreContextError:
        return False


def b64decode(data: str) -> bytes:
    """
    Base64 decode the given string.
    :param data: String to decode
    :return: Base64 decoded bytes
    """
    return base64.b64decode((data + "==").encode())
