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
MIIBITCByAIJAJIgM6o1Soz/MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTIwMzEyNTIwNFoXDTIzMTIwMzEyNTIwNFowGTEXMBUG
A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASz
mmKWEqdfYOcspvWpjyZlzDRj4ueX+VBMIh6PnyTDiF21CD9V/hCeJGMUBwOhA/0K
GBXjuHoEQWolytkNC4IdMAoGCCqGSM49BAMCA0gAMEUCIQCqtjjokBqyMe3h850n
HlXsfCDTLQe+Tq0YGX1s3Ac5zAIgW02bMx6mroNrFONplm6Li0HLIgCfXVOIS3BF
RQUGwhY=
-----END CERTIFICATE-----"""

pub_A = """-----BEGIN CERTIFICATE-----
MIIBJzCBzwIJAPi05h3+oZR3MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTIwMzEyNTIwNFoXDTIzMTIwMzEyNTIwNFowIDEeMBwG
A1UEAwwVIm1vaXRvcjJAbW9uaXRvci5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEBshF/Y40TAHRdcLc8CU9iu+ZJz8W69Qrmbttu/i9WAMR8sX+sF/glcOS
5BmltKxfL49B5jBZmVenmyajT6tfITAKBggqhkjOPQQDAgNHADBEAiAXvw+CwR97
ahXX2PPRJq/gQ2gXS/x0pvKNo6521UutlgIgdOknrMA6v+SglkBu8USsKGRgqFa2
RCNGeW9w1K4rnPY=
-----END CERTIFICATE-----"""

priv_A = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNxkH9Z8yVF7KHrLw
KP6IxRk1DYjHS6pYC8tXacYkizyhRANCAAQGyEX9jjRMAdF1wtzwJT2K75knPxbr
1CuZu227+L1YAxHyxf6wX+CVw5LkGaW0rF8vj0HmMFmZV6ebJqNPq18h
-----END PRIVATE KEY-----"""

pub_B = """-----BEGIN CERTIFICATE-----
MIIBKTCBzwIJAPi05h3+oZR4MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTIwMzEyNTIwNFoXDTIzMTIwMzEyNTIwNFowIDEeMBwG
A1UEAwwVIm1vaXRvcjJAbW9uaXRvci5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE2tg3CN9AENSlkL6FONlWDX3wVKIKAZoziWHkZ/U/y0VvcSSke1DMY8Id
jXqmwJtK7OTjv3muQezMaAYdJc73/DAKBggqhkjOPQQDAgNJADBGAiEApED995lG
XEpbpG0nqrnwtXFiZAR9jC6SV9AJP85MF0ECIQC/d3C2oq/q8OLAbcNMagwyEw26
1MnS5F6OMRw1m0IXwA==
-----END CERTIFICATE-----"""

priv_B ="""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqySZT+PKukQfGQGb
b3F8fZnpY8LYfadaZDaDwteHw1WhRANCAATa2DcI30AQ1KWQvoU42VYNffBUogoB
mjOJYeRn9T/LRW9xJKR7UMxjwh2NeqbAm0rs5OO/ea5B7MxoBh0lzvf8
-----END PRIVATE KEY-----"""