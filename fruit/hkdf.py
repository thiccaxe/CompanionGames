"""
This file includes a significant portion of pyatv - see ATTRIBUTION.txt
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf_expand(salt: str, info: str, shared_secret: bytes) -> bytes:
    """Derive encryption keys from shared secret."""
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt.encode(),
        info=info.encode(),
        backend=default_backend(),
    )
    return hkdf.derive(shared_secret)
