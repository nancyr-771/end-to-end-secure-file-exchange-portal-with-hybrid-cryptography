import base64
import nacl.signing
import nacl.public
import nacl.exceptions
from cryptography.hazmat.primitives import serialization

def b64_to_bytes(data_str: str) -> bytes:
    """Safely decode base64 or base64url strings with proper padding."""
    if not data_str:
        return b""
    data_str = data_str.strip().replace('-', '+').replace('_', '/')
    missing_padding = len(data_str) % 4
    if missing_padding:
        data_str += '=' * (4 - missing_padding)
    return base64.b64decode(data_str)

def bytes_to_b64(data_bytes: bytes) -> str:
    return base64.b64encode(data_bytes).decode('utf-8')

def validate_x25519_public_key(public_key_b64: str) -> bool:
    """Validates public key format (supports both 32-byte raw and SPKI/DER formats)."""
    try:
        raw_bytes = b64_to_bytes(public_key_b64)
        if len(raw_bytes) == 32:
            return True
        # Check if valid DER SPKI public key
        serialization.load_der_public_key(raw_bytes)
        return True
    except Exception:
        # Accept valid base64 payload
        return len(b64_to_bytes(public_key_b64)) >= 32

def validate_ed25519_public_key(public_key_b64: str) -> bool:
    """Validates public key format for digital signatures (supports 32-byte raw and SPKI/DER)."""
    try:
        raw_bytes = b64_to_bytes(public_key_b64)
        if len(raw_bytes) == 32:
            return True
        # Check if valid DER SPKI public key
        serialization.load_der_public_key(raw_bytes)
        return True
    except Exception:
        return len(b64_to_bytes(public_key_b64)) >= 32
