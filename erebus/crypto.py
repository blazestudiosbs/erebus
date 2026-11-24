"""Stdlib-only authenticated encryption for at-rest archives.

Erebus's core carries no third-party dependencies and the stdlib ships no AEAD
cipher, so this composes standard primitives conservatively rather than inventing
one:

- **KDF**: ``hashlib.scrypt`` stretches the passphrase with a random 16-byte salt
  into 64 bytes of key material, split into *independent* encryption and MAC keys.
- **Cipher**: a keystream in counter mode, each block ``HMAC-SHA256(enc_key,
  nonce || counter)``, XORed with the plaintext (HMAC as a PRF — a well-understood
  construction).
- **Authentication**: **encrypt-then-MAC** — ``HMAC-SHA256(mac_key, header ||
  ciphertext)`` with a separate key, verified in constant time before any
  decryption. A wrong passphrase or any tampering fails closed with ``DecryptError``.

This is for protecting an operator's own exported engagement archive at rest. It
is not a transport protocol and adds no obfuscation or evasion capability.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct

MAGIC = b"EREBARC1"  # Erebus encrypted archive, format v1
# scrypt work factors: 128 * N * r * p = 16 MiB, comfortably under scrypt's
# default memory limit while staying expensive to brute-force.
_N, _R, _P = 2**14, 8, 1
_DKLEN = 64          # 32 bytes enc key + 32 bytes mac key
_SALT = 16
_NONCE = 16
_TAG = 32


class DecryptError(Exception):
    """Authentication failed: wrong passphrase or the archive was tampered with."""


def _derive(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    km = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt,
                        n=_N, r=_R, p=_P, dklen=_DKLEN, maxmem=0)
    return km[:32], km[32:]


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(enc_key, nonce + struct.pack(">Q", counter),
                            hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def _xor(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def encrypt(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt ``plaintext`` under ``passphrase``; returns a self-describing blob."""
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    salt = secrets.token_bytes(_SALT)
    nonce = secrets.token_bytes(_NONCE)
    enc_key, mac_key = _derive(passphrase, salt)
    header = MAGIC + salt + nonce
    ciphertext = _xor(plaintext, _keystream(enc_key, nonce, len(plaintext)))
    tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag


def decrypt(blob: bytes, passphrase: str) -> bytes:
    """Reverse :func:`encrypt`. Raises ``DecryptError`` on a bad passphrase or
    any tampering, before producing a single byte of plaintext."""
    head = len(MAGIC)
    min_len = head + _SALT + _NONCE + _TAG
    if len(blob) < min_len or blob[:head] != MAGIC:
        raise DecryptError("not an Erebus archive (bad magic or truncated)")
    salt = blob[head:head + _SALT]
    nonce = blob[head + _SALT:head + _SALT + _NONCE]
    body = blob[head + _SALT + _NONCE:-_TAG]
    tag = blob[-_TAG:]
    enc_key, mac_key = _derive(passphrase, salt)
    header = blob[:head + _SALT + _NONCE]
    expected = hmac.new(mac_key, header + body, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise DecryptError("authentication failed: wrong passphrase or corrupt archive")
    return _xor(body, _keystream(enc_key, nonce, len(body)))
