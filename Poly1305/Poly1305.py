# Poly1305算法 使用的质数
# https://www.numberempire.com/primenumbers.php
# 选择一个足够大的质数作为 p = 1361129467683753853853498429727072845819

# RFC 8439 Poly1305 (standalone MAC) - minimal, correct reference implementation.
# - key: 32 bytes one-time key (r||s), little-endian
# - tag: 16 bytes
#
# Spec: RFC 8439, Section 2.5 (Poly1305 Algorithm)

from __future__ import annotations

import os
from typing import Final


P: Final[int] = (1 << 130) - 5
R_CLAMP_MASK: Final[int] = 0x0ffffffc0ffffffc0ffffffc0fffffff


def poly1305_mac(message: bytes, one_time_key: bytes) -> bytes:
    """Compute Poly1305 tag per RFC 8439.

    Args:
        message: Arbitrary-length bytes.
        one_time_key: 32-byte one-time key = r||s (little-endian).

    Returns:
        16-byte authentication tag (little-endian).
    """
    if len(one_time_key) != 32:
        raise ValueError("Poly1305 one-time key must be exactly 32 bytes")

    r = int.from_bytes(one_time_key[0:16], "little") & R_CLAMP_MASK
    s = int.from_bytes(one_time_key[16:32], "little")

    acc = 0
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        # Append 0x01 (adds 2^(8*len(block)) in little-endian form)
        n = int.from_bytes(block + b"\x01", "little")
        acc = (acc + n) % P
        acc = (acc * r) % P

    tag = (acc + s) % (1 << 128)
    return tag.to_bytes(16, "little")


def _self_test() -> None:
    # RFC 8439 Section 2.5.2 test vector
    key_hex = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    msg = b"Cryptographic Forum Research Group"
    expected_tag_hex = "a8061dc1305136c6c22b8baf0c0127a9"

    tag = poly1305_mac(msg, bytes.fromhex(key_hex))
    assert tag.hex() == expected_tag_hex, (tag.hex(), expected_tag_hex)

    # quick random sanity
    k = os.urandom(32)
    t1 = poly1305_mac(b"Hello, world!", k)
    t2 = poly1305_mac(b"Hello, world?", k)
    assert t1 != t2


if __name__ == "__main__":
    _self_test()
    print("OK")
