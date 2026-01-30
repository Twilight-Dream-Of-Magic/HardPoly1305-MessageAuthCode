"""
Full Differential Analysis for h_core
=====================================
Empirically evaluates output differential distributions under XOR and additive
differences. The code reports collision statistics and bit-level biases.
"""

from typing import Tuple
import random
from collections import Counter


# Constants (same as main implementation)
P1 = (1 << 130) - 5
P2 = (1 << 256) - 188_069
MASK_256 = (1 << 256) - 1

# ==========================
# 工具：bit rotate
# ==========================

def bit_rotate_left(x: int, n: int) -> int:
    x &= MASK_256
    n &= 255  # n mod 256
    if n == 0:
        return x
    return ((x << n) & MASK_256) | (x >> (256 - n))

def bit_rotate_right(x: int, n: int) -> int:
    x &= MASK_256
    n &= 255  # n mod 256
    if n == 0:
        return x
    return (x >> n) | ((x << (256 - n)) & MASK_256)

# ==========================
# 工具：key 规范化（xor-fold 到 32 字节）
# ==========================
def fold_key_32(key: bytes) -> bytes:
    """
    把任意长度(>=32)的 key 折叠成 32 字节：
    - 前 32 字节为基底
    - 后续字节按位置 i%32 进行 XOR 折叠
    目的：key>32 时也能贡献熵/差异，同时保持常量域、低开销。
    注意：这会把不同长 key 映射到同一个 32B key（等价类），使用者需知悉该语义。
    """
    if len(key) < 32:
        raise ValueError("key 至少需要 32 字节")
    if len(key) == 32:
        return key
    out = bytearray(key[0:32])
    for i, b in enumerate(key[32:]):
        out[i & 31] ^= b
    return bytes(out)

# ==========================
# 工具：从 key 派生参数
# ==========================

def derive_key_params(key: bytes) -> Tuple[int, int, int, int]:
    """
    从 32 字节 key 派生:
    - k_high, k_low: 在 P1 上的偏移
    - k_mix, k_mix_2: 在 P2 上的混合参数
    """
    # 参数派生是“32B 语义”：key>32 时通过 xor-fold 压缩进 32B（不丢弃尾巴）。
    key32 = fold_key_32(key)

    # 拆成两段
    k_high = int.from_bytes(key32[0:16], "little") & MASK_256
    k_low = int.from_bytes(key32[16:32], "little") & MASK_256

    k_mix = int.from_bytes(key32[0:32], "little") & MASK_256
    k_mix_2 = bit_rotate_right(~k_mix, 1)  # 比特取反 + 旋转（右旋 1 等价于左旋 255）

    return k_high, k_low, k_mix, k_mix_2

# ==========================
# 核心：h_core (带你这条 u 公式)
# ==========================

def h_core(
    hash_value: int,
    x_block: int,
    k_high: int,
    k_low: int,
    k_mix: int,
    k_mix_2: int,
) -> int:
    # 在 P2 上构造非线性 alpha / beta
    X = (x_block + k_high) % P2
    Y = (hash_value + k_low) % P2

    alpha = ((hash_value + X) ** 2 + (x_block - Y) ** 3) % P2
    beta = (X - Y) % P2

    # 后续操作 禁止二进制运算以外的东西 （+，-，*，/，%）

    # 控制在 256bit 范围做 bit 运算
    alpha_bits = alpha & MASK_256
    beta_bits = beta & MASK_256

    # 制作 交叉 bits
    _alpha_bits  = alpha_bits ^ ((beta_bits >> 17) | (alpha_bits << 239)) & MASK_256
    _beta_bits  = beta_bits ^ ((alpha_bits << 17) | (beta_bits >> 239)) & MASK_256

    # 应用 交叉 bits 扩散
    _k_mix = (k_mix ^ 0xB7E151628AED2A6ABF7158809CF4F3C7 ^ (_alpha_bits << 17)) & MASK_256
    _k_mix_2 = (k_mix_2 ^ 0x9E3779B97F4A7C15F39CC0605CEDC834 ^ ((_beta_bits >> (256 - 17)) & MASK_256)) & MASK_256

    # 应用 线性 mixing
    linear_mixing = bit_rotate_left(_k_mix, 127) ^ bit_rotate_left(_k_mix_2, 63) ^ bit_rotate_left(_alpha_bits , 31) ^ bit_rotate_left(_beta_bits , 15)
    temp = (hash_value ^ x_block) & MASK_256
    linear_mixing &= MASK_256
    hard = (~(k_mix ^ k_mix_2 ^ alpha_bits ^ beta_bits)) & MASK_256
    temp ^= (linear_mixing ^ hard)
    temp &= MASK_256

    # 因为 hash_i 来自 P1， 所以等价于 hash_i + temp 模 P2
    u = (hash_value + temp) % P2
    return u


def random_block_16() -> bytes:
    """Random 16-byte block (without the trailing 0x01)."""
    return bytes(random.getrandbits(8) for _ in range(16))


def apply_delta_to_block(block: bytes, delta_block: bytes) -> bytes:
    """Apply XOR difference to a 16-byte block."""
    assert len(block) == 16
    assert len(delta_block) == 16
    return bytes(b ^ d for b, d in zip(block, delta_block))


def make_single_bit_delta_block(bit_pos: int) -> bytes:
    """Construct a 16-byte XOR difference with a single 1-bit."""
    if not (0 <= bit_pos < 128):
        raise ValueError("bit_pos must be in [0, 128)")
    delta = bytearray(16)
    byte_idx = bit_pos // 8
    bit_idx = bit_pos % 8
    delta[byte_idx] = 1 << bit_idx
    return bytes(delta)


def h_core_delta_experiment(
    num_samples: int,
    delta_h: int,
    delta_m_block: bytes,
    key: bytes,
    xor_diff: bool = True,
):
    """
    Differential experiment on h_core.

    Parameters:
    - num_samples: number of samples
    - delta_h: difference applied to h (XOR or additive)
    - delta_m_block: 16-byte XOR difference for message block
    - key: 32+ byte key
    - xor_diff: if True use XOR difference for h; otherwise use additive difference
    """
    k_high, k_low, k_mix, k_mix2 = derive_key_params(key)

    delta_u_counter = Counter()
    bit_ones = [0] * 256

    for _ in range(num_samples):
        h = random.getrandbits(130)

        block = random_block_16()
        block2 = apply_delta_to_block(block, delta_m_block)

        x1 = int.from_bytes(block + b"\x01", "little")
        x2 = int.from_bytes(block2 + b"\x01", "little")

        if xor_diff:
            h2 = h ^ delta_h
        else:
            h2 = (h + delta_h) % P1

        u1 = h_core(h, x1, k_high, k_low, k_mix, k_mix2)
        u2 = h_core(h2, x2, k_high, k_low, k_mix, k_mix2)

        if xor_diff:
            du = u1 ^ u2
        else:
            du = (u2 - u1) % P2

        delta_u_counter[du] += 1

        for i in range(256):
            if (du >> i) & 1:
                bit_ones[i] += 1

    distinct = len(delta_u_counter)
    zero_prob = delta_u_counter[0] / num_samples if 0 in delta_u_counter else 0.0
    bit_bias = [c / num_samples for c in bit_ones]
    top_deltas = delta_u_counter.most_common(10)

    return {
        "num_samples": num_samples,
        "distinct_delta_u": distinct,
        "zero_prob": zero_prob,
        "bit_bias": bit_bias,
        "top_deltas": top_deltas,
    }


def pretty_print_diff_result(name: str, result):
    print(f"\n==== Differential Experiment: {name} ====")
    print(f"Samples: {result['num_samples']}")
    print(f"Distinct delta_u: {result['distinct_delta_u']}")
    print(f"P[delta_u = 0]: {result['zero_prob']:.6f}")

    print("Top 10 most common delta_u (value, count, probability):")
    for du, cnt in result["top_deltas"]:
        print(f" du = {du:#066x}, count = {cnt}")
        print(f" prob ~= {cnt / result['num_samples']:.6f}")

    print("First 32 bit 1-probabilities:")
    for i in range(32):
        print(f"  bit {i:2d}: {result['bit_bias'][i]:.4f}")
    print("...")


def run_delta_u_experiments():
    print("\n" + "=" * 60)
    print("HardPoly1305 h_core Delta-u Differential Experiments")
    print("=" * 60)

    random.seed(123456)
    key = bytes(i % 256 for i in range(32))

    # 1) Delta_h = 1, Delta_m = 0
    delta_h = 1
    delta_m_block = bytes(16)
    res1 = h_core_delta_experiment(
        num_samples=500_000,
        delta_h=delta_h,
        delta_m_block=delta_m_block,
        key=key,
        xor_diff=True,
    )
    pretty_print_diff_result("Delta h = 1, Delta m = 0 (XOR)", res1)

    # 2) Delta_h = 0, Delta_m = 2^0
    delta_h2 = 0
    delta_m_block2 = make_single_bit_delta_block(0)
    res2 = h_core_delta_experiment(
        num_samples=500_000,
        delta_h=delta_h2,
        delta_m_block=delta_m_block2,
        key=key,
        xor_diff=True,
    )
    pretty_print_diff_result("Delta h = 0, Delta m = 2^0 (XOR)", res2)

    # 3) Delta_h = 1, Delta_m = 2^17
    delta_h3 = 1
    delta_m_block3 = make_single_bit_delta_block(17)
    res3 = h_core_delta_experiment(
        num_samples=500_000,
        delta_h=delta_h3,
        delta_m_block=delta_m_block3,
        key=key,
        xor_diff=True,
    )
    pretty_print_diff_result("Delta h = 1, Delta m = 2^17 (XOR)", res3)


if __name__ == "__main__":
    run_delta_u_experiments()