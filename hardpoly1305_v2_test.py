#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HardPoly1305 h_core quick red-flag tests
- Jacobian span-rank w.r.t x_block / hash_value
- Avalanche (bit-flip) stats
- Output bit bias (max deviation)
- Collision sanity (should be none at this scale)

This is NOT a proof. It's a structural smell test.
"""

import secrets
from collections import Counter
from typing import Tuple, List, Optional, Dict, Any

import random
import math
import sys


MASK_256 = (1 << 256) - 1

# ====== Your primes (edit if you changed) ======
P1 = (1 << 130) - 5
P2: Optional[int] = (1 << 256) - 188_069   # set None to use mod 2^256 for speed (not recommended)


# ====== Helpers ======
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

def popcnt256(x: int) -> int:
    return (x & MASK_256).bit_count()

def parity(x: int) -> int:
    """Return parity (sum of bits mod 2) for an int masked to 256-bit."""
    return (x & MASK_256).bit_count() & 1

def gf2_rank(vectors: List[int]) -> int:
    """Rank over GF(2) for 256-bit vectors."""
    basis = [0] * 256
    rank = 0
    for v in vectors:
        x = v & MASK_256
        while x:
            p = x.bit_length() - 1
            if basis[p]:
                x ^= basis[p]
            else:
                basis[p] = x
                rank += 1
                break
    return rank


# ====== Key params (use your latest semantics here) ======
def derive_key_params_latest(key32: bytes) -> Tuple[int, int, int, int]:
    """
    You said you changed to:
      k_high = low 16B -> 256-bit masked
      k_low  = high16B -> 256-bit masked
      k_mix  = whole32B -> 256-bit masked
      k_mix_2 = rotr256((~k_mix) & MASK_256, 1)    (optionally xor a const)
    """
    if len(key32) != 32:
        raise ValueError("need 32-byte key32")

    k_high = int.from_bytes(key32[0:16], "little") & MASK_256
    k_low  = int.from_bytes(key32[16:32], "little") & MASK_256

    k_mix  = int.from_bytes(key32[0:32], "little") & MASK_256
    k_mix_2 = bit_rotate_right((~k_mix) & MASK_256, 1)

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

def h_core_bits(hash_value: int, x_block: int, kp: Tuple[int,int,int,int]) -> int:
    k_high, k_low, k_mix, k_mix_2 = kp
    u = h_core(hash_value, x_block, k_high, k_low, k_mix, k_mix_2)
    # You later treat u as 256-bit material (derive r/s from low/high 16B),
    # so we test u_bits.
    return u & MASK_256

# ====== Test 1.5: "Affine smell" tests (basepoint dependence / 2nd derivative) ======
def _rand_delta(width: int) -> int:
    # mostly single-bit; sometimes multi-bit to avoid limited-direction artifacts
    if secrets.randbelow(10) < 7:
        return 1 << secrets.randbelow(width)
    return secrets.randbits(width) & ((1 << width) - 1)

def _apply_delta(mode: str, h: int, x: int, delta: int, width: int) -> Tuple[int, int]:
    """
    Apply XOR delta to either x or h, respecting their natural widths.
    - x is treated as 'width' bits (realistic: 136) when mode == 'x'
    - h is treated as 130 bits (P1 range) when mode == 'h'
    """
    if mode == "x":
        return h, x ^ (delta & ((1 << width) - 1))
    if mode == "h":
        # only flip within 130-bit range (h lives in Z_{P1})
        dh = delta & ((1 << 130) - 1)
        return (h ^ dh) % P1, x
    raise ValueError("mode must be 'x' or 'h'")

def affine_basepoint_invariance_test(
    mode: str,
    key_samples: int = 50,
    pairs_per_key: int = 50,
    deltas_per_pair: int = 64,
    full_width: bool = False,
) -> None:
    """
    For an affine function f over XOR, the first derivative is basepoint-independent:
      f(z⊕d) ⊕ f(z) == f(z'⊕d) ⊕ f(z')   for all z,z',d
    We estimate how often this holds.
    """
    width = 256 if full_width else (136 if mode == "x" else 130)
    total = 0
    equal = 0

    for _k in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)
        for _p in range(pairs_per_key):
            h0 = sample_hash_value()
            x0 = sample_x_block_full256() if full_width else sample_x_block_realistic()
            h1 = sample_hash_value()
            x1 = sample_x_block_full256() if full_width else sample_x_block_realistic()

            f0 = h_core_bits(h0, x0, kp)
            f1 = h_core_bits(h1, x1, kp)

            for _t in range(deltas_per_pair):
                d = _rand_delta(width)
                hh0, xx0 = _apply_delta(mode, h0, x0, d, width)
                hh1, xx1 = _apply_delta(mode, h1, x1, d, width)

                g0 = h_core_bits(hh0, xx0, kp) ^ f0
                g1 = h_core_bits(hh1, xx1, kp) ^ f1

                total += 1
                if g0 == g1:
                    equal += 1

    rate = equal / total if total else 0.0
    print("\n=== Affine smell: basepoint invariance of 1st derivative ===")
    print(f"mode={mode} width={width} full_width={full_width}")
    print(f"total={total}  equal={equal}  rate={rate:.6e}")

def affine_second_derivative_test(
    mode: str,
    key_samples: int = 50,
    points_per_key: int = 50,
    trials_per_point: int = 64,
    full_width: bool = False,
) -> None:
    """
    For an affine function f over XOR, the 2nd derivative is identically 0:
      f(z) ⊕ f(z⊕a) ⊕ f(z⊕b) ⊕ f(z⊕a⊕b) == 0
    We estimate P[2nd-derivative == 0].
    """
    width = 256 if full_width else (136 if mode == "x" else 130)
    total = 0
    zeros = 0

    for _k in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)
        for _p in range(points_per_key):
            h0 = sample_hash_value()
            x0 = sample_x_block_full256() if full_width else sample_x_block_realistic()
            f = h_core_bits(h0, x0, kp)

            for _t in range(trials_per_point):
                a = _rand_delta(width)
                b = _rand_delta(width)

                h_a, x_a = _apply_delta(mode, h0, x0, a, width)
                h_b, x_b = _apply_delta(mode, h0, x0, b, width)
                h_ab, x_ab = _apply_delta(mode, h0, x0, a ^ b, width)

                v = f ^ h_core_bits(h_a, x_a, kp) ^ h_core_bits(h_b, x_b, kp) ^ h_core_bits(h_ab, x_ab, kp)
                total += 1
                if v == 0:
                    zeros += 1

    rate = zeros / total if total else 0.0
    print("\n=== Affine smell: 2nd derivative zero-rate ===")
    print(f"mode={mode} width={width} full_width={full_width}")
    print(f"total={total}  zeros={zeros}  rate={rate:.6e}")

def second_derivative_zero_diagnose(
    mode: str,
    key_samples: int = 10,
    points_per_key: int = 10,
    trials_per_point: int = 256,
    full_width: bool = False,
    print_examples: int = 5,
) -> None:
    """
    Diagnose why 2nd-derivative hits 0 too often.
    Prints:
    - overall zero-rate
    - split by whether (a,b) are single-bit or multi-bit deltas
    - bit-position histogram when zeros happen with single-bit deltas
    """
    width = 256 if full_width else (136 if mode == "x" else 130)

    total = 0
    zeros = 0
    zeros_sb = 0      # both deltas single-bit (including a==b)
    total_sb = 0
    zeros_sb_eq = 0   # a==b (single-bit)
    total_sb_eq = 0
    zeros_sb_neq = 0  # a!=b (single-bit)
    total_sb_neq = 0
    zeros_mm = 0      # at least one delta multi-bit
    total_mm = 0

    # histograms for single-bit a/b positions when v==0
    hist_a = Counter()
    hist_b = Counter()

    examples_left = print_examples

    for _k in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)

        for _p in range(points_per_key):
            h0 = sample_hash_value()
            x0 = sample_x_block_full256() if full_width else sample_x_block_realistic()
            f = h_core_bits(h0, x0, kp)

            for _t in range(trials_per_point):
                a = _rand_delta(width)
                b = _rand_delta(width)

                # classify delta types cheaply
                a_is_single = (a != 0) and ((a & (a - 1)) == 0)
                b_is_single = (b != 0) and ((b & (b - 1)) == 0)
                is_sb = a_is_single and b_is_single

                # Avoid the trivial 2nd-derivative cancellation when a==b:
                #   f(z)⊕f(z⊕a)⊕f(z⊕a)⊕f(z) == 0 always.
                # We still count (a==b) separately for sanity, but for the
                # main "is there structure?" signal we enforce a!=b in the
                # single-bit regime by resampling b.
                if is_sb and a == b:
                    total_sb_eq += 1
                    # resample b until it's a different single-bit delta
                    # (bounded expected time: ~width/(width-1))
                    while True:
                        b2 = 1 << secrets.randbelow(width)
                        if b2 != a:
                            b = b2
                            break
                    # after this, we're in single-bit a!=b case
                    total_sb_neq += 1
                elif is_sb:
                    total_sb_neq += 1

                if is_sb:
                    total_sb += 1
                else:
                    total_mm += 1

                h_a, x_a = _apply_delta(mode, h0, x0, a, width)
                h_b, x_b = _apply_delta(mode, h0, x0, b, width)
                h_ab, x_ab = _apply_delta(mode, h0, x0, a ^ b, width)

                v = f ^ h_core_bits(h_a, x_a, kp) ^ h_core_bits(h_b, x_b, kp) ^ h_core_bits(h_ab, x_ab, kp)

                total += 1
                if v == 0:
                    zeros += 1
                    if is_sb:
                        zeros_sb += 1
                        if a_is_single and b_is_single and a == b:
                            zeros_sb_eq += 1
                        else:
                            zeros_sb_neq += 1
                            hist_a[(a.bit_length() - 1)] += 1
                            hist_b[(b.bit_length() - 1)] += 1
                    else:
                        zeros_mm += 1

                    if examples_left > 0:
                        examples_left -= 1
                        print("\n[example v==0]")
                        print(f"mode={mode} width={width} full_width={full_width}")
                        print(f"h0={h0}")
                        print(f"x0={x0}")
                        print(f"a={a:#x}  b={b:#x}  a_is_single={a_is_single}  b_is_single={b_is_single}")

    def _rate(z: int, t: int) -> float:
        return z / t if t else 0.0

    print("\n=== 2nd-derivative zero DIAGNOSE ===")
    print(f"mode={mode} width={width} full_width={full_width}")
    print(f"keys={key_samples} points_per_key={points_per_key} trials_per_point={trials_per_point}")
    print(f"total={total} zeros={zeros} rate={_rate(zeros,total):.6e}")
    print(f"[single-bit a,b] total={total_sb} zeros={zeros_sb} rate={_rate(zeros_sb,total_sb):.6e}")
    print(f"  [single-bit a==b] total={total_sb_eq} zeros={zeros_sb_eq} rate={_rate(zeros_sb_eq,total_sb_eq):.6e}")
    print(f"  [single-bit a!=b] total={total_sb_neq} zeros={zeros_sb_neq} rate={_rate(zeros_sb_neq,total_sb_neq):.6e}")
    print(f"[multi-bit (else)] total={total_mm} zeros={zeros_mm} rate={_rate(zeros_mm,total_mm):.6e}")

    if hist_a:
        print("\n[top single-bit positions when v==0]")
        print("a_bit : count   | b_bit : count")
        topa = hist_a.most_common(10)
        topb = hist_b.most_common(10)
        for i in range(max(len(topa), len(topb))):
            la = f"{topa[i][0]:5d}:{topa[i][1]:6d}" if i < len(topa) else " " * 12
            lb = f"{topb[i][0]:5d}:{topb[i][1]:6d}" if i < len(topb) else ""
            print(f"{la}  | {lb}")

def linear_distinguisher_mask_search(
    mode: str,
    *,
    key_samples: int = 1,
    dataset_size: int = 4_000,
    mask_trials: int = 2_000,
    full_width: bool = False,
    seed: int = 123456,
) -> None:
    """
    Try a simple PPT-style distinguisher family:
      predict bit = parity(in_mask & input_bits) XOR parity(out_mask & output_bits)
    For a random function with random data, this should be ~ unbiased (0.5).
    We do mask search on a train split, then validate best mask on holdout
    to avoid "winner's curse" overfitting.
    """
    rng = random.Random(seed)
    width = 256 if full_width else (136 if mode == "x" else 130)

    def sample_point() -> Tuple[int, int]:
        h0 = sample_hash_value()
        x0 = sample_x_block_full256() if full_width else sample_x_block_realistic()
        y = h_core_bits(h0, x0, kp)  # 256-bit output material
        inp = (x0 & ((1 << width) - 1)) if mode == "x" else (h0 & ((1 << width) - 1))
        return inp, y

    print("\n=== Linear distinguisher mask-search (train/holdout) ===")
    print(f"mode={mode} width={width} dataset_size={dataset_size} mask_trials={mask_trials} key_samples={key_samples}")

    for ks in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)

        data = [sample_point() for _ in range(dataset_size)]
        mid = dataset_size // 2
        train = data[:mid]
        test = data[mid:]

        best = None  # (abs_bias, in_bit, out_bit, p1_train, z_train)

        # Pre-pack train/test bits as bitsets (Python int) for fast evaluation:
        # ones_count = popcnt( in_bits[in_bit] XOR out_bits[out_bit] )
        N = len(train)
        N2 = len(test)
        in_bits_train = [0] * width
        out_bits_train = [0] * 256
        in_bits_test = [0] * width
        out_bits_test = [0] * 256

        for i, (inp, out) in enumerate(train):
            # input bits: iterate only set bits (faster than scanning width)
            t = inp & ((1 << width) - 1)
            while t:
                lsb = t & -t
                b = lsb.bit_length() - 1
                in_bits_train[b] |= (1 << i)
                t ^= lsb

            # output bits: iterate only set bits (avg ~128) instead of scanning 256
            o = out & MASK_256
            while o:
                lsb = o & -o
                b = lsb.bit_length() - 1
                out_bits_train[b] |= (1 << i)
                o ^= lsb

        for i, (inp, out) in enumerate(test):
            t = inp & ((1 << width) - 1)
            while t:
                lsb = t & -t
                b = lsb.bit_length() - 1
                in_bits_test[b] |= (1 << i)
                t ^= lsb

            o = out & MASK_256
            while o:
                lsb = o & -o
                b = lsb.bit_length() - 1
                out_bits_test[b] |= (1 << i)
                o ^= lsb

        std = (0.25 / N) ** 0.5
        std2 = (0.25 / N2) ** 0.5

        # search simple 1-bit vs 1-bit linear distinguishers on train (fast bitset form)
        for _t in range(mask_trials):
            in_bit = rng.randrange(width)
            out_bit = rng.randrange(256)

            ones = (in_bits_train[in_bit] ^ out_bits_train[out_bit]).bit_count()
            p1 = ones / N
            bias = abs(p1 - 0.5)
            z = (p1 - 0.5) / std

            if best is None or bias > best[0]:
                best = (bias, in_bit, out_bit, p1, z)

        assert best is not None
        bias, in_bit, out_bit, p1_train, z_train = best

        # validate on holdout
        ones = (in_bits_test[in_bit] ^ out_bits_test[out_bit]).bit_count()
        p1_test = ones / N2
        bias_test = abs(p1_test - 0.5)
        z_test = (p1_test - 0.5) / std2

        # expected extreme bias scale for random after searching M masks on train:
        # roughly sqrt(log(2M)/(2N)) (very rough); we report it for calibration.
        expected_extreme = math.sqrt(max(1.0, math.log(2.0 * mask_trials)) / (2.0 * N))

        print(f"\n-- key[{ks}] --")
        print(f"train: N={len(train)}  best_bias={bias:.6f}  p1={p1_train:.6f}  z={z_train:+.2f}  expected_extreme~{expected_extreme:.6f}")
        print(f"test : N={len(test)}   bias={bias_test:.6f}  p1={p1_test:.6f}  z={z_test:+.2f}")
        print(f"best_in_bit  = {in_bit}")
        print(f"best_out_bit = {out_bit}")

# ====== Differential distinguisher search (train/holdout) ======
def _collect_bit_counts_256(values: List[int]) -> List[int]:
    """Return per-bit 1-counts for 256-bit ints (little-endian byte order)."""
    ones = [0] * 256
    for v in values:
        bs = (v & MASK_256).to_bytes(32, "little")
        for bi in range(32):
            lut = _BIT_LUT[bs[bi]]
            base = bi * 8
            ones[base + 0] += lut[0]
            ones[base + 1] += lut[1]
            ones[base + 2] += lut[2]
            ones[base + 3] += lut[3]
            ones[base + 4] += lut[4]
            ones[base + 5] += lut[5]
            ones[base + 6] += lut[6]
            ones[base + 7] += lut[7]
    return ones

def _collect_bit_counts_selected(values: List[int], bit_indices: List[int]) -> List[int]:
    """
    Return 1-counts for selected output bit indices (subset of [0..255]).
    Output list aligns with bit_indices order.
    """
    by_byte: Dict[int, List[int]] = {}
    for j, b in enumerate(bit_indices):
        if not (0 <= b < 256):
            raise ValueError("bit index out of range")
        by_byte.setdefault(b // 8, []).append(j)

    ones = [0] * len(bit_indices)
    for v in values:
        bs = (v & MASK_256).to_bytes(32, "little")
        for byte_i, slots in by_byte.items():
            lut = _BIT_LUT[bs[byte_i]]
            base = byte_i * 8
            for j in slots:
                bit = bit_indices[j] - base
                ones[j] += lut[bit]
    return ones

def _apply_delta_point(
    mode: str,
    h: int,
    x: int,
    delta: int,
    width: int,
    diff_type: str,
) -> Tuple[int, int]:
    """
    Apply delta to the input point (h,x) under chosen difference model.
    - diff_type='xor': xor within width bits (x) / 130 bits (h)
    - diff_type='add': add within width bits (x) / mod P1 (h)
    """
    if diff_type == "xor":
        return _apply_delta(mode, h, x, delta, width)
    if diff_type == "add":
        if mode == "x":
            mask = (1 << width) - 1
            x2 = (x + (delta & mask)) & mask
            return h, x2
        if mode == "h":
            dh = delta & ((1 << 130) - 1)
            return (h + dh) % P1, x
        raise ValueError("mode must be 'x' or 'h'")
    raise ValueError("diff_type must be 'xor' or 'add'")

def diff_distinguisher_search(
    mode: str,
    *,
    key_samples: int = 2,
    points_train: int = 150,
    points_test: int = 150,
    deltas: int = 64,
    diff_type: str = "xor",
    out_diff: str = "xor",  # 'xor' or 'sub' (for additive-style output diff)
    seed: int = 123456,
    full_width: bool = False,
    out_bits: Optional[List[int]] = None,
) -> None:
    """
    Search for a simple differential distinguisher:
      choose delta (in input space), look at du = f(z') XOR f(z)  (or sub mod P2),
      find an output bit with bias on train, validate on test.

    This is closer to a real PPT distinguisher than avalanche stats because it tries
    to *learn* the best delta/bit pair (train) and then confirm it generalizes (holdout).
    """
    rng = random.Random(seed)
    width = 256 if full_width else (136 if mode == "x" else 130)

    # build candidate delta set: mostly single-bit deltas, plus some multi-bit
    cand: List[int] = []
    for _ in range(deltas):
        if rng.randrange(10) < 8:
            cand.append(1 << rng.randrange(width))
        else:
            cand.append(rng.getrandbits(width) & ((1 << width) - 1))

    print("\n=== Differential distinguisher search (train/holdout) ===")
    print(f"mode={mode} width={width} diff_type={diff_type} out_diff={out_diff}")
    print(f"key_samples={key_samples} train={points_train} test={points_test} deltas={len(cand)}")

    for ks in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)

        # sample points
        pts_train = [(sample_hash_value(), sample_x_block_full256() if full_width else sample_x_block_realistic()) for _ in range(points_train)]
        pts_test = [(sample_hash_value(), sample_x_block_full256() if full_width else sample_x_block_realistic()) for _ in range(points_test)]

        # cache base outputs (u_bits)
        base_train = [h_core_bits(h, x, kp) for (h, x) in pts_train]
        base_test = [h_core_bits(h, x, kp) for (h, x) in pts_test]

        best = None  # (abs_bias, delta, out_bit, p1_train, z_train)

        bit_space = out_bits if out_bits is not None else list(range(256))
        bit_index_map = {b: i for i, b in enumerate(bit_space)}

        for d in cand:
            # compute du samples for train
            du_train: List[int] = []
            for (h, x), u0 in zip(pts_train, base_train):
                h2, x2 = _apply_delta_point(mode, h, x, d, width, diff_type)
                u1 = h_core_bits(h2, x2, kp)
                if out_diff == "xor":
                    du = (u1 ^ u0) & MASK_256
                elif out_diff == "sub":
                    du = ((u1 - u0) % P2) & MASK_256
                else:
                    raise ValueError("out_diff must be 'xor' or 'sub'")
                du_train.append(du)

            if out_bits is None:
                ones = _collect_bit_counts_256(du_train)
            else:
                ones = _collect_bit_counts_selected(du_train, bit_space)
            N = len(du_train)
            std = (0.25 / N) ** 0.5

            # pick best output bit for this delta
            for out_bit in bit_space:
                idx = out_bit if out_bits is None else bit_index_map[out_bit]
                p1 = ones[idx] / N
                bias = abs(p1 - 0.5)
                z = (p1 - 0.5) / std
                if best is None or bias > best[0]:
                    best = (bias, d, out_bit, p1, z)

        assert best is not None
        bias, d_best, out_bit_best, p1_train, z_train = best

        # validate on test
        du_test: List[int] = []
        for (h, x), u0 in zip(pts_test, base_test):
            h2, x2 = _apply_delta_point(mode, h, x, d_best, width, diff_type)
            u1 = h_core_bits(h2, x2, kp)
            if out_diff == "xor":
                du = (u1 ^ u0) & MASK_256
            else:
                du = ((u1 - u0) % P2) & MASK_256
            du_test.append(du)

        N2 = len(du_test)
        if out_bits is None:
            ones_test = _collect_bit_counts_256(du_test)
            p1_test = ones_test[out_bit_best] / N2
        else:
            ones_test = _collect_bit_counts_selected(du_test, bit_space)
            p1_test = ones_test[bit_index_map[out_bit_best]] / N2
        bias_test = abs(p1_test - 0.5)
        std2 = (0.25 / N2) ** 0.5
        z_test = (p1_test - 0.5) / std2

        # calibration: expected max bias over 256*deltas bits in pure noise
        M = len(bit_space) * len(cand)
        expected_extreme = math.sqrt(max(1.0, math.log(2.0 * M)) / (2.0 * points_train))

        print(f"\n-- key[{ks}] --")
        print(f"train: N={points_train}  best_bias={bias:.6f}  p1={p1_train:.6f}  z={z_train:+.2f}  expected_extreme~{expected_extreme:.6f}")
        print(f"test : N={points_test}   bias={bias_test:.6f}  p1={p1_test:.6f}  z={z_test:+.2f}")
        print(f"best_delta = {d_best:#x}")
        print(f"best_out_bit = {out_bit_best}")

def _trunc_bitsets() -> Dict[str, List[int]]:
    """
    Common truncated observation sets (bit indices in [0..255]).
    - low64: bits [0..63]
    - low128: bits [0..127]
    - clamp_r_bits: bits in low128 that survive Poly1305 clamp mask
    """
    low64 = list(range(64))
    low128 = list(range(128))
    clamp_mask = 0x0ffffffc0ffffffc0ffffffc0fffffff
    clamp_bits = [i for i in range(128) if (clamp_mask >> i) & 1]
    return {"low64": low64, "low128": low128, "clamp_r_bits": clamp_bits}

def integral_xorsum_test(
    mode: str,
    *,
    key_samples: int = 2,
    basepoints_per_key: int = 32,
    k_active: int = 10,
    active_sets: int = 4,
    seed: int = 123456,
    full_width: bool = False,
) -> None:
    """
    Very basic integral-style test (PPT-ish):
    - choose k_active input bit positions (in x or h domain)
    - enumerate all 2^k_active masks, compute y = f(z with active bits toggled)
    - compute XOR-sum of outputs over the cube for each output bit
    For a random boolean function, each output bit's cube XOR-sum is 0 with prob ~1/2.
    If some bits are *systematically balanced* across many random basepoints/active-sets,
    that is a red flag.
    """
    rng = random.Random(seed)
    width = 256 if full_width else (136 if mode == "x" else 130)
    if k_active <= 0 or k_active > min(20, width):
        raise ValueError("k_active too large for this quick integral test")

    print("\n=== Integral (cube XOR-sum) quick test ===")
    print(f"mode={mode} width={width} k_active={k_active} active_sets={active_sets} basepoints_per_key={basepoints_per_key} key_samples={key_samples}")

    for ks in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)

        # pick several active-bit sets
        sets = []
        for _ in range(active_sets):
            # sample distinct bit positions
            pos = rng.sample(range(width), k_active)
            sets.append(pos)

        # statistics: for each out bit, how often cube-xorsum == 0
        total_cubes = 0
        zeros = [0] * 256

        for pos in sets:
            # precompute basis deltas for active bits
            basis = [1 << p for p in pos]

            for _bp in range(basepoints_per_key):
                h0 = sample_hash_value()
                x0 = sample_x_block_full256() if full_width else sample_x_block_realistic()

                # enumerate cube
                acc = 0
                for mask in range(1 << k_active):
                    d = 0
                    # build delta from basis bits
                    # (k_active <= 10 by default, so this loop is cheap)
                    for i in range(k_active):
                        if (mask >> i) & 1:
                            d ^= basis[i]

                    if mode == "x":
                        y = h_core_bits(h0, x0 ^ d, kp)
                    else:
                        # flip only within 130-bit domain (h in Z_P1)
                        y = h_core_bits((h0 ^ d) % P1, x0, kp)
                    acc ^= y

                total_cubes += 1
                # update per-bit zero counts
                # acc_bit==0 means the XOR-sum for that bit is 0
                a = acc & MASK_256
                for b in range(256):
                    if ((a >> b) & 1) == 0:
                        zeros[b] += 1

        # summarize worst deviations from 1/2
        N = total_cubes
        # expected sigma for Bernoulli(0.5)
        std = math.sqrt(0.25 / N) if N else 0.0
        worst = None
        max_bias = 0.0
        for b in range(256):
            p0 = zeros[b] / N
            bias = abs(p0 - 0.5)
            if bias > max_bias:
                max_bias = bias
                worst = (b, p0)

        wb, p0 = worst
        z = (p0 - 0.5) / std if std else 0.0
        print(f"\n-- key[{ks}] -- cubes={N}")
        print(f"worst_bit={wb}  P[cube_xorsum_bit==0]={p0:.6f}  bias={max_bias:.6f}  z={z:+.2f}")

def integral_holdout_search(
    mode: str,
    *,
    key_samples: int = 2,
    candidate_sets: int = 8,
    k_active: int = 10,
    train_basepoints: int = 16,
    test_basepoints: int = 16,
    seed: int = 123456,
    full_width: bool = False,
) -> None:
    """
    Integral distinguisher (train/holdout):
    - sample candidate active-bit sets S_j (size k_active)
    - for each set, sample train_basepoints random basepoints z
      and compute cube XOR-sum acc(z,S_j) = XOR_{u in {0,1}^k} f(z ⊕ (u·S_j))
    - treat each output bit of acc as a Bernoulli for "acc_bit == 0"
      (under a random function this should be ~0.5)
    - pick best (set, out_bit) on train, then validate on holdout basepoints
    """
    rng = random.Random(seed)
    width = 256 if full_width else (136 if mode == "x" else 130)
    if k_active <= 0 or k_active > min(12, width):
        raise ValueError("k_active too large for holdout integral test")

    print("\n=== Integral distinguisher (cube XOR-sum) search (train/holdout) ===")
    print(
        f"mode={mode} width={width} k_active={k_active} "
        f"candidate_sets={candidate_sets} train_basepoints={train_basepoints} test_basepoints={test_basepoints} "
        f"key_samples={key_samples}"
    )

    def cube_acc_values(kp: Tuple[int, int, int, int], pos: List[int], basepoints: List[Tuple[int, int]]) -> List[int]:
        basis = [1 << p for p in pos]
        out: List[int] = []
        for h0, x0 in basepoints:
            acc = 0
            # Enumerate the cube via Gray code so we flip only one active bit per step.
            # This avoids an inner O(k_active) loop per mask.
            d = 0
            prev_g = 0
            for m in range(1 << k_active):
                g = m ^ (m >> 1)
                if m != 0:
                    diff = prev_g ^ g  # exactly one bit set
                    idx = diff.bit_length() - 1
                    d ^= basis[idx]
                prev_g = g
                if mode == "x":
                    y = h_core_bits(h0, x0 ^ d, kp)
                else:
                    y = h_core_bits((h0 ^ d) % P1, x0, kp)
                acc ^= y
            out.append(acc & MASK_256)
        return out

    for ks in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)

        # candidate active-bit sets
        sets: List[List[int]] = [rng.sample(range(width), k_active) for _ in range(candidate_sets)]

        # train/test basepoints
        train_pts = [(sample_hash_value(), sample_x_block_full256() if full_width else sample_x_block_realistic()) for _ in range(train_basepoints)]
        test_pts = [(sample_hash_value(), sample_x_block_full256() if full_width else sample_x_block_realistic()) for _ in range(test_basepoints)]

        best = None  # (abs_bias, set_idx, out_bit, p0_train, z_train)
        N = train_basepoints
        std = math.sqrt(0.25 / N) if N else 0.0

        for j, pos in enumerate(sets):
            acc_train = cube_acc_values(kp, pos, train_pts)
            ones = _collect_bit_counts_256(acc_train)
            # p0 = P[acc_bit == 0] = 1 - p1
            for out_bit in range(256):
                p0 = 1.0 - (ones[out_bit] / N)
                bias = abs(p0 - 0.5)
                z = (p0 - 0.5) / std if std else 0.0
                if best is None or bias > best[0]:
                    best = (bias, j, out_bit, p0, z)

        assert best is not None
        bias, j_best, out_bit_best, p0_train, z_train = best

        # validate
        acc_test = cube_acc_values(kp, sets[j_best], test_pts)
        ones_t = _collect_bit_counts_256(acc_test)
        N2 = test_basepoints
        p0_test = 1.0 - (ones_t[out_bit_best] / N2)
        bias_test = abs(p0_test - 0.5)
        std2 = math.sqrt(0.25 / N2) if N2 else 0.0
        z_test = (p0_test - 0.5) / std2 if std2 else 0.0

        # calibration: expected extreme over M = 256*candidate_sets
        M = 256 * candidate_sets
        expected_extreme = math.sqrt(max(1.0, math.log(2.0 * M)) / (2.0 * N)) if N else 0.0

        print(f"\n-- key[{ks}] --")
        print(f"train: N={N}  best_bias={bias:.6f}  P0={p0_train:.6f}  z={z_train:+.2f}  expected_extreme~{expected_extreme:.6f}")
        print(f"test : N={N2}  bias={bias_test:.6f}  P0={p0_test:.6f}  z={z_test:+.2f}")
        print(f"best_set_idx={j_best}  best_out_bit={out_bit_best}")

# ====== Sampling realistic-ish inputs ======
def sample_hash_value() -> int:
    # state h normally lives in Z_{P1}
    return secrets.randbelow(P1)

def sample_x_block_realistic() -> int:
    # Poly1305-style block: 16 bytes + 0x01 => up to ~136 bits
    return secrets.randbits(136)

def sample_x_block_full256() -> int:
    return secrets.randbits(256)

class StatsSmellSuite:
    """
    统计/气味测试集合（不等价于“区别器”）。
    目的：发现明显结构红旗/实现错误，而不是证明 PRF/抗区分。

    注意：为了避免“统计测试”干扰真正的区分器实验：
    - 这个类只包含 span-rank / avalanche / bit-bias / collision / stability 这类统计项
    - 正统的区别器（差分/线性/仿射等）保持为独立函数，并由 CLI 显式触发
    """

    def __init__(self, *, full_width: bool = False) -> None:
        self.full_width = full_width

    def run_span_rank(self, *, heavy: bool) -> None:
        if heavy:
            x_trials = [64, 128, 256, 512, 1024]
            h_trials = [64, 128, 256, 512, 1024]
            key_samples = 200
            points_per_key = 5
        else:
            x_trials = [64, 128, 256, 512]
            h_trials = [64, 128, 256, 512]
            key_samples = 50
            points_per_key = 2

        span_rank_under_random_deltas(
            mode="x",
            key_samples=key_samples,
            points_per_key=points_per_key,
            trials_list=x_trials,
            full_width=self.full_width,
        )
        span_rank_under_random_deltas(
            mode="h",
            key_samples=key_samples,
            points_per_key=points_per_key,
            trials_list=h_trials,
            full_width=self.full_width,
        )

        span_rank_all_single_bits(
            mode="x",
            key_samples=50 if not heavy else 200,
            points_per_key=2 if not heavy else 5,
        )
        span_rank_all_single_bits(
            mode="h",
            key_samples=50 if not heavy else 200,
            points_per_key=2 if not heavy else 5,
        )

    def run_avalanche(self, *, heavy: bool) -> None:
        avalanche_test(
            "x",
            key_samples=50 if not heavy else 200,
            trials_per_key=50 if not heavy else 200,
            full_width=self.full_width,
        )
        avalanche_test(
            "h",
            key_samples=50 if not heavy else 200,
            trials_per_key=50 if not heavy else 200,
            full_width=self.full_width,
        )

    def run_bit_bias(self, *, heavy: bool) -> None:
        bit_bias_test(
            key_samples=10 if not heavy else 30,
            outputs_per_key=1000 if not heavy else 2000,
            full_width=self.full_width,
        )

    def run_collision(self, *, heavy: bool) -> None:
        collision_sanity(
            key_samples=5 if not heavy else 10,
            outputs_per_key=2000 if not heavy else 5000,
            full_width=self.full_width,
        )

    def run_bias_stability_heavy(self) -> None:
        # Heavy: you want "stability conclusions" (takes longer).
        bit_bias_stability_test(
            key_samples=5,
            repeats_per_key=10,
            outputs_per_repeat=1_000_000,
            topk=10,
            base_seed=123456,
            full_width=self.full_width,
        )

    def run(self, *, heavy: bool) -> None:
        self.run_span_rank(heavy=heavy)
        self.run_avalanche(heavy=heavy)
        self.run_bit_bias(heavy=heavy)
        self.run_collision(heavy=heavy)
        if heavy:
            self.run_bias_stability_heavy()


# ====== Test 1: Jacobian span-rank (XOR-derivative) ======
def span_rank_under_random_deltas(
    mode: str,
    key_samples: int,
    points_per_key: int,
    trials_list: List[int],
    full_width: bool = False,
) -> None:
    """
    Compute rank of span{ f(z xor delta_i) xor f(z) } over GF(2)^256
    - mode: "x" or "h"
    - deltas: random (single-bit + occasional multi-bit) masks
    """
    width = 256 if full_width else (256 if mode == "h" else 136)
    print(f"\n=== Span-rank under random deltas ===")
    print(f"P2 mode: {'exact P2' if P2 is not None else 'mod 2^256 fallback'}")
    print(f"mode={mode}  full_width={full_width}  width={width}")
    print(f"Key samples: {key_samples}  points_per_key: {points_per_key}")
    print(f"Trials list: {trials_list}\n")

    for trials in trials_list:
        ranks = []
        for _k in range(key_samples):
            key32 = secrets.token_bytes(32)
            kp = derive_key_params_latest(key32)

            for _p in range(points_per_key):
                h0 = sample_hash_value()
                x0 = sample_x_block_full256() if full_width else sample_x_block_realistic()
                base = h_core_bits(h0, x0, kp)

                vecs = []
                for t in range(trials):
                    # mix: mostly single-bit, sometimes multi-bit to avoid "limited direction" artifacts
                    if t < min(width, 256):
                        bit = secrets.randbelow(width)
                        delta = 1 << bit
                    else:
                        delta = secrets.randbits(256) & MASK_256

                    if mode == "x":
                        y = h_core_bits(h0, x0 ^ delta, kp) ^ base
                    elif mode == "h":
                        y = h_core_bits((h0 ^ (delta & ((1<<130)-1))) % P1, x0, kp) ^ base
                    else:
                        raise ValueError("mode must be 'x' or 'h'")

                    vecs.append(y & MASK_256)

                ranks.append(gf2_rank(vecs))

        ranks.sort()
        n = len(ranks)
        avg = sum(ranks) / n if n else 0.0
        p10 = ranks[int(0.10 * (n-1))] if n else 0
        p50 = ranks[int(0.50 * (n-1))] if n else 0
        p90 = ranks[int(0.90 * (n-1))] if n else 0
        mx = ranks[-1] if n else 0

        print(f"[trials={trials:4d}] avg={avg:.2f}  p10={p10}  p50={p50}  p90={p90}  max={mx}")

def span_rank_singlebit_only(
    mode: str,
    key_samples: int,
    points_per_key: int,
    trials: int,
) -> None:
    if mode == "x":
        width = 136
    elif mode == "h":
        width = 130
    else:
        raise ValueError("mode must be 'x' or 'h'")

    trials = min(trials, width)

    ranks = []
    for _k in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)

        for _p in range(points_per_key):
            h0 = sample_hash_value()
            x0 = sample_x_block_realistic()
            base = h_core_bits(h0, x0, kp)

            vecs = []
            for _t in range(trials):
                bit = secrets.randbelow(width)
                delta = 1 << bit

                if mode == "x":
                    y = h_core_bits(h0, x0 ^ delta, kp) ^ base
                else:
                    # flip only within 130-bit range
                    h1 = (h0 ^ (delta & ((1<<130)-1))) % P1
                    y = h_core_bits(h1, x0, kp) ^ base

                vecs.append(y & MASK_256)

            ranks.append(gf2_rank(vecs))

    ranks.sort()
    n = len(ranks)
    avg = sum(ranks)/n
    p50 = ranks[n//2]
    mx = ranks[-1]
    print(f"\n=== Single-bit span rank ===")
    print(f"mode={mode} trials={trials} (cap={width})  samples={n}")
    print(f"avg={avg:.2f}  p50={p50}  max={mx}")

def span_rank_all_single_bits(
    mode: str,
    key_samples: int,
    points_per_key: int,
) -> None:
    if mode == "x":
        width = 136
    elif mode == "h":
        width = 130
    else:
        raise ValueError("mode must be 'x' or 'h'")

    ranks = []
    for _k in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)

        for _p in range(points_per_key):
            h0 = sample_hash_value()
            x0 = sample_x_block_realistic()
            base = h_core_bits(h0, x0, kp)

            vecs = []
            for bit in range(width):
                delta = 1 << bit
                if mode == "x":
                    y = h_core_bits(h0, x0 ^ delta, kp) ^ base
                else:
                    h1 = (h0 ^ delta) % P1
                    y = h_core_bits(h1, x0, kp) ^ base
                vecs.append(y & MASK_256)

            ranks.append(gf2_rank(vecs))

    ranks.sort()
    n = len(ranks)
    avg = sum(ranks) / n
    p50 = ranks[n//2]
    mx = ranks[-1]
    print(f"\n=== All-single-bit span rank ===")
    print(f"mode={mode} width={width} samples={n}")
    print(f"avg={avg:.2f} p50={p50} max={mx}")


# ====== Test 2: Avalanche (bit flip) ======
def avalanche_test(
    which: str,
    key_samples: int = 200,
    trials_per_key: int = 200,
    full_width: bool = False,
) -> None:
    """
    Flip ONE random bit in x or h, measure output Hamming distance.
    """
    width = 256 if full_width else (136 if which == "x" else 130)

    dists = []
    for _k in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)

        for _t in range(trials_per_key):
            h0 = sample_hash_value()
            x0 = sample_x_block_full256() if full_width else sample_x_block_realistic()
            out0 = h_core_bits(h0, x0, kp)

            bit = secrets.randbelow(width)
            delta = 1 << bit

            if which == "x":
                out1 = h_core_bits(h0, x0 ^ delta, kp)
            elif which == "h":
                h1 = (h0 ^ delta) % P1
                out1 = h_core_bits(h1, x0, kp)
            else:
                raise ValueError("which must be 'x' or 'h'")

            dists.append(popcnt256(out0 ^ out1))

    dists.sort()
    n = len(dists)
    avg = sum(dists)/n if n else 0.0
    p10 = dists[int(0.10*(n-1))] if n else 0
    p50 = dists[int(0.50*(n-1))] if n else 0
    p90 = dists[int(0.90*(n-1))] if n else 0

    print(f"\n=== Avalanche test ({which}) ===")
    print(f"full_width={full_width}  flip_width={width}  samples={n}")
    print(f"avg_hd={avg:.2f}  p10={p10}  p50={p50}  p90={p90}  min={dists[0]}  max={dists[-1]}")


# ====== Test 3: Output bit bias ======
def bit_bias_test(
    key_samples: int = 30,
    outputs_per_key: int = 2000,
    full_width: bool = False,
) -> None:
    total_outputs = key_samples * outputs_per_key
    ones = [0] * 256

    for _k in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)

        for _t in range(outputs_per_key):
            h0 = sample_hash_value()
            x0 = sample_x_block_full256() if full_width else sample_x_block_realistic()
            y = h_core_bits(h0, x0, kp)
            bs = y.to_bytes(32, "little")
            for bi in range(32):
                v = bs[bi]
                base = bi * 8
                ones[base+0] += (v >> 0) & 1
                ones[base+1] += (v >> 1) & 1
                ones[base+2] += (v >> 2) & 1
                ones[base+3] += (v >> 3) & 1
                ones[base+4] += (v >> 4) & 1
                ones[base+5] += (v >> 5) & 1
                ones[base+6] += (v >> 6) & 1
                ones[base+7] += (v >> 7) & 1

    # compute worst bit bias globally
    worst = None
    max_bias = 0.0
    for i in range(256):
        p = ones[i] / total_outputs
        bias = abs(p - 0.5)
        if bias > max_bias:
            max_bias = bias
            worst = (i, p)

    i, p = worst
    # also print a z-score (how many sigmas away from 0.5)
    # std = sqrt(0.25/N)
    std = (0.25 / total_outputs) ** 0.5
    z = (p - 0.5) / std
    print("\n=== Bit bias test (GLOBAL aggregate) ===")
    print(f"total_outputs={total_outputs}")
    print(f"worst_bit={i}  p1={p:.6f}  bias={max_bias:.6f}  z={z:.2f}")


# ====== Test 4: Collision sanity ======
def collision_sanity(
    key_samples: int = 20,
    outputs_per_key: int = 5000,
    full_width: bool = False,
) -> None:
    """
    Collisions in 256-bit at this scale should be zero. Any collision is a bug / severe structure.
    """
    print(f"\n=== Collision sanity ===")
    print(f"key_samples={key_samples}  outputs_per_key={outputs_per_key}")

    for _k in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)
        seen = set()
        collisions = 0

        for _t in range(outputs_per_key):
            h0 = sample_hash_value()
            x0 = sample_x_block_full256() if full_width else sample_x_block_realistic()
            y = h_core_bits(h0, x0, kp)
            if y in seen:
                collisions += 1
            else:
                seen.add(y)

        print(f"collisions={collisions}  unique={len(seen)} / {outputs_per_key}")


# 预计算：byte -> 8 bits（加速一点点）
_BIT_LUT = [((b >> 0) & 1, (b >> 1) & 1, (b >> 2) & 1, (b >> 3) & 1,
             (b >> 4) & 1, (b >> 5) & 1, (b >> 6) & 1, (b >> 7) & 1)
            for b in range(256)]


def _rand_hash_value(rng: random.Random) -> int:
    # h lives in Z_{P1}
    return rng.randrange(P1)

def _rand_x_block(rng: random.Random, full_width: bool) -> int:
    # realistic Poly1305-ish blocks are ~136 bits; you already do that
    return rng.getrandbits(256 if full_width else 136)

def _bit_bias_once_fixed_key(
    kp: Tuple[int,int,int,int],
    outputs: int,
    seed: int,
    full_width: bool = False,
) -> Dict[str, Any]:
    """
    固定 key(kp)，跑 outputs 次，统计每个输出 bit 的 p1/bias/z。
    返回：top bits 列表 + 全体 max_bias 等。
    """
    rng = random.Random(seed)

    ones = [0] * 256
    for _ in range(outputs):
        h0 = _rand_hash_value(rng)
        x0 = _rand_x_block(rng, full_width)
        y = h_core_bits(h0, x0, kp)
        bs = y.to_bytes(32, "little")
        for bi in range(32):
            v = bs[bi]
            base = bi * 8
            lut = _BIT_LUT[v]
            ones[base+0] += lut[0]
            ones[base+1] += lut[1]
            ones[base+2] += lut[2]
            ones[base+3] += lut[3]
            ones[base+4] += lut[4]
            ones[base+5] += lut[5]
            ones[base+6] += lut[6]
            ones[base+7] += lut[7]

    # 计算 p / bias / z
    N = outputs
    std = math.sqrt(0.25 / N)  # sigma for Bernoulli(0.5)
    p = [c / N for c in ones]
    bias = [abs(pi - 0.5) for pi in p]
    z = [(pi - 0.5) / std for pi in p]

    worst_bit = max(range(256), key=lambda i: bias[i])
    return {
        "N": N,
        "p": p,
        "bias": bias,
        "z": z,
        "worst_bit": worst_bit,
        "worst_p": p[worst_bit],
        "worst_bias": bias[worst_bit],
        "worst_z": z[worst_bit],
    }


def bit_bias_stability_test(
    key_samples: int = 3,
    repeats_per_key: int = 5,
    outputs_per_repeat: int = 1_000_000,
    topk: int = 10,
    base_seed: int = 123456,
    full_width: bool = False,
) -> None:
    """
    固定 key，多次重复抽样，看 worst/topk bits 是否“稳定”。
    - 如果每次 topk bits 都乱跳：多半是噪声极值
    - 如果总是同一小撮 bits 稳定偏：才像结构

    参数建议：
    - outputs_per_repeat: 200k~1M 起步（你机器自己选）
    - repeats_per_key: 3~10
    - key_samples: 1~5
    """
    print("\n=== Bit bias stability test (fixed-key, repeated) ===")
    print(f"key_samples={key_samples} repeats_per_key={repeats_per_key} "
          f"outputs_per_repeat={outputs_per_repeat} topk={topk} "
          f"full_width={full_width} base_seed={base_seed}")

    global_topk_counter = Counter()

    for ks in range(key_samples):
        key32 = secrets.token_bytes(32)
        kp = derive_key_params_latest(key32)

        print(f"\n-- key[{ks}] --")
        topk_counter = Counter()

        for r in range(repeats_per_key):
            seed = base_seed + ks * 10_000 + r
            res = _bit_bias_once_fixed_key(kp, outputs_per_repeat, seed, full_width=full_width)

            # 取 topk bits
            bias = res["bias"]
            p = res["p"]
            z = res["z"]

            idx = sorted(range(256), key=lambda i: bias[i], reverse=True)[:topk]
            for b in idx:
                topk_counter[b] += 1
                global_topk_counter[b] += 1

            worst = res["worst_bit"]
            print(f"  repeat={r:2d}  worst_bit={worst:3d}  p1={p[worst]:.6f}  "
                  f"bias={bias[worst]:.6f}  z={z[worst]:+.2f}")

        # 汇总：本 key 下最常出现的 topk bits
        print("  [stable top bits for this key]")
        for b, cnt in topk_counter.most_common(min(20, 256)):
            print(f"    bit={b:3d}  appearances_in_top{topk}={cnt}/{repeats_per_key}")

    # 全局汇总
    print("\n-- global stability across keys --")
    for b, cnt in global_topk_counter.most_common(30):
        denom = key_samples * repeats_per_key
        print(f"  bit={b:3d}  appearances_in_top{topk}={cnt}/{denom}")

def main() -> None:
    # CLI:
    # - 默认：只跑统计/气味测试（封装在 StatsSmellSuite，不跑任何区别器）
    # - 只跑区别器：用 --only-xxx
    # - 额外跑“仿射/差分”区别器：用 --affine
    heavy = ("--heavy" in sys.argv)
    two_min = ("--2m" in sys.argv)  # budget preset aiming for ~2 minutes per mode on a typical desktop
    only_second_deriv = ("--only-second-deriv" in sys.argv)
    only_linear = ("--only-linear" in sys.argv)
    run_affine = ("--affine" in sys.argv)
    only_diff_search = ("--only-diff-search" in sys.argv)
    only_all_basic_hard = ("--only-all-basic-hard" in sys.argv)
    only_integral_hard = ("--only-integral-hard" in sys.argv)
    only_trunc_basic = ("--only-trunc-basic" in sys.argv)

    if only_second_deriv:
        ks = 8 if two_min else 10
        ppk = 8 if two_min else 10
        tpp = 128 if two_min else 256
        pe = 0
        second_derivative_zero_diagnose(mode="x", key_samples=ks, points_per_key=ppk, trials_per_point=tpp, full_width=False, print_examples=pe)
        second_derivative_zero_diagnose(mode="h", key_samples=ks, points_per_key=ppk, trials_per_point=tpp, full_width=False, print_examples=pe)
        return

    if only_linear:
        # budget preset
        ds = 8_000 if two_min else 12_000
        mt = 8_000 if two_min else 10_000
        linear_distinguisher_mask_search(mode="x", key_samples=2, dataset_size=ds, mask_trials=mt, full_width=False, seed=123456)
        linear_distinguisher_mask_search(mode="h", key_samples=2, dataset_size=ds, mask_trials=mt, full_width=False, seed=223344)
        return
    if only_diff_search:
        # Differential distinguisher search only (no stats).
        pts = 300 if two_min else 300
        ds = 96 if two_min else 96
        diff_distinguisher_search(
            mode="x",
            key_samples=2,
            points_train=pts,
            points_test=pts,
            deltas=ds,
            diff_type="xor",
            out_diff="xor",
            seed=123456,
            full_width=False,
        )
        diff_distinguisher_search(
            mode="h",
            key_samples=2,
            points_train=pts,
            points_test=pts,
            deltas=ds,
            diff_type="xor",
            out_diff="xor",
            seed=223344,
            full_width=False,
        )
        # also try add/sub model (ARX-ish)
        diff_distinguisher_search(
            mode="x",
            key_samples=2,
            points_train=pts,
            points_test=pts,
            deltas=ds,
            diff_type="add",
            out_diff="sub",
            seed=334455,
            full_width=False,
        )
        diff_distinguisher_search(
            mode="h",
            key_samples=2,
            points_train=pts,
            points_test=pts,
            deltas=ds,
            diff_type="add",
            out_diff="sub",
            seed=445566,
            full_width=False,
        )
        return

    if only_all_basic_hard:
        # Run a "basic normalized distinguishers" battery at raised budgets:
        # - affine/2nd-derivative diagnostics
        # - linear (train/holdout)
        # - differential search (train/holdout) in XOR and ADD models
        # - integral cube XOR-sum quick test
        second_derivative_zero_diagnose(mode="x", key_samples=10, points_per_key=10, trials_per_point=256, full_width=False, print_examples=0)
        second_derivative_zero_diagnose(mode="h", key_samples=10, points_per_key=10, trials_per_point=256, full_width=False, print_examples=0)

        linear_distinguisher_mask_search(mode="x", key_samples=2, dataset_size=20_000, mask_trials=20_000, full_width=False, seed=123456)
        linear_distinguisher_mask_search(mode="h", key_samples=2, dataset_size=20_000, mask_trials=20_000, full_width=False, seed=223344)

        diff_distinguisher_search(mode="x", key_samples=2, points_train=400, points_test=400, deltas=128, diff_type="xor", out_diff="xor", seed=123456, full_width=False)
        diff_distinguisher_search(mode="h", key_samples=2, points_train=400, points_test=400, deltas=128, diff_type="xor", out_diff="xor", seed=223344, full_width=False)
        diff_distinguisher_search(mode="x", key_samples=2, points_train=400, points_test=400, deltas=128, diff_type="add", out_diff="sub", seed=334455, full_width=False)
        diff_distinguisher_search(mode="h", key_samples=2, points_train=400, points_test=400, deltas=128, diff_type="add", out_diff="sub", seed=445566, full_width=False)

        integral_holdout_search(mode="x", key_samples=2, candidate_sets=8, k_active=10, train_basepoints=16, test_basepoints=16, seed=555666, full_width=False)
        integral_holdout_search(mode="h", key_samples=2, candidate_sets=8, k_active=10, train_basepoints=16, test_basepoints=16, seed=666777, full_width=False)
        return

    if only_integral_hard:
        # Raised-budget integral-only run (no stats / no other distinguishers).
        # Note: cube size is 2^k_active, so keep k_active modest.
        # 2m preset: keep it smaller but still meaningful holdout.
        cs = 12 if two_min else 16
        tb = 24 if two_min else 32
        vb = 24 if two_min else 32
        integral_holdout_search(mode="x", key_samples=2, candidate_sets=cs, k_active=9 if two_min else 10, train_basepoints=tb, test_basepoints=vb, seed=555666, full_width=False)
        integral_holdout_search(mode="h", key_samples=2, candidate_sets=cs, k_active=8 if two_min else 9, train_basepoints=tb, test_basepoints=vb, seed=666777, full_width=False)
        return

    if only_trunc_basic:
        # Truncated-view differential distinguishers (newbie-friendly attack surface):
        # Observe only a subset of output bits (low64/low128/clamp-r bits),
        # run the same train/holdout differential search.
        obs = _trunc_bitsets()
        for name, bits in obs.items():
            print(f"\n==================== TRUNC VIEW: {name} (|bits|={len(bits)}) ====================")
            diff_distinguisher_search(
                mode="x",
                key_samples=2,
                points_train=300,
                points_test=300,
                deltas=96,
                diff_type="xor",
                out_diff="xor",
                seed=123456,
                full_width=False,
                out_bits=bits,
            )
            diff_distinguisher_search(
                mode="h",
                key_samples=2,
                points_train=300,
                points_test=300,
                deltas=96,
                diff_type="xor",
                out_diff="xor",
                seed=223344,
                full_width=False,
                out_bits=bits,
            )
        return

    # --- stats-only suite (class) ---
    StatsSmellSuite(full_width=False).run(heavy=heavy)

    # --- optional: "orthodox" distinguishers (kept outside stats suite) ---
    if run_affine:
        affine_basepoint_invariance_test(
            mode="x",
            key_samples=20 if not heavy else 50,
            pairs_per_key=20 if not heavy else 50,
            deltas_per_pair=32 if not heavy else 64,
            full_width=False,
        )
        affine_basepoint_invariance_test(
            mode="h",
            key_samples=20 if not heavy else 50,
            pairs_per_key=20 if not heavy else 50,
            deltas_per_pair=32 if not heavy else 64,
            full_width=False,
        )
        affine_second_derivative_test(
            mode="x",
            key_samples=20 if not heavy else 50,
            points_per_key=20 if not heavy else 50,
            trials_per_point=32 if not heavy else 64,
            full_width=False,
        )
        affine_second_derivative_test(
            mode="h",
            key_samples=20 if not heavy else 50,
            points_per_key=20 if not heavy else 50,
            trials_per_point=32 if not heavy else 64,
            full_width=False,
        )


if __name__ == "__main__":
    main()
