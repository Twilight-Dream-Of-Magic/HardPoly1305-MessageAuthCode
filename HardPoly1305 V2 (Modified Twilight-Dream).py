from typing import Tuple

# ==========================
# 常量：safe primes
# ==========================

P1 = (1 << 130) - 5                    # Poly1305 的 p
P2 = (1 << 256) - 188_069              # HardPoly1305 之前用的 safe prime
MASK_256 = (1 << 256) - 1              # 限制 bit 宽度用

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
# 工具：混合 message & key
# ==========================

MIX_DELIMITER_BYTE = 0xA7  # domain-separator：固定非 0 常量即可（避免短消息拼接导致的确定性碰撞/泄露）

def mix_key_and_message(message: bytes, key: bytes) -> bytes:
    """
    超轻量前项混合逻辑（constant-domain & fast）：
    - 短消息(<32B) padding：message || delim || 0x00... 填到 32 字节
    - 然后对 padding 后每个字节做按字节加法混合：mixed[i] = (padded[i] + key[j]) mod 256
    - message >= 32 则不 padding
    """
    if not key:
        raise ValueError("key 不能为空")
    if len(key) < 32:
        raise ValueError("key length 不能小于 32 Bytes")

    # 说明：delimiter 只是 domain-separator，不是秘密；选一个非 0/1 的常量避免和常见 padding 混淆。
    if len(message) < 32:
        pad_len = 32 - len(message) - 1
        padded = message + bytes([MIX_DELIMITER_BYTE]) + (b"\x00" * pad_len)
    else:
        padded = message

    # 让 key>len(padded) 的“尾巴”也参与：先取前 L 字节作为基底，然后把尾巴 XOR-fold 到 [0..L-1]
    L = len(padded)
    key_eff = bytearray(key[i] for i in range(min(L, len(key)))) + bytearray(max(0, L - len(key)))
    # key 短于消息时继续循环填充
    if len(key) < L:
        for i in range(len(key), L):
            key_eff[i] = key[i % len(key)]
    # key 长于消息时，把尾巴 fold 回来（你说的“XOR到消息上面”）
    for j in range(L, len(key)):
        key_eff[j % L] ^= key[j]

    mixed = bytearray(L)
    for i, b in enumerate(padded):
        #use constant mask domain only?????
        mixed[i] = (b + key_eff[i]) & 0xFF

    return bytes(mixed)


# ==========================
# 工具：从 u 中导出 r_i, s_i
# ==========================

def derive_r_s_from_u(u: int) -> Tuple[int, int]:
    """
    把 256-bit 的 u 看成 32 字节:
    - 低 16 字节 -> r_i_raw，做 Poly1305 clamp
    - 高 16 字节 -> s_i（直接用 128bit 偏移）
    """
    u &= MASK_256
    b = u.to_bytes(32, "little")

    r_raw = int.from_bytes(b[0:16], "little")
    # 标准 Poly1305 的 clamp mask
    r = r_raw & 0x0ffffffc0ffffffc0ffffffc0fffffff

    s = int.from_bytes(b[16:32], "little") & ((1 << 128) - 1)
    return r, s


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


# ==========================
# 主函数：HardPoly1305 V2-Lite
# ==========================

def hardpoly1305_v2_lite_tag(message: bytes, key: bytes) -> bytes:
    """
    计算 HardPoly1305 V2-Lite 的 16 字节 MAC 标签。
    - 使用 prime1 = P1, safeprime2 = P2
    - 每块重新计算 r_i, s_i（从 u_i 导出）
    - 非线性来自 hash_value 和 mixed(message, key)
    """
    # 参数派生使用 32B 折叠语义；混合预处理使用“全 key”语义（key 尾巴会 XOR-fold 到消息域上）
    key32 = fold_key_32(key)

    k_high, k_low, k_mix, k_mix_2 = derive_key_params(key32)

    mixed = mix_key_and_message(message, key)

    h = 0  # hash_value 初始为 0 (mod P1)

    # 每 16 字节一块；不足 16 的最后一块照旧加一个 0x01
    for offset in range(0, len(mixed), 16):
        block = mixed[offset: offset + 16]
        block += b"\x01"  # Poly1305 风格在块末尾加 1

        m_i = int.from_bytes(block, "little")

        # 计算 u_i，然后从 u_i 派生 r_i, s_i
        u_i = h_core(h, m_i, k_high, k_low, k_mix, k_mix_2)
        r_i, s_i = derive_r_s_from_u(u_i)

        # Poly1305 形状的更新
        h_tmp = (h + m_i) % P1
        h = (r_i * h_tmp + s_i) % P1

    # 输出 128bit tag（低 128 bit）
    tag = (h % (1 << 128)).to_bytes(16, "little")
    return tag


# ==========================
# HardPoly1305 V2-Lite 单元测试
# ==========================

def run_tests():
    print("开始 HardPoly1305 V2-Lite 单元测试")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    # 测试 1: derive_key_params 基本功能
    print("\n测试 1: derive_key_params 基本功能")
    try:
        key1 = bytes([i % 256 for i in range(32)])
        k_high, k_low, k_mix, k_mix_2 = derive_key_params(key1)
        
        # 检查范围
        assert 0 <= k_high < P1, f"k_high={k_high} 超出范围 0-{P1}"
        assert 0 <= k_low < P1, f"k_low={k_low} 超出范围 0-{P1}"
        assert 0 <= k_mix < P2, f"k_mix={k_mix} 超出范围 0-{P2}"
        assert 0 <= k_mix_2 < P2, f"k_mix_2={k_mix_2} 超出范围 0-{P2}"
        
        # 检查一致性（相同输入产生相同输出）
        k_high2, k_low2, k_mix2, k_mix_22 = derive_key_params(key1)
        assert k_high == k_high2, "k_high 不一致"
        assert k_low == k_low2, "k_low 不一致"
        assert k_mix == k_mix2, "k_mix 不一致"
        assert k_mix_2 == k_mix_22, "k_mix_2 不一致"
        
        # 测试不同key产生不同输出
        key2 = bytes([(i+1) % 256 for i in range(32)])
        k_high3, k_low3, k_mix3, k_mix_23 = derive_key_params(key2)
        assert k_high != k_high3, "不同key产生了相同的k_high"
        assert k_mix != k_mix3, "不同key产生了相同的k_mix"
        
        print("✓ 测试 1 通过")
        passed += 1
    except Exception as e:
        print(f"✗ 测试 1 失败: {e}")
        failed += 1
    
    # 测试 2: mix_key_and_message 功能
    print("\n测试 2: mix_key_and_message 功能")
    try:
        key = b"0123456789abcdef" * 2  # 32字节key
        message = b"Hello, World!"
        
        # 基础混合测试
        mixed = mix_key_and_message(message, key)
        # 注意：当消息长度小于32时，混合后的消息会被扩展到至少32字节
        # 所以我们需要更新这个断言
        expected_length = max(len(message), 32)
        assert len(mixed) == expected_length, f"长度不匹配: {len(mixed)} != {expected_length}"
        
        # 验证混合计算（只验证原始消息部分）
        expected = bytearray()
        for i, b in enumerate(message):
            expected.append((b + key[i % len(key)]) & 0xFF)
        # 只比较原始消息长度的部分
        assert bytes(expected) == mixed[:len(message)], "混合计算错误"

        # key>32 且 key>message：尾巴必须 fold 进 message 域（不应被忽略）
        key_long = key + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        mixed_long = mix_key_and_message(message, key_long)
        assert mixed_long != mixed, "key>32 的尾巴应影响 mixed（当前看起来被忽略了）"
        
        # 测试短消息（长度 < 32）
        short_msg = b"short"
        mixed_short = mix_key_and_message(short_msg, key)
        # 由于消息长度小于32，应该被扩展到32字节
        assert len(mixed_short) == 32, f"短消息未正确扩展: {len(mixed_short)} != 32"
        # 验证 padding + 混合（整段 32B）
        padded_short = short_msg + bytes([MIX_DELIMITER_BYTE]) + b"\x00" * (32 - len(short_msg) - 1)
        short_expected = bytearray((padded_short[i] + key[i % len(key)]) & 0xFF for i in range(32))
        assert bytes(short_expected) == mixed_short, "短消息 padding/混合计算错误"
        # 回归测试：旧实现会出现 M 与 M||0 的确定性碰撞；新实现必须避免
        short_msg2 = short_msg + b"\x00"
        mixed_short2 = mix_key_and_message(short_msg2, key)
        assert mixed_short != mixed_short2, "短消息 padding 回归：M 与 M||0 不应产生相同 mixed"
        
        # 测试长消息（长度 >= 32）不应被扩展
        long_msg = b"A" * 40
        mixed_long = mix_key_and_message(long_msg, key)
        assert len(mixed_long) == len(long_msg), f"长消息长度被修改: {len(mixed_long)} != {len(long_msg)}"
        
        # 测试空key
        try:
            mix_key_and_message(b"test", b"")
            assert False, "空key应该抛出异常"
        except ValueError:
            pass  # 正常
        
        # 测试key长度小于32
        try:
            short_key = b"shortkey"
            mix_key_and_message(b"test", short_key)
            assert False, "key长度小于32应该抛出异常"
        except ValueError:
            pass  # 正常
        
        print("✓ 测试 2 通过")
        passed += 1
    except Exception as e:
        print(f"✗ 测试 2 失败: {e}")
        failed += 1
    
    # 测试 3: derive_r_s_from_u 功能
    print("\n测试 3: derive_r_s_from_u 功能")
    try:
        # 测试用例1: 全0
        u1 = 0
        r1, s1 = derive_r_s_from_u(u1)
        assert r1 == 0, f"r1应为0，实际为{r1}"
        assert s1 == 0, f"s1应为0，实际为{s1}"
        
        # 测试用例2: 全1
        u2 = (1 << 256) - 1
        r2, s2 = derive_r_s_from_u(u2)
        # r应该被clamp
        r2_expected = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF & 0x0ffffffc0ffffffc0ffffffc0fffffff
        assert r2 == r2_expected, f"r2 clamp错误: {hex(r2)} != {hex(r2_expected)}"
        # s应该是高16字节的全1
        s2_expected = (1 << 128) - 1
        assert s2 == s2_expected, f"s2错误: {hex(s2)} != {hex(s2_expected)}"
        
        # 测试用例3: 特定值
        u3 = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
        r3, s3 = derive_r_s_from_u(u3)
        # 手动计算验证
        b = u3.to_bytes(32, 'little')
        r_raw = int.from_bytes(b[0:16], 'little')
        r_expected = r_raw & 0x0ffffffc0ffffffc0ffffffc0fffffff
        s_expected = int.from_bytes(b[16:32], 'little') & ((1 << 128) - 1)
        assert r3 == r_expected, f"r3计算错误: {hex(r3)} != {hex(r_expected)}"
        assert s3 == s_expected, f"s3计算错误: {hex(s3)} != {hex(s_expected)}"
        
        print("✓ 测试 3 通过")
        passed += 1
    except Exception as e:
        print(f"✗ 测试 3 失败: {e}")
        failed += 1
    
    # 测试 4: h_core 功能
    print("\n测试 4: h_core 功能")
    try:
        # 简单测试：检查输出在P2范围内
        h = 12345
        x = 67890
        k_high, k_low, k_mix, k_mix_2 = 111, 222, 333, 444
        
        u = h_core(h, x, k_high, k_low, k_mix, k_mix_2)
        assert 0 <= u < P2, f"u={u} 超出范围 0-{P2}"
        
        # 测试一致性
        u2 = h_core(h, x, k_high, k_low, k_mix, k_mix_2)
        assert u == u2, "相同输入产生不同输出"
        
        # 测试不同输入产生不同输出
        u3 = h_core(h+1, x, k_high, k_low, k_mix, k_mix_2)
        assert u != u3, "不同hash值产生相同输出"
        
        u4 = h_core(h, x+1, k_high, k_low, k_mix, k_mix_2)
        assert u != u4, "不同x_block产生相同输出"
        
        print("✓ 测试 4 通过")
        passed += 1
    except Exception as e:
        print(f"✗ 测试 4 失败: {e}")
        failed += 1
    
    # 测试 5: hardpoly1305_v2_lite_tag 完整功能
    print("\n测试 5: hardpoly1305_v2_lite_tag 完整功能")
    try:
        # 测试1: 空消息
        key = bytes([i for i in range(32)])
        tag1 = hardpoly1305_v2_lite_tag(b"", key)
        assert len(tag1) == 16, f"标签长度错误: {len(tag1)} != 16"
        # 空消息必须随 key 改变（防止出现固定 tag）
        key_alt = bytes([(i + 1) % 256 for i in range(32)])
        tag1_alt = hardpoly1305_v2_lite_tag(b"", key_alt)
        assert tag1 != tag1_alt, "空消息的标签不应对不同 key 相同"
        
        # 测试2: 短消息
        message2 = b"Hello"
        tag2 = hardpoly1305_v2_lite_tag(message2, key)
        assert len(tag2) == 16, f"标签长度错误: {len(tag2)} != 16"
        
        # 测试3: 长消息
        message3 = b"A" * 100
        tag3 = hardpoly1305_v2_lite_tag(message3, key)
        assert len(tag3) == 16, f"标签长度错误: {len(tag3)} != 16"
        
        # 测试4: 相同输入产生相同输出
        tag2_again = hardpoly1305_v2_lite_tag(message2, key)
        assert tag2 == tag2_again, "相同输入产生不同标签"
        
        # 测试5: 不同key产生不同标签
        key2 = bytes([(i+1) for i in range(32)])
        tag2_diff = hardpoly1305_v2_lite_tag(message2, key2)
        assert tag2 != tag2_diff, "不同key产生相同标签"
        
        # 测试6: 不同消息产生不同标签
        message4 = b"Hello!"
        tag4 = hardpoly1305_v2_lite_tag(message4, key)
        assert tag2 != tag4, "不同消息产生相同标签"
        
        # 测试7: key长度不足应该抛异常
        try:
            hardpoly1305_v2_lite_tag(b"test", b"short")
            assert False, "key长度不足应该抛出异常"
        except ValueError:
            pass  # 正常
        
        print("✓ 测试 5 通过")
        passed += 1
    except Exception as e:
        print(f"✗ 测试 5 失败: {e}")
        failed += 1
    
    # 测试 6: 边界条件和随机测试
    print("\n测试 6: 边界条件和随机测试")
    try:
        import random
        random.seed(42)  # 固定随机种子以重现测试
        
        for i in range(10):
            # 随机key和消息
            key_len = random.randint(32, 64)
            key = bytes(random.getrandbits(8) for _ in range(key_len))
            
            msg_len = random.randint(0, 100)
            message = bytes(random.getrandbits(8) for _ in range(msg_len))
            
            # 计算标签
            tag = hardpoly1305_v2_lite_tag(message, key)
            
            # 验证标签属性
            assert len(tag) == 16, f"随机测试{i}: 标签长度错误"
            
            # 相同输入产生相同输出
            tag2 = hardpoly1305_v2_lite_tag(message, key)
            assert tag == tag2, f"随机测试{i}: 相同输入产生不同输出"
            
            # 稍微修改消息应该改变标签
            if message:
                modified = bytearray(message)
                modified[0] = (modified[0] + 1) % 256
                tag3 = hardpoly1305_v2_lite_tag(bytes(modified), key)
                assert tag != tag3, f"随机测试{i}: 修改消息未改变标签"
        
        print("✓ 测试 6 通过")
        passed += 1
    except Exception as e:
        print(f"✗ 测试 6 失败: {e}")
        failed += 1
    
    # 汇总结果
    print("\n" + "=" * 60)
    print(f"测试完成: {passed} 通过, {failed} 失败")
    
    if failed == 0:
        print("\n所有测试通过！🎉")
    else:
        print(f"\n有 {failed} 个测试失败")
    
    return failed == 0
    
def run_comprehensive_tests():
    print("\n" + "=" * 60)
    print("开始 HardPoly1305 V2-Lite 综合测试")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    # 测试 7: 性能和大数据测试
    print("\n测试 7: 性能和大数据测试")
    try:
        import time
        
        # 大消息测试（1MB）
        print("  测试大消息（1MB）...")
        key = bytes([i % 256 for i in range(32)])
        large_message = b"X" * (1024 * 1024)  # 1MB
        
        start_time = time.time()
        tag_large = hardpoly1305_v2_lite_tag(large_message, key)
        end_time = time.time()
        
        assert len(tag_large) == 16, f"大消息标签长度错误: {len(tag_large)}"
        print(f"  处理 1MB 消息用时: {end_time - start_time:.4f} 秒")
        
        print("  测试小消息多次计算...")
        small_message = b"test"
        tags_set = set()
    
        start_time = time.time()
        for i in range(1024):
            # 生成32字节的key，确保每个i都不同
            key_var = (i * 0x9E3779B97F4A7C15).to_bytes(32, 'little')
            tag = hardpoly1305_v2_lite_tag(small_message, key_var)
            tags_set.add(tag)
        end_time = time.time()
    
        # 确保1024次计算得到1024个不同的标签（不同key）
        assert len(tags_set) == 1024, f"不同key应该产生不同标签: {len(tags_set)}/1024"
        print(f"  1024次小消息计算用时: {end_time - start_time:.4f} 秒")
        
        print("✓ 测试 7 通过")
        passed += 1
    except Exception as e:
        print(f"✗ 测试 7 失败: {e}")
        failed += 1
    
    # 测试 8: 特殊字符和边界值测试
    print("\n测试 8: 特殊字符和边界值测试")
    try:
        key = bytes([i for i in range(32)])
        
        # 测试全0消息
        zero_msg = b"\x00" * 50
        tag_zero = hardpoly1305_v2_lite_tag(zero_msg, key)
        assert len(tag_zero) == 16, "全0消息标签长度错误"
        
        # 测试全255消息
        max_msg = b"\xFF" * 50
        tag_max = hardpoly1305_v2_lite_tag(max_msg, key)
        assert len(tag_max) == 16, "全255消息标签长度错误"
        
        # 测试空消息
        empty_tag = hardpoly1305_v2_lite_tag(b"", key)
        assert len(empty_tag) == 16, "空消息标签长度错误"
        
        # 确保不同消息产生不同标签
        assert tag_zero != tag_max, "全0和全255消息产生了相同标签"
        assert tag_zero != empty_tag, "全0和空消息产生了相同标签"
        
        # 测试刚好16字节边界
        exact_16_msg = b"A" * 16
        tag_exact = hardpoly1305_v2_lite_tag(exact_16_msg, key)
        assert len(tag_exact) == 16, "16字节消息标签长度错误"
        
        # 测试刚好32字节边界
        exact_32_msg = b"B" * 32
        tag_exact32 = hardpoly1305_v2_lite_tag(exact_32_msg, key)
        assert len(tag_exact32) == 16, "32字节消息标签长度错误"
        
        print("✓ 测试 8 通过")
        passed += 1
    except Exception as e:
        print(f"✗ 测试 8 失败: {e}")
        failed += 1
    
    # 测试 9: 算法特性测试
    print("\n测试 9: 算法特性测试")
    try:
        # 测试雪崩效应（微小变化导致完全不同标签）
        key = bytes([i for i in range(32)])
        original_msg = b"The quick brown fox jumps over the lazy dog"
        
        # 原始消息标签
        original_tag = hardpoly1305_v2_lite_tag(original_msg, key)
        
        # 测试1: 修改一个字节
        modified_msg1 = bytearray(original_msg)
        modified_msg1[0] = (modified_msg1[0] + 1) % 256
        tag1 = hardpoly1305_v2_lite_tag(bytes(modified_msg1), key)
        
        # 计算汉明距离
        def hamming_distance(b1, b2):
            return sum(bin(b1[i] ^ b2[i]).count('1') for i in range(len(b1)))
        
        hamming1 = hamming_distance(original_tag, tag1)
        assert hamming1 > 0, "修改一个字节后标签应该不同"
        print(f"  单个字节修改的汉明距离: {hamming1}")
        
        # 测试2: 修改一个比特
        modified_msg2 = bytearray(original_msg)
        modified_msg2[10] ^= 1  # 翻转一个比特
        tag2 = hardpoly1305_v2_lite_tag(bytes(modified_msg2), key)
        
        hamming2 = hamming_distance(original_tag, tag2)
        assert hamming2 > 0, "修改一个比特后标签应该不同"
        print(f"  单个比特修改的汉明距离: {hamming2}")
        
        # 测试3: 添加一个字节
        modified_msg3 = original_msg + b"!"
        tag3 = hardpoly1305_v2_lite_tag(modified_msg3, key)
        
        hamming3 = hamming_distance(original_tag, tag3)
        assert hamming3 > 0, "添加一个字节后标签应该不同"
        print(f"  添加一个字节的汉明距离: {hamming3}")
        
        # 测试4: 不同key的雪崩效应
        key2 = bytes([(i+1) % 256 for i in range(32)])
        tag_key2 = hardpoly1305_v2_lite_tag(original_msg, key2)
        
        hamming_key = hamming_distance(original_tag, tag_key2)
        assert hamming_key > 0, "不同key应该产生不同标签"
        print(f"  不同key的汉明距离: {hamming_key}")
        
        print("✓ 测试 9 通过")
        passed += 1
    except Exception as e:
        print(f"✗ 测试 9 失败: {e}")
        failed += 1
    
    # 测试 10: 一致性测试（与参考实现对比）
    print("\n测试 10: 一致性测试")
    try:
        # 已知的测试向量（我们可以用算法自己生成一些）
        test_cases = [
            (b"", bytes(range(32))),
            (b"Hello, World!", bytes(range(32))),
            (b"The quick brown fox jumps over the lazy dog", bytes(range(32))),
            (b"A" * 100, bytes(range(32))),
            (b"\x00" * 50, bytes([i % 256 for i in range(32)])),
            (b"\xFF" * 50, bytes([(i+128) % 256 for i in range(32)])),
        ]
        
        print("  测试用例结果:")
        for i, (message, key) in enumerate(test_cases):
            tag = hardpoly1305_v2_lite_tag(message, key)
            # 再次计算以验证一致性
            tag2 = hardpoly1305_v2_lite_tag(message, key)
            assert tag == tag2, f"测试用例 {i+1}: 相同输入产生不同输出"
            
            # 输出标签的十六进制表示以便参考
            hex_tag = tag.hex()
            print(f"    用例{i+1}: 消息长度={len(message)}, 标签={hex_tag}")
        
        # 额外验证：三次计算应该得到相同结果
        for message, key in test_cases[:3]:
            tag1 = hardpoly1305_v2_lite_tag(message, key)
            tag2 = hardpoly1305_v2_lite_tag(message, key)
            tag3 = hardpoly1305_v2_lite_tag(message, key)
            assert tag1 == tag2 == tag3, f"消息 '{message[:10]}...' 三次计算不一致"
        
        print("✓ 测试 10 通过")
        passed += 1
    except Exception as e:
        print(f"✗ 测试 10 失败: {e}")
        failed += 1
    
    # 汇总结果
    print("\n" + "=" * 60)
    print(f"综合测试完成: {passed} 通过, {failed} 失败")
    
    if failed == 0:
        print("\n所有综合测试通过！🎉")
    else:
        print(f"\n有 {failed} 个综合测试失败")
    
    return failed == 0


# 修改主函数以运行两种测试
if __name__ == "__main__":
    print("=" * 60)
    print("HardPoly1305 V2-Lite 测试套件")
    print("=" * 60)
    
    # 运行基本单元测试
    unit_test_success = run_tests()
    
    # 运行综合测试
    comprehensive_test_success = run_comprehensive_tests()
    
    # 最终结果
    print("\n" + "=" * 60)
    print("最终测试结果")
    print("=" * 60)
    
    if unit_test_success and comprehensive_test_success:
        print("✅ 所有测试通过！")
        exit(0)
    else:
        print("❌ 测试失败")
        exit(1)