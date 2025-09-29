import itertools

# S-DES 固定参数
# 初始置换IP
IP = [1, 5, 2, 0, 3, 7, 4, 6]
# 逆初始置换
IP_INV = [3, 0, 2, 4, 6, 1, 7, 5]
# P10置换
P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
# P8置换
P8 = [5, 2, 6, 3, 7, 4, 9, 8]
# P4置换
P4 = [1, 3, 2, 0]
# 扩展置换EP
EP = [3, 0, 1, 2, 1, 2, 3, 0]
# S盒
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


def permute(bits, permutation):
    """执行置换操作"""
    return [bits[i] for i in permutation]


def left_shift(bits, n):
    """循环左移"""
    return bits[n:] + bits[:n]


def generate_subkeys(key):
    """生成两个子密钥k1和k2"""
    # P10置换
    p10_key = permute(key, P10)

    # 分成左右两部分
    left = p10_key[:5]
    right = p10_key[5:]

    # 左移1位
    left_shift1_left = left_shift(left, 1)
    left_shift1_right = left_shift(right, 1)

    # 生成k1 (P8置换)
    k1 = permute(left_shift1_left + left_shift1_right, P8)

    # 左移2位
    left_shift2_left = left_shift(left_shift1_left, 2)
    left_shift2_right = left_shift(left_shift1_right, 2)

    # 生成k2 (P8置换)
    k2 = permute(left_shift2_left + left_shift2_right, P8)

    return k1, k2


def s_box_lookup(bits, s_box):
    """S盒查找"""
    row = (bits[0] << 1) + bits[1]  # 第1位和第4位作为行
    col = (bits[2] << 1) + bits[3]  # 第2位和第3位作为列
    value = s_box[row][col]
    return [value >> 1 & 1, value & 1]  # 返回2位二进制


def f_function(bits, subkey):
    """F函数"""
    # 扩展置换
    expanded = permute(bits, EP)

    # 与子密钥异或
    xor_result = [expanded[i] ^ subkey[i] for i in range(8)]

    # S盒替换
    s0_input = xor_result[:4]
    s1_input = xor_result[4:]

    s0_output = s_box_lookup(s0_input, S0)
    s1_output = s_box_lookup(s1_input, S1)

    # P4置换
    p4_result = permute(s0_output + s1_output, P4)

    return p4_result


def s_des_encrypt(plaintext, key):
    """S-DES加密"""
    # 生成子密钥
    k1, k2 = generate_subkeys(key)

    # 初始置换
    ip_result = permute(plaintext, IP)

    # 分成左右两部分
    left = ip_result[:4]
    right = ip_result[4:]

    # 第一轮: F函数 + SW
    f_result1 = f_function(right, k1)
    new_left = [left[i] ^ f_result1[i] for i in range(4)]

    # 交换
    left, right = right, new_left

    # 第二轮: F函数
    f_result2 = f_function(right, k2)
    new_left = [left[i] ^ f_result2[i] for i in range(4)]

    # 最终组合
    final = new_left + right

    # 逆初始置换
    ciphertext = permute(final, IP_INV)

    return ciphertext


def s_des_decrypt(ciphertext, key):
    """S-DES解密"""
    # 生成子密钥
    k1, k2 = generate_subkeys(key)

    # 初始置换
    ip_result = permute(ciphertext, IP)

    # 分成左右两部分
    left = ip_result[:4]
    right = ip_result[4:]

    # 第一轮: F函数 + SW (使用k2)
    f_result1 = f_function(right, k2)
    new_left = [left[i] ^ f_result1[i] for i in range(4)]

    # 交换
    left, right = right, new_left

    # 第二轮: F函数 (使用k1)
    f_result2 = f_function(right, k1)
    new_left = [left[i] ^ f_result2[i] for i in range(4)]

    # 最终组合
    final = new_left + right

    # 逆初始置换
    plaintext = permute(final, IP_INV)

    return plaintext


def binary_to_string(bits):
    """将二进制列表转换为字符串"""
    # 将8位二进制转换为字符
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        if len(byte) == 8:
            char_code = int(''.join(map(str, byte)), 2)
            if 32 <= char_code <= 126:  # 可打印ASCII字符
                chars.append(chr(char_code))
            else:
                chars.append(f'\\x{char_code:02x}')
    return ''.join(chars)


def string_to_binary(text):
    """将字符串转换为二进制列表"""
    bits = []
    for char in text:
        byte = format(ord(char), '08b')
        bits.extend([int(bit) for bit in byte])
    return bits


def input_binary(prompt, length):
    """获取用户输入的二进制数据"""
    while True:
        user_input = input(prompt).strip()
        if all(c in '01' for c in user_input) and len(user_input) == length:
            return [int(bit) for bit in user_input]
        else:
            print(f"请输入{length}位二进制数（只包含0和1）")


def input_text(prompt):
    """获取用户输入的文本"""
    return input(prompt).strip()


def brute_force_with_known_plaintext(known_plaintext, known_ciphertext):
    """已知明文攻击"""
    print("开始已知明文攻击...")
    print(f"已知明文: {known_plaintext}")
    print(f"已知密文: {known_ciphertext}")

    found_keys = []

    # 遍历所有可能的10位密钥 (0-1023)
    for key_int in range(1024):
        # 将整数转换为10位二进制列表
        key = [int(bit) for bit in format(key_int, '010b')]

        # 尝试加密已知明文
        test_ciphertext = s_des_encrypt(known_plaintext, key)

        # 检查是否匹配已知密文
        if test_ciphertext == known_ciphertext:
            found_keys.append(key)

    return found_keys


def brute_force_ciphertext_only(ciphertext, max_results=10):
    """唯密文攻击 - 返回最可能的密钥和明文"""
    print("开始唯密文攻击...")
    print(f"目标密文: {ciphertext}")

    results = []

    # 遍历所有可能的10位密钥 (0-1023)
    for key_int in range(1024):
        # 将整数转换为10位二进制列表
        key = [int(bit) for bit in format(key_int, '010b')]

        # 尝试解密密文
        possible_plaintext = s_des_decrypt(ciphertext, key)

        # 计算明文的可读性分数（简单的启发式方法）
        readability_score = calculate_readability(possible_plaintext)

        results.append({
            'key': key,
            'key_int': key_int,
            'plaintext': possible_plaintext,
            'score': readability_score
        })

    # 根据可读性分数排序
    results.sort(key=lambda x: x['score'], reverse=True)

    return results[:max_results]


def calculate_readability(bits):
    """计算二进制数据的可读性分数"""
    if len(bits) % 8 != 0:
        return 0

    score = 0
    # 检查每个字节是否为可打印ASCII字符
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        char_code = int(''.join(map(str, byte)), 2)
        if 32 <= char_code <= 126:  # 可打印ASCII字符
            score += 1
            # 给字母和数字更高的分数
            if 65 <= char_code <= 90 or 97 <= char_code <= 122 or 48 <= char_code <= 57:
                score += 1
            # 给空格更高的分数（常见单词分隔符）
            if char_code == 32:
                score += 1

    return score


def interactive_mode():
    """交互模式"""
    print("=" * 60)
    print("S-DES暴力破解工具")
    print("=" * 60)

    while True:
        print("\n请选择模式:")
        print("1. 已知明文攻击（已知明文和密文对）")
        print("2. 唯密文攻击（只知道密文）")
        print("3. 退出")

        choice = input("请输入选择 (1-3): ").strip()

        if choice == '1':
            known_plaintext_attack()
        elif choice == '2':
            ciphertext_only_attack()
        elif choice == '3':
            print("再见！")
            break
        else:
            print("无效选择，请重新输入")


def known_plaintext_attack():
    """已知明文攻击模式"""
    print("\n[已知明文攻击模式]")

    print("\n输入格式选择:")
    print("1. 二进制格式 (8位明文, 8位密文)")
    print("2. 文本格式 (自动转换为二进制)")

    format_choice = input("请选择输入格式 (1-2): ").strip()

    if format_choice == '1':
        # 二进制输入
        known_plaintext = input_binary("请输入8位已知明文（二进制）: ", 8)
        known_ciphertext = input_binary("请输入8位已知密文（二进制）: ", 8)
    elif format_choice == '2':
        # 文本输入
        plaintext_text = input_text("请输入已知明文（文本）: ")
        ciphertext_text = input_text("请输入已知密文（文本）: ")

        # 转换为二进制
        known_plaintext = string_to_binary(plaintext_text)[:8]  # 只取前8位
        known_ciphertext = string_to_binary(ciphertext_text)[:8]  # 只取前8位

        print(f"明文二进制: {known_plaintext}")
        print(f"密文二进制: {known_ciphertext}")
    else:
        print("无效选择")
        return

    # 执行暴力破解
    found_keys = brute_force_with_known_plaintext(known_plaintext, known_ciphertext)

    # 显示结果
    print(f"\n攻击完成！找到 {len(found_keys)} 个可能的密钥:")

    for i, key in enumerate(found_keys, 1):
        key_int = int(''.join(map(str, key)), 2)
        print(f"{i}. 密钥: {key} (十进制: {key_int})")

        # 验证加解密
        test_cipher = s_des_encrypt(known_plaintext, key)
        test_plain = s_des_decrypt(known_ciphertext, key)

        if test_cipher == known_ciphertext and test_plain == known_plaintext:
            print("   验证: 加解密测试成功")
        else:
            print("   验证: 加解密测试失败")


def ciphertext_only_attack():
    """唯密文攻击模式"""
    print("\n[唯密文攻击模式]")

    print("\n输入格式选择:")
    print("1. 二进制格式 (8位密文)")
    print("2. 文本格式 (自动转换为二进制)")

    format_choice = input("请选择输入格式 (1-2): ").strip()

    if format_choice == '1':
        # 二进制输入
        ciphertext = input_binary("请输入8位密文（二进制）: ", 8)
    elif format_choice == '2':
        # 文本输入
        ciphertext_text = input_text("请输入密文（文本）: ")
        # 转换为二进制
        ciphertext = string_to_binary(ciphertext_text)[:8]  # 只取前8位
        print(f"密文二进制: {ciphertext}")
    else:
        print("无效选择")
        return

    max_results = int(input("请输入要显示的最大结果数量 (默认10): ") or "10")

    # 执行暴力破解
    results = brute_force_ciphertext_only(ciphertext, max_results)

    # 显示结果
    print(f"\n攻击完成！找到 {len(results)} 个最可能的结果:")

    for i, result in enumerate(results, 1):
        key = result['key']
        key_int = result['key_int']
        plaintext = result['plaintext']
        score = result['score']

        print(f"\n{i}. 密钥: {key} (十进制: {key_int})")
        print(f"   可读性分数: {score}")
        print(f"   解密结果（二进制）: {plaintext}")

        # 尝试显示为文本
        plaintext_text = binary_to_string(plaintext)
        print(f"   解密结果（文本）: {plaintext_text}")


def test_sdes():
    """测试S-DES实现"""
    print("测试S-DES加解密...")

    # 测试用例
    plaintext = [1, 0, 1, 0, 1, 0, 1, 0]  # 8位明文
    key = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]  # 10位密钥

    print(f"明文: {plaintext}")
    print(f"密钥: {key}")

    # 加密
    ciphertext = s_des_encrypt(plaintext, key)
    print(f"密文: {ciphertext}")

    # 解密
    decrypted = s_des_decrypt(ciphertext, key)
    print(f"解密: {decrypted}")

    # 验证
    if plaintext == decrypted:
        print("加解密测试成功!")
    else:
        print("加解密测试失败!")

    return plaintext, ciphertext


def main():
    # 首先测试S-DES实现
    print("正在进行S-DES实现测试...")
    test_sdes()

    print("\n" + "=" * 60)

    # 进入交互模式
    interactive_mode()


if __name__ == "__main__":
    main()