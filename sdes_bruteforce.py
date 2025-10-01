# sdes_bruteforce.py
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from sdes import SDES

class SDESBruteForce:
    """S-DES 暴力破解类 - 完整版"""
    
    @staticmethod
    def brute_force_with_known_plaintext(known_plaintext, known_ciphertext):
        """已知明文攻击 - 单线程版本"""
        print("开始已知明文攻击（单线程）...")
        start_time = time.time()
        
        found_keys = []

        # 遍历所有可能的10位密钥 (0-1023)
        for key_int in range(1024):
            # 将整数转换为10位二进制列表
            key = [int(bit) for bit in format(key_int, '010b')]

            # 尝试加密已知明文
            test_ciphertext = SDES.encrypt_block(known_plaintext, key)

            # 检查是否匹配已知密文
            if test_ciphertext == known_ciphertext:
                found_keys.append(key)
        
        end_time = time.time()
        print(f"单线程破解完成！耗时: {end_time - start_time:.4f}秒")
        
        return found_keys

    @classmethod
    def brute_force_multithread(cls, known_plaintext, known_ciphertext, max_workers=4):
        """已知明文攻击 - 多线程版本"""
        print(f"开始多线程暴力破解（{max_workers}线程）...")
        start_time = time.time()
        
        found_keys = []
        lock = threading.Lock()
        
        def check_key(key_int):
            key = [int(bit) for bit in format(key_int, '010b')]
            test_ciphertext = SDES.encrypt_block(known_plaintext, key)
            if test_ciphertext == known_ciphertext:
                with lock:
                    found_keys.append((key_int, key))
        
        # 使用线程池并行检查密钥
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(check_key, range(1024))
        
        end_time = time.time()
        print(f"多线程破解完成！耗时: {end_time - start_time:.4f}秒")
        
        # 只返回密钥列表
        return [key for _, key in found_keys]

    @staticmethod
    def brute_force_ciphertext_only(ciphertext, max_results=10):
        """唯密文攻击 - 返回最可能的密钥和明文"""
        print("开始唯密文攻击...")
        start_time = time.time()
        
        results = []

        # 遍历所有可能的10位密钥 (0-1023)
        for key_int in range(1024):
            # 将整数转换为10位二进制列表
            key = [int(bit) for bit in format(key_int, '010b')]

            # 尝试解密密文
            possible_plaintext = SDES.decrypt_block(ciphertext, key)

            # 计算明文的可读性分数（简单的启发式方法）
            readability_score = SDESBruteForce.calculate_readability(possible_plaintext)

            results.append({
                'key': key,
                'key_int': key_int,
                'plaintext': possible_plaintext,
                'score': readability_score
            })

        # 根据可读性分数排序
        results.sort(key=lambda x: x['score'], reverse=True)
        
        end_time = time.time()
        print(f"唯密文攻击完成！耗时: {end_time - start_time:.4f}秒")

        return results[:max_results]

    @staticmethod
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

    @classmethod
    def analyze_key_collisions(cls, plaintext=None):
        """分析密钥碰撞（第5关要求）
        
        分析：
        1. 一个明密文对是否对应多个密钥
        2. 不同密钥是否会产生相同密文
        """
        print("\n[密钥碰撞分析]")
        
        if plaintext is None:
            # 如果没有提供明文，使用默认测试明文
            plaintext = [1, 0, 1, 0, 1, 0, 1, 0]
            print(f"使用默认明文: {SDES.bin_list_to_str(plaintext)}")
        else:
            print(f"分析明文: {SDES.bin_list_to_str(plaintext)}")
        
        key_to_ciphertext = {}
        ciphertext_to_keys = {}
        
        start_time = time.time()
        
        # 遍历所有密钥
        for key_int in range(1024):
            key = [int(bit) for bit in format(key_int, '010b')]
            ciphertext = SDES.encrypt_block(plaintext, key)
            
            # 记录密钥到密文的映射
            key_str = SDES.bin_list_to_str(key)
            ciphertext_str = SDES.bin_list_to_str(ciphertext)
            
            key_to_ciphertext[key_str] = ciphertext_str
            
            # 记录密文到多个密钥的映射
            if ciphertext_str not in ciphertext_to_keys:
                ciphertext_to_keys[ciphertext_str] = []
            ciphertext_to_keys[ciphertext_str].append(key_str)
        
        end_time = time.time()
        
        # 分析结果
        collisions = {ct: keys for ct, keys in ciphertext_to_keys.items() if len(keys) > 1}
        unique_ciphertexts = len(ciphertext_to_keys)
        
        print(f"\n分析完成！耗时: {end_time - start_time:.4f}秒")
        print(f"\n=== 分析结果 ===")
        print(f"总密钥数: 1024")
        print(f"生成的唯一密文数: {unique_ciphertexts}")
        print(f"存在密钥碰撞的密文数: {len(collisions)}")
        print(f"碰撞率: {len(collisions)/unique_ciphertexts*100:.2f}%")
        
        if collisions:
            print(f"\n=== 碰撞详情（前5个）===")
            for i, (ct, keys) in enumerate(list(collisions.items())[:5]):
                print(f"{i+1}. 密文 {ct}: 对应 {len(keys)} 个不同密钥")
                for j, key in enumerate(keys[:3]):  # 显示前3个密钥
                    print(f"   密钥{j+1}: {key}")
                if len(keys) > 3:
                    print(f"   ... 还有 {len(keys)-3} 个密钥")
        
        # 寻找一个明密文对对应多个密钥的例子
        if collisions:
            sample_ct, sample_keys = list(collisions.items())[0]
            print(f"\n=== 示例：一个明密文对对应多个密钥 ===")
            print(f"明文: {SDES.bin_list_to_str(plaintext)}")
            print(f"密文: {sample_ct}")
            print(f"对应的密钥数量: {len(sample_keys)}")
            print(f"前3个密钥:")
            for i, key in enumerate(sample_keys[:3]):
                print(f"  密钥{i+1}: {key} (十进制: {int(key, 2)})")
        
        return collisions

    @classmethod
    def known_plaintext_attack(cls):
        """已知明文攻击模式"""
        print("\n[已知明文攻击模式]")

        print("\n输入格式选择:")
        print("1. 二进制格式 (8位明文, 8位密文)")
        print("2. 文本格式 (自动转换为二进制)")

        format_choice = input("请选择输入格式 (1-2): ").strip()

        if format_choice == '1':
            # 二进制输入
            known_plaintext = cls.input_binary("请输入8位已知明文（二进制）: ", 8)
            known_ciphertext = cls.input_binary("请输入8位已知密文（二进制）: ", 8)
        elif format_choice == '2':
            # 文本输入
            plaintext_text = cls.input_text("请输入已知明文（文本）: ")
            ciphertext_text = cls.input_text("请输入已知密文（文本）: ")

            # 转换为二进制
            known_plaintext = SDES.ascii_to_binary(plaintext_text)[0]  # 取第一个8位块
            known_ciphertext = SDES.ascii_to_binary(ciphertext_text)[0]  # 取第一个8位块

            print(f"明文二进制: {SDES.bin_list_to_str(known_plaintext)}")
            print(f"密文二进制: {SDES.bin_list_to_str(known_ciphertext)}")
        else:
            print("无效选择")
            return

        print("\n选择破解模式:")
        print("1. 单线程破解")
        print("2. 多线程破解（推荐）")
        thread_choice = input("请选择 (1-2, 默认2): ").strip() or "2"

        # 执行暴力破解
        if thread_choice == "1":
            found_keys = cls.brute_force_with_known_plaintext(known_plaintext, known_ciphertext)
        else:
            workers = int(input("请输入线程数 (默认4): ").strip() or "4")
            found_keys = cls.brute_force_multithread(known_plaintext, known_ciphertext, workers)

        # 显示结果
        print(f"\n攻击完成！找到 {len(found_keys)} 个可能的密钥:")

        for i, key in enumerate(found_keys, 1):
            key_int = int(SDES.bin_list_to_str(key), 2)
            print(f"{i}. 密钥: {SDES.bin_list_to_str(key)} (十进制: {key_int})")

            # 验证加解密
            test_cipher = SDES.encrypt_block(known_plaintext, key)
            test_plain = SDES.decrypt_block(known_ciphertext, key)

            if test_cipher == known_ciphertext and test_plain == known_plaintext:
                print("   验证: 加解密测试成功")
            else:
                print("   验证: 加解密测试失败")

    @classmethod
    def ciphertext_only_attack(cls):
        """唯密文攻击模式"""
        print("\n[唯密文攻击模式]")

        print("\n输入格式选择:")
        print("1. 二进制格式 (8位密文)")
        print("2. 文本格式 (自动转换为二进制)")

        format_choice = input("请选择输入格式 (1-2): ").strip()

        if format_choice == '1':
            # 二进制输入
            ciphertext = cls.input_binary("请输入8位密文（二进制）: ", 8)
        elif format_choice == '2':
            # 文本输入
            ciphertext_text = cls.input_text("请输入密文（文本）: ")
            # 转换为二进制
            ciphertext = SDES.ascii_to_binary(ciphertext_text)[0]  # 取第一个8位块
            print(f"密文二进制: {SDES.bin_list_to_str(ciphertext)}")
        else:
            print("无效选择")
            return

        max_results = int(input("请输入要显示的最大结果数量 (默认10): ") or "10")

        # 执行暴力破解
        results = cls.brute_force_ciphertext_only(ciphertext, max_results)

        # 显示结果
        print(f"\n攻击完成！找到 {len(results)} 个最可能的结果:")

        for i, result in enumerate(results, 1):
            key = result['key']
            key_int = result['key_int']
            plaintext = result['plaintext']
            score = result['score']

            print(f"\n{i}. 密钥: {SDES.bin_list_to_str(key)} (十进制: {key_int})")
            print(f"   可读性分数: {score}")
            print(f"   解密结果（二进制）: {SDES.bin_list_to_str(plaintext)}")

            # 尝试显示为文本
            plaintext_text = SDES.binary_to_ascii([plaintext])
            print(f"   解密结果（文本）: {plaintext_text}")

    # 输入辅助方法
    @staticmethod
    def input_binary(prompt, length):
        """获取用户输入的二进制数据"""
        while True:
            user_input = input(prompt).strip()
            if all(c in '01' for c in user_input) and len(user_input) == length:
                return [int(bit) for bit in user_input]
            else:
                print(f"请输入{length}位二进制数（只包含0和1）")

    @staticmethod
    def input_text(prompt):
        """获取用户输入的文本"""
        return input(prompt).strip()


def interactive_mode():
    """交互模式"""
    print("=" * 60)
    print("S-DES暴力破解工具 - 完整版")
    print("=" * 60)

    while True:
        print("\n请选择模式:")
        print("1. 已知明文攻击（已知明文和密文对）")
        print("2. 唯密文攻击（只知道密文）")
        print("3. 密钥碰撞分析（第5关）")
        print("4. 性能测试")
        print("5. 退出")

        choice = input("请输入选择 (1-5): ").strip()

        if choice == '1':
            SDESBruteForce.known_plaintext_attack()
        elif choice == '2':
            SDESBruteForce.ciphertext_only_attack()
        elif choice == '3':
            print("\n密钥碰撞分析选项:")
            print("1. 使用默认明文分析")
            print("2. 输入自定义明文")
            analysis_choice = input("请选择 (1-2): ").strip()
            
            if analysis_choice == '1':
                SDESBruteForce.analyze_key_collisions()
            elif analysis_choice == '2':
                plaintext_input = input("请输入8位二进制明文: ").strip()
                if len(plaintext_input) == 8 and all(c in '01' for c in plaintext_input):
                    plaintext = [int(bit) for bit in plaintext_input]
                    SDESBruteForce.analyze_key_collisions(plaintext)
                else:
                    print("输入无效，必须为8位二进制数")
            else:
                print("无效选择")
        elif choice == '4':
            performance_test()
        elif choice == '5':
            print("再见！")
            break
        else:
            print("无效选择，请重新输入")


def performance_test():
    """性能测试函数"""
    print("\n[性能测试]")
    
    # 测试数据
    test_plaintext = [1, 0, 1, 0, 1, 0, 1, 0]
    test_ciphertext = SDES.encrypt_block(test_plaintext, [1, 0, 1, 0, 0, 0, 0, 0, 1, 0])
    
    print(f"测试明文: {SDES.bin_list_to_str(test_plaintext)}")
    print(f"测试密文: {SDES.bin_list_to_str(test_ciphertext)}")
    
    print("\n单线程破解测试...")
    start_time = time.time()
    keys_single = SDESBruteForce.brute_force_with_known_plaintext(test_plaintext, test_ciphertext)
    single_time = time.time() - start_time
    
    print("\n多线程破解测试（4线程）...")
    start_time = time.time()
    keys_multi = SDESBruteForce.brute_force_multithread(test_plaintext, test_ciphertext, 4)
    multi_time = time.time() - start_time
    
    print(f"\n=== 性能测试结果 ===")
    print(f"单线程耗时: {single_time:.4f}秒")
    print(f"多线程耗时: {multi_time:.4f}秒")
    print(f"加速比: {single_time/multi_time:.2f}x")
    print(f"找到密钥数 - 单线程: {len(keys_single)}, 多线程: {len(keys_multi)}")


def main():
    # 首先测试S-DES实现
    print("正在进行S-DES实现测试...")
    SDES.test_sdes()

    print("\n" + "=" * 60)

    # 进入交互模式
    interactive_mode()


if __name__ == "__main__":
    main()