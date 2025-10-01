"""
S-DES核心算法实现
提供加密、解密和密钥生成功能
支持8位二进制数据和ASCII字符串加解密
"""

class SDES:
    # 置换表 - 按照题目要求
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    P4 = [2, 4, 3, 1]
    
    # 左移位表
    LEFT_SHIFT1 = [2, 3, 4, 5, 1]  # Left_Shift^1
    LEFT_SHIFT2 = [3, 4, 5, 1, 2]  # Left_Shift^2
    
    # S盒 - 按照题目要求
    SBox1 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 0, 2]
    ]
    
    SBox2 = [
        [0, 1, 2, 3],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]

    @staticmethod
    def permute(bits, table):
        """置换函数"""
        return [bits[i-1] for i in table]

    @staticmethod
    def shift_left(bits, shift_table):
        """按照置换表进行左循环移位"""
        return [bits[i-1] for i in shift_table]

    @staticmethod
    def xor(bits1, bits2):
        """异或操作"""
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    @staticmethod
    def s_box_lookup(bits, s_box):
        """S盒查找"""
        # 第1位和第4位决定行，第2位和第3位决定列
        row = (bits[0] << 1) | bits[3]
        col = (bits[1] << 1) | bits[2]
        value = s_box[row][col]
        return [value >> 1 & 1, value & 1]

    @classmethod
    def generate_keys(cls, key):
        """
        生成子密钥K1和K2
        
        Args:
            key: 10位密钥列表
            
        Returns:
            tuple: (k1, k2) 两个8位子密钥
        """
        # P10置换
        p10_key = cls.permute(key, cls.P10)
        
        # 分成左右两部分
        left = p10_key[:5]
        right = p10_key[5:]
        
        # 第一次左移位（使用LEFT_SHIFT1表）
        left_shift1_left = cls.shift_left(left, cls.LEFT_SHIFT1)
        left_shift1_right = cls.shift_left(right, cls.LEFT_SHIFT1)
        
        # 生成K1
        combined1 = left_shift1_left + left_shift1_right
        k1 = cls.permute(combined1, cls.P8)
        
        # 第二次左移位（使用LEFT_SHIFT2表）
        left_shift2_left = cls.shift_left(left_shift1_left, cls.LEFT_SHIFT2)
        left_shift2_right = cls.shift_left(left_shift1_right, cls.LEFT_SHIFT2)
        
        # 生成K2
        combined2 = left_shift2_left + left_shift2_right
        k2 = cls.permute(combined2, cls.P8)
        
        return k1, k2

    @classmethod
    def f_function(cls, right, subkey):
        """
        轮函数f
        
        Args:
            right: 4位右半部分
            subkey: 8位子密钥
            
        Returns:
            list: 4位输出
        """
        # 扩展置换
        expanded = cls.permute(right, cls.EP)
        
        # 与子密钥异或
        xor_result = cls.xor(expanded, subkey)
        
        # S盒替换
        s0_input = xor_result[:4]
        s1_input = xor_result[4:]
        s0_output = cls.s_box_lookup(s0_input, cls.SBox1)
        s1_output = cls.s_box_lookup(s1_input, cls.SBox2)
        
        # P4置换
        p4_result = cls.permute(s0_output + s1_output, cls.P4)
        
        return p4_result

    @classmethod
    def encrypt_block(cls, plaintext, key):
        """
        加密一个8位数据块
        
        Args:
            plaintext: 8位明文列表
            key: 10位密钥列表
            
        Returns:
            list: 8位密文列表
        """
        # 生成子密钥
        k1, k2 = cls.generate_keys(key)
        
        # 初始置换
        ip_result = cls.permute(plaintext, cls.IP)
        
        # 第一轮
        left = ip_result[:4]
        right = ip_result[4:]
        f_result = cls.f_function(right, k1)
        new_right = cls.xor(left, f_result)
        
        # 交换
        left, right = right, new_right
        
        # 第二轮
        f_result = cls.f_function(right, k2)
        new_left = cls.xor(left, f_result)
        
        # 最终置换
        ciphertext = cls.permute(new_left + right, cls.IP_INV)
        
        return ciphertext

    @classmethod
    def decrypt_block(cls, ciphertext, key):
        """
        解密一个8位数据块
        
        Args:
            ciphertext: 8位密文列表
            key: 10位密钥列表
            
        Returns:
            list: 8位明文列表
        """
        # 生成子密钥
        k1, k2 = cls.generate_keys(key)
        
        # 初始置换
        ip_result = cls.permute(ciphertext, cls.IP)
        
        # 第一轮（使用K2）
        left = ip_result[:4]
        right = ip_result[4:]
        f_result = cls.f_function(right, k2)
        new_right = cls.xor(left, f_result)
        
        # 交换
        left, right = right, new_right
        
        # 第二轮（使用K1）
        f_result = cls.f_function(right, k1)
        new_left = cls.xor(left, f_result)
        
        # 最终置换
        plaintext = cls.permute(new_left + right, cls.IP_INV)
        
        return plaintext

    # 扩展功能：ASCII字符串支持
    @staticmethod
    def ascii_to_binary(text):
        """将ASCII字符串转换为二进制列表"""
        binary_list = []
        for char in text:
            binary = format(ord(char), '08b')
            binary_list.append([int(bit) for bit in binary])
        return binary_list

    @staticmethod
    def binary_to_ascii(binary_list):
        """将二进制列表转换为ASCII字符串"""
        text = ""
        for binary in binary_list:
            char_code = int(''.join(str(bit) for bit in binary), 2)
            text += chr(char_code)
        return text

    @classmethod
    def encrypt_text(cls, text, key):
        """加密ASCII文本"""
        binary_blocks = cls.ascii_to_binary(text)
        encrypted_blocks = []
        for block in binary_blocks:
            encrypted_block = cls.encrypt_block(block, key)
            encrypted_blocks.append(encrypted_block)
        return cls.binary_to_ascii(encrypted_blocks)

    @classmethod
    def decrypt_text(cls, text, key):
        """解密ASCII文本"""
        binary_blocks = cls.ascii_to_binary(text)
        decrypted_blocks = []
        for block in binary_blocks:
            decrypted_block = cls.decrypt_block(block, key)
            decrypted_blocks.append(decrypted_block)
        return cls.binary_to_ascii(decrypted_blocks)

    # 工具函数：字符串和二进制列表转换
    @staticmethod
    def str_to_bin_list(bin_str):
        """将二进制字符串转换为二进制列表"""
        return [int(bit) for bit in bin_str]

    @staticmethod
    def bin_list_to_str(bin_list):
        """将二进制列表转换为二进制字符串"""
        return ''.join(str(bit) for bit in bin_list)


    @staticmethod
    # 测试函数
    def test_sdes():
        """测试S-DES算法"""
        sdes = SDES()
        
        # 测试用例
        plaintext = [1, 1, 1, 0, 1, 0, 1, 0]  # 8位明文
        key = [1, 0, 1, 0, 0, 1, 1, 0, 1, 0]  # 10位密钥
        
        print("=== S-DES算法测试 ===")
        print(f"明文: {SDES.bin_list_to_str(plaintext)}")
        print(f"密钥: {SDES.bin_list_to_str(key)}")
        
        # 加密
        ciphertext = sdes.encrypt_block(plaintext, key)
        print(f"密文: {SDES.bin_list_to_str(ciphertext)}")
        
        # 解密
        decrypted = sdes.decrypt_block(ciphertext, key)
        print(f"解密: {SDES.bin_list_to_str(decrypted)}")
        
        # 测试ASCII加密
        print("\n=== ASCII加密测试 ===")
        text = "World"
        print(f"原文: {text}")
        
        encrypted_text = sdes.encrypt_text(text, key)
        print(f"加密后: {encrypted_text}")
        
        decrypted_text = sdes.decrypt_text(encrypted_text, key)
        print(f"解密后: {decrypted_text}")

# if __name__ == "__main__":
#     test_sdes()