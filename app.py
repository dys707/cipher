from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sdes
import sdes_bruteforce
import time
import threading
from collections import defaultdict

app = Flask(__name__)
CORS(app)

# 存储HTML页面
@app.route('/')
def index():
    return render_template('index.html')

# 基本加密API
@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    input_data = data.get('input')
    key_str = data.get('key')
    input_type = data.get('type')
    
    # 验证密钥
    if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
        return jsonify({'error': '密钥必须是10位二进制数'}), 400
    
    key = sdes.SDES.str_to_bin_list(key_str)
    
    try:
        if input_type == 'binary':
            # 二进制加密
            if len(input_data) != 8 or not all(bit in '01' for bit in input_data):
                return jsonify({'error': '明文必须是8位二进制数'}), 400
            
            plaintext = sdes.SDES.str_to_bin_list(input_data)
            ciphertext = sdes.SDES.encrypt_block(plaintext, key)
            binary_result = sdes.SDES.bin_list_to_str(ciphertext)
            text_result = sdes.SDES.binary_to_ascii([ciphertext])
            
        else:
            # 文本加密
            encrypted_text = sdes.SDES.encrypt_text(input_data, key)
            binary_result = ''.join(sdes.SDES.bin_list_to_str(block) for block in sdes.SDES.ascii_to_binary(encrypted_text))
            text_result = encrypted_text
        
        return jsonify({
            'binary': binary_result,
            'text': text_result
        })
        
    except Exception as e:
        return jsonify({'error': f'加密失败: {str(e)}'}), 500

# 基本解密API
@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    input_data = data.get('input')
    key_str = data.get('key')
    input_type = data.get('type')
    
    # 验证密钥
    if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
        return jsonify({'error': '密钥必须是10位二进制数'}), 400
    
    key = sdes.SDES.str_to_bin_list(key_str)
    
    try:
        if input_type == 'binary':
            # 二进制解密
            if len(input_data) != 8 or not all(bit in '01' for bit in input_data):
                return jsonify({'error': '密文必须是8位二进制数'}), 400
            
            ciphertext = sdes.SDES.str_to_bin_list(input_data)
            plaintext = sdes.SDES.decrypt_block(ciphertext, key)
            binary_result = sdes.SDES.bin_list_to_str(plaintext)
            text_result = sdes.SDES.binary_to_ascii([plaintext])
            
        else:
            # 文本解密
            decrypted_text = sdes.SDES.decrypt_text(input_data, key)
            binary_result = ''.join(sdes.SDES.bin_list_to_str(block) for block in sdes.SDES.ascii_to_binary(decrypted_text))
            text_result = decrypted_text
        
        return jsonify({
            'binary': binary_result,
            'text': text_result
        })
        
    except Exception as e:
        return jsonify({'error': f'解密失败: {str(e)}'}), 500

# 已知明文攻击API
@app.route('/api/known_attack', methods=['POST'])
def known_attack():
    data = request.json
    plaintext = data.get('plaintext')
    ciphertext = data.get('ciphertext')
    thread_count = data.get('threads', 4)
    
    # 验证输入
    if len(plaintext) != 8 or not all(bit in '01' for bit in plaintext):
        return jsonify({'error': '明文必须是8位二进制数'}), 400
    if len(ciphertext) != 8 or not all(bit in '01' for bit in ciphertext):
        return jsonify({'error': '密文必须是8位二进制数'}), 400
    
    # 转换为二进制列表
    plaintext_bits = sdes.SDES.str_to_bin_list(plaintext)
    ciphertext_bits = sdes.SDES.str_to_bin_list(ciphertext)
    
    start_time = time.time()
    
    # 使用暴力破解模块
    if thread_count == 1:
        found_keys = sdes_bruteforce.SDESBruteForce.brute_force_with_known_plaintext(plaintext_bits, ciphertext_bits)
    else:
        found_keys = sdes_bruteforce.SDESBruteForce.brute_force_multithread(plaintext_bits, ciphertext_bits, thread_count)
    
    end_time = time.time()
    
    # 格式化结果
    keys_result = []
    for key in found_keys:
        key_str = sdes.SDES.bin_list_to_str(key)
        keys_result.append({
            'binary': key_str,
            'decimal': int(key_str, 2)
        })
    
    return jsonify({
        'keys': keys_result,
        'time': round(end_time - start_time, 4)
    })

# 唯密文攻击API
@app.route('/api/ciphertext_attack', methods=['POST'])
def ciphertext_attack():
    data = request.json
    ciphertext = data.get('ciphertext')
    max_results = data.get('max_results', 10)
    
    # 验证输入
    if len(ciphertext) != 8 or not all(bit in '01' for bit in ciphertext):
        return jsonify({'error': '密文必须是8位二进制数'}), 400
    
    ciphertext_bits = sdes.SDES.str_to_bin_list(ciphertext)
    
    start_time = time.time()
    
    # 使用暴力破解模块
    results = sdes_bruteforce.SDESBruteForce.brute_force_ciphertext_only(ciphertext_bits, max_results)
    
    end_time = time.time()
    
    # 格式化结果
    formatted_results = []
    for result in results:
        key_str = sdes.SDES.bin_list_to_str(result['key'])
        plaintext_str = sdes.SDES.bin_list_to_str(result['plaintext'])
        plaintext_text = sdes.SDES.binary_to_ascii([result['plaintext']])
        
        formatted_results.append({
            'key': {
                'binary': key_str,
                'decimal': result['key_int']
            },
            'plaintext': {
                'binary': plaintext_str,
                'text': plaintext_text
            },
            'score': result['score']
        })
    
    return jsonify({
        'keys': formatted_results,
        'time': round(end_time - start_time, 4)
    })

# 密钥碰撞分析API
@app.route('/api/collision_analysis', methods=['POST'])
def collision_analysis():
    data = request.json
    plaintext = data.get('plaintext')
    
    # 验证输入
    if len(plaintext) != 8 or not all(bit in '01' for bit in plaintext):
        return jsonify({'error': '明文必须是8位二进制数'}), 400
    
    plaintext_bits = sdes.SDES.str_to_bin_list(plaintext)
    
    # 使用暴力破解模块进行分析
    collisions = sdes_bruteforce.SDESBruteForce.analyze_key_collisions(plaintext_bits)
    
    # 格式化结果
    collision_list = []
    for ciphertext, keys in collisions.items():
        key_list = []
        for key_str in keys:
            key_list.append({
                'binary': key_str,
                'decimal': int(key_str, 2)
            })
        
        collision_list.append({
            'ciphertext': ciphertext,
            'keys': key_list
        })
    
    unique_ciphertexts = len(set(collisions.keys()))
    collision_rate = (len(collision_list) / unique_ciphertexts * 100) if unique_ciphertexts > 0 else 0
    
    return jsonify({
        'uniqueCiphertexts': unique_ciphertexts,
        'collisions': collision_list,
        'collisionRate': round(collision_rate, 2)
    })

if __name__ == '__main__':
    # 创建templates文件夹并放入index.html
    import os
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # 将HTML文件移动到templates文件夹
    with open('index.html', 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("服务器启动中...")
    print("访问地址: http://localhost:5000")
    app.run(debug=True, port=5000)

