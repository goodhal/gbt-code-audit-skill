"""
Python代码安全测试样例
覆盖 GB/T 39412-2020 通用标准
"""

import os
import pickle
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional
import yaml
import hashlib


class VulnerablePython:
    """Python代码安全漏洞测试"""

    # ========== 错误处理 ==========

    # [7.1] 空异常捕获
    def empty_except(self):
        try:
            result = int("abc")
        except:
            pass  # 空异常，静默忽略

    # [7.2] 过于宽泛的异常
    def broad_exception(self):
        try:
            with open("config.yaml", "r") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            # 捕获所有异常
            pass

    # ========== 代码质量 ==========

    # [8.1] 空指针解引用 (Python的None)
    def null_pointer_risk(self, config):
        return config["key"].lower()  # 如果config或config["key"]为None会抛异常

    # [8.2] 使用未初始化变量
    def uninitialized_var(self):
        if condition:
            value = load_config()
        return value  # 如果condition为False，value未定义

    # ========== SQL注入 ==========

    def sql_injection(self, user_id):
        query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL注入
        return query

    # [9.2] LIKE注入
    def like_injection(self, search):
        query = f"SELECT * FROM products WHERE name LIKE '%{search}%'"
        return query

    # ========== 命令注入 ==========

    def command_injection(self, filename):
        os.system("cat " + filename)  # 命令注入
        subprocess.call("ls -la " + filename, shell=True)  # 命令注入

    # ========== 代码注入 ==========

    def code_injection(self, code):
        exec(code)  # 代码注入

    def eval_injection(self, expr):
        result = eval(expr)  # eval注入
        return result

    # ========== XSS漏洞 ==========

    def xss_vulnerability(self, name, response):
        response.write("Hello " + name)  # 直接输出，未转义

    # ========== 文件操作 ==========

    def path_traversal(self, filename):
        path = os.path.join("/var/www/uploads/", filename)
        with open(path, "r") as f:  # 路径遍历
            return f.read()

    def arbitrary_file_read(self, path):
        with open(path, "r") as f:  # 任意文件读取
            return f.read()

    # ========== 反序列化 ==========

    def unsafe_deserialization(self, data):
        return pickle.loads(data)  # pickle反序列化漏洞

    # ========== SSRF ==========

    def ssrf(self, url):
        import urllib.request
        response = urllib.request.urlopen(url)  # SSRF
        return response.read()

    # ========== 数据保护 ==========

    # [15.1] 硬编码密钥
    AES_KEY = "1234567890abcdef"  # 硬编码密钥

    def hardcoded_key_usage(self, data):
        # 使用硬编码密钥
        return hashlib.aes_encrypt(self.AES_KEY, data)

    # [15.2] 敏感数据日志
    def log_sensitive_data(self, password):
        print("Password reset: " + password)  # 密码日志
        import logging
        logging.info("Token: " + password)

    # ========== YAML反序列化 ==========

    def yaml_deserialization(self, data):
        return yaml.load(data)  # 不安全，应该用yaml.safe_load

    # ========== XML注入 ==========

    def xxe_vulnerability(self, xml_string):
        tree = ET.parse(xml_string)  # XXE
        return tree.getroot()

    # ========== 路径遍历 ==========

    def directory_traversal(self, user_input):
        path = "/var/www/" + user_input
        return os.listdir(path)

    # ========== 弱加密 ==========

    def weak_hash(self, password):
        return hashlib.md5(password)  # MD5已被破解

    def weak_encryption(self, data):
        # 使用弱加密
        import base64
        return base64.b64encode(data)  # 只是编码，非加密

    # ========== 临时文件 ==========

    def insecure_temp_file(self):
        return os.tempnam("/tmp")  # 不安全的临时文件创建

    # ========== 辅助方法 ==========

    def condition(self):
        return False

    def load_config(self):
        return {}


def dynamic_import_vulnerability(module_name):
    """动态导入漏洞"""
    module = __import__(module_name)  # 任意模块导入
    return module


def subprocess_shell_true():
    """shell=True的危险性"""
    cmd = input("Enter command: ")
    subprocess.run(cmd, shell=True)  # 命令注入


if __name__ == "__main__":
    print("Running vulnerable code examples...")
