"""
Python代码安全测试样例
覆盖 GB/T 39412-2020 通用标准
规则编号对应标准章节
"""

import os
import pickle
import subprocess
import xml.etree.ElementTree as ET
import yaml
import hashlib
import random
import threading
import tempfile
import sqlite3
import urllib.request
import base64
import struct
import ctypes
import logging
from typing import Optional
from concurrent.futures import ThreadPoolExecutor


class VulnerablePython:
    """Python代码安全漏洞测试"""

    # ========== 6.1.1 输入验证 ==========

    # [GB/T39412-6.1.1.1] 关键状态数据被外部可控 🟠 HIGH
    def critical_state_data_external_control(self, user_input):
        self.is_admin = user_input  # 用户输入直接控制关键状态
        return self.is_admin

    # [GB/T39412-6.1.1.2] 数据真实性验证不足 🟠 HIGH
    def insufficient_data_validation(self, signed_data, signature):
        # 未验证签名真实性
        return signed_data  # 直接使用未验证的数据

    # [GB/T39412-6.1.1.3] 绕过数据净化和验证 🟠 HIGH
    def bypass_validation_case(self, input_str):
        # 大小写绕过风险
        if "script" in input_str.lower():  # 仅检查小写，可能被绕过
            return "blocked"
        return input_str

    # [GB/T39412-6.1.1.4] 在字符串验证前未进行过滤 🟡 MEDIUM
    def validate_before_filter(self, input_str):
        # 先验证再过滤，顺序错误
        if len(input_str) > 10:  # 先验证长度
            return input_str
        return input_str.replace("<", "")  # 后过滤

    # [GB/T39412-6.1.1.5] HTTP Head Web脚本特殊元素处理 🟠 HIGH
    def http_header_xss(self, user_input, response):
        response.headers["X-Custom"] = user_input  # HTTP头注入XSS风险

    # [GB/T39412-6.1.1.6] 命令行注入 🔴 CRITICAL
    def command_injection(self, filename):
        os.system("cat " + filename)  # 命令拼接
        subprocess.call("ls -la " + filename, shell=True)  # shell=True危险
        subprocess.run(f"grep pattern {filename}", shell=True)  # f-string拼接

    # [GB/T39412-6.1.1.7] 数据结构控制域缺安全 🟠 HIGH
    def data_structure_control_issue(self, data):
        data["length"] = 999999  # 修改数据结构控制域
        return data

    # [GB/T39412-6.1.1.8] 忽略字符串串尾符 🟡 MEDIUM
    def ignore_string_terminator(self, buffer, input_str):
        # 未预留结尾符空间
        buffer[:len(input_str)] = input_str.encode()  # 可能缺少'\0'

    # [GB/T39412-6.1.1.9] 对环境变量长度做出假设 🟡 MEDIUM
    def assume_env_length(self):
        env_value = os.environ.get("PATH", "")
        buffer = bytearray(256)  # 假设环境变量长度不超过256
        buffer[:len(env_value)] = env_value.encode()  # 可能溢出

    # [GB/T39412-6.1.1.10] 条件比较不充分 🟡 MEDIUM
    def insufficient_comparison(self, user_type):
        if user_type == "admin":  # 仅检查一种情况
            return True
        # 缺少其他类型的处理

    # [GB/T39412-6.1.1.11] 结构体长度 🟡 MEDIUM
    def struct_length_assumption(self):
        # 假设结构体长度等于各成员之和（Python中类似问题）
        total = 4 + 8 + 1  # 假设int+long+char的大小
        buffer = bytearray(total)  # 可能不够

    # [GB/T39412-6.1.1.12] 数值赋值越界 🟠 HIGH
    def integer_overflow(self, value):
        result = value * 1000000  # 可能溢出
        return result

    # [GB/T39412-6.1.1.13] 除零错误 🟡 MEDIUM
    def divide_by_zero(self, divisor):
        return 100 / divisor  # divisor可能为0

    # [GB/T39412-6.1.1.14] 边界值检查缺失 🟠 HIGH
    def missing_boundary_check(self, index, arr):
        return arr[index]  # 未检查index是否在有效范围内

    # [GB/T39412-6.1.1.15] 数据信任边界的违背 🟠 HIGH
    def trust_boundary_violation(self, user_input, internal_data):
        internal_data["user_value"] = user_input  # 不可信数据混入可信数据结构
        return internal_data

    # [GB/T39412-6.1.1.16] 条件语句缺失默认情况 🟢 LOW
    def missing_default_case(self, action):
        if action == "read":
            return "reading"
        elif action == "write":
            return "writing"
        # 缺少default/else处理

    # [GB/T39412-6.1.1.17] 无法执行的死代码 🟢 LOW
    def dead_code(self):
        return "result"
        print("This will never execute")  # 死代码

    # [GB/T39412-6.1.1.18] 表达式求真或永假 🟢 LOW
    def always_true_false(self):
        if True:  # 永真
            return "always"
        if False:  # 永假，永不执行
            return "never"

    # ========== 6.1.2 Web安全 ==========

    # [GB/T39412-6.1.2.1] 跨站脚本(XSS)攻击 🟠 HIGH
    def xss_vulnerability(self, name, response):
        response.write("Hello " + name)  # 直接输出，未转义

    # [GB/T39412-6.1.2.2] Web应用重定向后执行额外代码 🟡 MEDIUM
    def redirect_extra_code(self, response):
        response.redirect("/home")
        do_sensitive_operation()  # 重定向后继续执行代码

    # [GB/T39412-6.1.2.3] URL重定向向不可信站点 🟠 HIGH
    def open_redirect(self, url, response):
        response.redirect(url)  # url来自用户输入，未验证

    # ========== 6.2.1 密码安全 ==========

    # [GB/T39412-6.2.1.1] 密码安全不符合国密管理规定 🟠 HIGH
    def weak_crypto_algorithm(self, data):
        return hashlib.md5(data).hexdigest()  # MD5不符合国密要求

    # [GB/T39412-6.2.1.2] 随机数安全 🟠 HIGH
    def insufficient_randomness(self):
        return random.randint(0, 100)  # 使用不安全的random模块

    # [GB/T39412-6.2.1.3] 使用安全相关的硬编码 🔴 CRITICAL
    HARDCODED_KEY = "MySecretKey123456"  # 硬编码密钥
    HARDCODED_PASSWORD = "admin123"  # 硬编码密码
    API_KEY = "sk-abc123def456"  # 硬编码API密钥

    def hardcoded_key_usage(self, data):
        return hashlib.sha256(self.HARDCODED_KEY.encode() + data.encode())

    # ========== 6.2.2 信息保护 ==========

    # [GB/T39412-6.2.2.1] 敏感信息暴露 🟠 HIGH
    def sensitive_info_exposure(self, password):
        logging.info("User password: " + password)  # 密码写入日志
        print("Debug: token=" + get_token())  # 调试信息泄露

    # [GB/T39412-6.2.2.2] 个人信息保护不当 🟠 HIGH
    def improper_personal_info_handling(self, user_data):
        # 个人信息未加密存储
        store_user_data(user_data)  # 直接存储身份证号、手机号等

    # ========== 6.3.1 身份鉴别 ==========

    # [GB/T39412-6.3.1.1] 身份鉴别过程暴露多余信息 🟡 MEDIUM
    def auth_info_exposure(self, username):
        if not user_exists(username):
            return "用户名不存在"  # 暴露用户名是否存在
        return "密码错误"

    # [GB/T39412-6.3.1.2] 身份鉴别被绕过 🔴 CRITICAL
    def auth_bypass(self, request):
        if request.get("skip_auth") == "true":  # 可绕过的认证路径
            return True
        return verify_token(request.get("token"))

    # [GB/T39412-6.3.1.3] 身份鉴别尝试频率限制缺失 🟠 HIGH
    def no_rate_limit(self, username, password):
        # 无登录频率限制
        return check_password(username, password)

    # [GB/T39412-6.3.1.4] 多因素认证缺失 🟡 MEDIUM
    def single_factor_auth(self, username, password):
        # 仅依赖密码认证
        return verify_password(username, password)

    # ========== 6.3.2 口令安全 ==========

    # [GB/T39412-6.3.2.1] 登录口令不明文显示 🟢 LOW
    def password_display(self):
        password = input("Enter password: ")  # 未掩码显示

    # [GB/T39412-6.3.2.2] 明文存储口令 🔴 CRITICAL
    def plaintext_password_storage(self, username, password):
        conn = sqlite3.connect("users.db")
        conn.execute(f"INSERT INTO users VALUES ('{username}', '{password}')")  # 明文存储

    # [GB/T39412-6.3.2.3] 明文传递口令 🔴 CRITICAL
    def plaintext_password_transmission(self, password):
        # HTTP明文传输口令
        urllib.request.urlopen(f"http://api.example.com/login?password={password}")

    # ========== 6.3.3 权限控制 ==========

    # [GB/T39412-6.3.3.1] 权限访问控制缺失 🔴 CRITICAL
    def missing_access_control(self, user_id, resource_id):
        # 未检查用户是否有权限访问该资源
        return get_resource(resource_id)

    # [GB/T39412-6.3.3.2] 未加限制的外部可访问锁 🟠 HIGH
    def unrestricted_external_access(self, lock):
        # 外部可访问的锁无限制
        lock.acquire()
        return do_sensitive_work()

    # ========== 6.4.1 日志输出 ==========

    # [GB/T39412-6.4.1] 对输出日志中特殊元素处理 🟡 MEDIUM
    def log_injection(self, user_input):
        logging.info("User action: " + user_input)  # 日志注入风险

    # ========== 6.4.2 信息丢失 ==========

    # [GB/T39412-6.4.2] 信息丢失或遗漏 🟡 MEDIUM
    def info_loss(self, error):
        # 不记录关键安全事件
        pass  # 空处理，信息丢失

    # ========== 7.1.1 泛型使用 ==========

    # [GB/T39412-7.1.1] 混用具泛型和非泛型的数据类型 🟡 MEDIUM
    def mixed_generic_types(self):
        # Python中类似问题：混用类型注解和无类型
        data = []  # 无类型注解
        typed_data: list[str] = ["a", "b"]  # 有类型注解
        data.extend(typed_data)  # 混用

    # ========== 7.1.2 序列化 ==========

    # [GB/T39412-7.1.2] 包含敏感信息类的不可复制和不可序列化 🟠 HIGH
    class SensitiveClass:
        password: str  # 敏感信息，但类可序列化
        
        def __init__(self, password):
            self.password = password

    # ========== 7.1.3 类比较 ==========

    # [GB/T39412-7.1.3] 类比较 🟡 MEDIUM
    def class_name_comparison(self, obj1, obj2):
        return obj1.__class__.__name__ == obj2.__class__.__name__  # 仅比较类名

    # ========== 7.1.4 私有成员 ==========

    # [GB/T39412-7.1.4] 类私有可变成员的引用 🟢 LOW
    def return_private_mutable(self):
        self._internal_list = [1, 2, 3]
        return self._internal_list  # 返回私有可变成员的引用

    # ========== 7.1.5 序列化存储 ==========

    # [GB/T39412-7.1.5] 存储不可序列化的对象到磁盘 🟡 MEDIUM
    def store_non_serializable(self, obj):
        pickle.dump(obj, open("data.pkl", "wb"))  # 可能序列化失败

    # ========== 7.2.1 会话隔离 ==========

    # [GB/T39412-7.2.1] 不同会话间信息泄露 🟠 HIGH
    session_data = {}  # 全局变量，可能跨会话泄露
    
    def session_info_leak(self, user_id, data):
        self.session_data[user_id] = data  # 全局存储用户数据

    # ========== 7.2.2 初始化 ==========

    # [GB/T39412-7.2.2] 发布未完成初始化的对象 🟠 HIGH
    def publish_uninitialized(self):
        obj = self.SensitiveClass(None)
        register_callback(obj)  # 注册未完全初始化的对象
        obj.password = get_password()

    # ========== 7.2.3 并发安全 ==========

    # [GB/T39412-7.2.3] 共享资源的并发安全 🟠 HIGH
    counter = 0  # 共享变量无同步保护
    
    def unsafe_concurrent_access(self):
        self.counter += 1  # 非原子操作，竞态条件

    # ========== 7.2.4 子进程 ==========

    # [GB/T39412-7.2.4] 子进程访问进程敏感资源 🟠 HIGH
    def subprocess_sensitive_resource(self, sensitive_file):
        f = open(sensitive_file, "r")  # 打开敏感文件
        subprocess.Popen(["child_process"])  # 子进程可能继承文件描述符
        f.close()

    # ========== 7.2.5 线程资源 ==========

    # [GB/T39412-7.2.5] 释放线程专有对象 🟡 MEDIUM
    local_data = threading.local()
    
    def thread_local_leak(self):
        self.local_data.value = "sensitive"
        # 未调用清理，线程复用时可能泄露

    # ========== 7.3.1 格式化字符串 ==========

    # [GB/T39412-7.3.1] 格式化学符串 🟠 HIGH
    def format_string_vulnerability(self, user_input):
        # 格式化字符串来自用户输入
        return user_input.format(name="test")  # 可能泄露信息

    # ========== 7.3.2 参数验证 ==========

    # [GB/T39412-7.3.2] 对方法或函数参数进行验证 🟠 HIGH
    def no_parameter_validation(self, param):
        # 未验证参数
        return process(param)  # param可能为None或无效值

    # ========== 7.3.3 参数指定 ==========

    # [GB/T39412-7.3.3] 参数指定错误 🟡 MEDIUM
    def wrong_parameter_order(self, size, value):
        buffer = bytearray(value)  # 参数顺序可能错误
        buffer[:size] = b'\x00'

    # ========== 7.3.4 返回栈变量 ==========

    # [GB/T39412-7.3.4] 返回栈变量地址 🟠 HIGH
    def return_stack_reference(self):
        local_list = [1, 2, 3]
        return local_list  # Python中返回局部变量引用

    # ========== 7.3.5 不一致函数 ==========

    # [GB/T39412-7.3.5] 实现不一致函数 🟡 MEDIUM
    def inconsistent_function(self):
        # 使用平台行为不一致的函数
        return os.path.join("a", "b")  # 不同平台路径分隔符不同

    # ========== 7.3.6 暴露危险方法 ==========

    # [GB/T39412-7.3.6] 暴露危险的方法或函数 🔴 CRITICAL
    def exposed_dangerous_method(self, code):
        exec(code)  # 暴露代码执行能力
        eval(code)  # 暴露eval能力

    # ========== 7.4.1 异常处理 ==========

    # [GB/T39412-7.4.1] 异常处理不当 🟡 MEDIUM
    def improper_exception_handling(self):
        try:
            do_something()
        except:
            pass  # 空catch块，静默忽略异常

    # ========== 7.5.1 指针类型 ==========

    # [GB/T39412-7.5.1] 不兼容的指针类型 🟠 HIGH (C扩展)
    def incompatible_pointer_type(self):
        # Python C扩展中可能存在此问题
        ptr = ctypes.c_void_p(0x1234)
        int_ptr = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_int))  # 不兼容类型转换

    # ========== 7.5.2 指针减法 ==========

    # [GB/T39412-7.5.2] 利用指针减法确定内存大小 🟠 HIGH (C扩展)
    def pointer_subtraction_size(self):
        # Python C扩展中可能存在此问题
        arr = (ctypes.c_int * 10)()
        ptr1 = ctypes.pointer(arr[0])
        ptr2 = ctypes.pointer(arr[5])
        size = ptr2.value - ptr1.value  # 指针减法计算大小

    # ========== 7.5.3 固定地址 ==========

    # [GB/T39412-7.5.3] 将固定地址赋值给指针 🟠 HIGH (C扩展)
    def fixed_address_pointer(self):
        ptr = ctypes.c_void_p(0x12345678)  # 固定地址赋值给指针

    # ========== 7.5.4 非结构体指针 ==========

    # [GB/T39412-7.5.4] 试访非结构体类型指针的数据域 🟡 MEDIUM (C扩展)
    def access_non_struct_pointer(self):
        # Python C扩展中可能存在此问题
        ptr = ctypes.c_void_p(0x1234)
        struct_ptr = ctypes.cast(ptr, ctypes.POINTER(MyStruct))  # 强转并访问字段

    # ========== 7.5.5 指针偏移 ==========

    # [GB/T39412-7.5.5] 指针偏移越界 🟠 HIGH (C扩展)
    def pointer_offset_out_of_bounds(self):
        arr = (ctypes.c_int * 5)()
        ptr = ctypes.pointer(arr[0])
        out_of_bounds = ptr[10]  # 偏移越界

    # ========== 7.5.6 无效指针 ==========

    # [GB/T39412-7.5.6] 无效指针使用 🟠 HIGH (C扩展)
    def invalid_pointer_use(self):
        ptr = ctypes.c_void_p()
        value = ptr.value  # 使用未初始化的指针

    # ========== 8.1.1 重复释放 ==========

    # [GB/T39412-8.1.1] 重复释放资源 🟠 HIGH
    def double_free(self):
        f = open("temp.txt", "w")
        f.close()
        f.close()  # 重复关闭

    # ========== 8.1.2 不安全初始化 ==========

    # [GB/T39412-8.1.2] 资源或变量不安全初始化 🟠 HIGH
    def unsafe_initialization(self):
        # 使用外部输入初始化关键变量
        self.config_value = os.environ.get("CONFIG_VALUE")  # 未验证的环境变量

    # ========== 8.1.3 初始化失败 ==========

    # [GB/T39412-8.1.3] 初始化失败后未安全退出 🟡 MEDIUM
    def init_failure_no_exit(self):
        try:
            init_critical_resource()
        except Exception:
            pass  # 初始化失败后未安全退出

    # ========== 8.1.4 引用计数 ==========

    # [GB/T39412-8.1.4] 引用计数的更新不正确 🟡 MEDIUM
    def incorrect_reference_count(self):
        # Python中引用计数由GC管理，但C扩展中可能有问题
        pass

    # ========== 8.1.5 资源清理 ==========

    # [GB/T39412-8.1.5] 资源不安全清理 🟡 MEDIUM
    def unsafe_resource_cleanup(self):
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        # 使用后未删除临时文件
        temp_file.write(b"data")

    # ========== 8.1.6 资源暴露 ==========

    # [GB/T39412-8.1.6] 资源暴露给非授权范围 🟡 MEDIUM
    def resource_exposure(self):
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        temp_file.write("sensitive data")
        # 临时文件权限可能过于宽松

    # ========== 8.1.7 递归 ==========

    # [GB/T39412-8.1.7] 未经控制的递归 🟡 MEDIUM
    def uncontrolled_recursion(self, n):
        if n > 0:
            return self.uncontrolled_recursion(n - 1) + self.uncontrolled_recursion(n - 2)
        return 1  # 无递归深度限制

    # ========== 8.1.8 无限循环 ==========

    # [GB/T39412-8.1.8] 无限循环 🟠 HIGH
    def infinite_loop(self, condition):
        while True:  # 无退出条件
            process_data()

    # ========== 8.1.9 算法复杂度 ==========

    # [GB/T39412-8.1.9] 算法复杂度攻击 🟠 HIGH
    def algorithm_complexity_attack(self, data):
        # 用户输入可能导致算法进入最坏情况
        sorted_data = sorted(data)  # 特定输入可能导致O(n²)

    # ========== 8.2.1 内存配对 ==========

    # [GB/T39412-8.2.1] 内存分配释放函数成对调用 🟠 HIGH
    def memory_allocation_pair(self):
        buffer = bytearray(1024)
        # Python中内存由GC管理，但C扩展中可能有问题
        pass

    # ========== 8.2.2 堆内存清理 ==========

    # [GB/T39412-8.2.2] 堆内存释放 🟠 HIGH
    def heap_memory_cleanup(self, password_buffer):
        # 释放前未清理敏感数据
        password_buffer = None  # 仅置空，未清零

    # ========== 8.2.3 内存泄漏 ==========

    # [GB/T39412-8.2.3] 内存未释放 🟡 MEDIUM
    def memory_leak(self):
        global_cache = []
        global_cache.append(large_object())  # 不断增长，内存泄漏

    # ========== 8.2.4 访问已释放内存 ==========

    # [GB/T39412-8.2.4] 访问已释放内存 🟠 HIGH
    def use_after_free(self):
        obj = create_object()
        obj.close()
        return obj.get_value()  # 访问已释放的对象

    # ========== 8.2.5 内存布局 ==========

    # [GB/T39412-8.2.5] 数据/内存布局 🟡 MEDIUM
    def memory_layout_assumption(self):
        # 假设内存布局
        struct_size = 4 + 8 + 1  # 假设字段大小之和

    # ========== 8.2.6 缓冲区越界 ==========

    # [GB/T39412-8.2.6] 内存缓冲区边界操作越界 🟠 HIGH
    def buffer_overflow(self, input_data):
        buffer = bytearray(64)
        buffer[:len(input_data)] = input_data  # 可能越界

    # ========== 8.2.7 复制溢出 ==========

    # [GB/T39412-8.2.7] 缓冲区复制制造溢出 🟠 HIGH
    def copy_overflow(self, source):
        dest = bytearray(10)
        dest[:] = source  # source可能大于dest

    # ========== 8.2.8 错误长度 ==========

    # [GB/T39412-8.2.8] 使用错误长度访问缓冲区 🟠 HIGH
    def wrong_length_access(self, data):
        buffer = bytearray(len(data) // 2)  # 错误的长度计算
        buffer[:] = data.encode()  # 可能溢出

    # ========== 8.2.9 堆空间耗尽 ==========

    # [GB/T39412-8.2.9] 堆空间耗尽 🟠 HIGH
    def heap_exhaustion(self):
        big_list = []
        for i in range(10000000):
            big_list.append(bytearray(1024 * 1024))  # 消耗大量内存

    # ========== 8.3.1 数据库资源 ==========

    # [GB/T39412-8.3.1] 及时释放数据库资源 🟡 MEDIUM
    def database_resource_leak(self):
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        # 未关闭连接

    # ========== 8.3.2 SQL注入 ==========

    # [GB/T39412-8.3.2] SQL注入 🔴 CRITICAL
    def sql_injection(self, user_id):
        conn = sqlite3.connect("database.db")
        query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL拼接
        return conn.execute(query).fetchall()

    # ========== 反序列化 ==========

    def unsafe_deserialization(self, data):
        return pickle.loads(data)  # pickle反序列化漏洞

    def yaml_deserialization(self, data):
        return yaml.load(data)  # 不安全，应使用yaml.safe_load

    # ========== SSRF ==========

    def ssrf(self, url):
        response = urllib.request.urlopen(url)  # SSRF
        return response.read()

    # ========== 文件操作 ==========

    def path_traversal(self, filename):
        path = os.path.join("/var/www/uploads/", filename)
        with open(path, "r") as f:  # 路径遍历
            return f.read()

    def arbitrary_file_read(self, path):
        with open(path, "r") as f:  # 任意文件读取
            return f.read()

    # ========== 辅助方法 ==========

    def user_exists(self, username): return True
    def verify_token(self, token): return token == "valid"
    def check_password(self, username, password): return True
    def verify_password(self, username, password): return True
    def get_resource(self, resource_id): return "data"
    def do_sensitive_work(self): return "done"
    def get_token(self): return "secret_token"
    def store_user_data(self, data): pass
    def do_something(self): pass
    def process(self, param): return param
    def register_callback(self, obj): pass
    def get_password(self): return "password"
    def init_critical_resource(self): pass
    def process_data(self): pass
    def large_object(self): return bytearray(1024)
    def create_object(self): return MockObject()
    def do_sensitive_operation(self): pass


class MockObject:
    def close(self): pass
    def get_value(self): return "value"


class MyStruct(ctypes.Structure):
    _fields_ = [("field1", ctypes.c_int), ("field2", ctypes.c_char)]


def dynamic_import_vulnerability(module_name):
    """动态导入漏洞"""
    module = __import__(module_name)  # 任意模块导入
    return module


def subprocess_shell_true():
    """shell=True的危险性"""
    cmd = input("Enter command: ")
    subprocess.run(cmd, shell=True)  # 命令注入


if __name__ == "__main__":
    print("GB/T 39412-2020 Python Vulnerability Test Samples")