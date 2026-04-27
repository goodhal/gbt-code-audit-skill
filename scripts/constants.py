"""
常量定义模块
包含语言映射、国标映射、工具配置等常量
"""
from pathlib import Path
import os

MAX_WORKERS = 4

SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent

BASELINE_DIR = PROJECT_ROOT / "findings" / "baseline"
LLM_AUDIT_DIR = PROJECT_ROOT / "findings" / "llm_audit"
FINDINGS_DIR = PROJECT_ROOT / "findings"

SEVERITY_ORDER = ["严重", "高危", "中危", "低危"]
SEVERITY_CRITICAL = "严重"
SEVERITY_HIGH = "高危"
SEVERITY_MEDIUM = "中危"
SEVERITY_LOW = "低危"

LANGUAGE_EXTENSIONS = {
    "java": [".java"],
    "python": [".py", ".pyw"],
    "cpp": [".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"],
    "csharp": [".cs"],
    "go": [".go"],
    "javascript": [".js", ".jsx", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx"],
    "php": [".php", ".phtml", ".php3", ".php4", ".php5"],
    "ruby": [".rb", ".rbw"],
    "rust": [".rs"],
    "kotlin": [".kt", ".kts"],
    "swift": [".swift"],
    "scala": [".scala", ".sc"],
    "perl": [".pl", ".pm", ".t"],
    "lua": [".lua"],
    "shell": [".sh", ".bash", ".zsh"],
}

LANGUAGES_WITH_DEDICATED_STANDARD = {
    "java": "GB/T34944",
    "cpp": "GB/T34943",
    "c": "GB/T34943",
    "csharp": "GB/T34946",
}

VALID_GBT_PREFIXES = list(set(list(LANGUAGES_WITH_DEDICATED_STANDARD.values()) + ["GB/T39412"]))

GBT_PREFIX_TO_STANDARD = {
    "GB/T34943": "GB/T 34943-2017",
    "GB/T34944": "GB/T 34944-2017",
    "GB/T34946": "GB/T 34946-2017",
    "GB/T39412": "GB/T 39412-2020",
}

GBT_PREFIX_TO_DESCRIPTION = {
    "GB/T34943": "C/C++ 语言源代码漏洞测试规范",
    "GB/T34944": "Java 语言源代码漏洞测试规范",
    "GB/T34946": "C# 语言源代码漏洞测试规范",
    "GB/T39412": "网络安全技术 源代码漏洞检测规则",
}

TOOL_SUPPORTED_LANGUAGES = {
    "bandit": ["python"],
    "semgrep": ["java", "python", "cpp", "csharp", "go", "javascript", "typescript", "ruby", "rust"],
    "gitleaks": ["all"],
}

EXTERNAL_TOOLS = {
    "bandit": {"cmd": "bandit", "args": ["-r", "-f", "json"]},
    "semgrep": {"cmd": "semgrep", "args": ["--config", "auto", "--json"]},
    "gitleaks": {"cmd": "gitleaks", "args": ["detect", "--report-format", "json"]},
}

TOOL_PRIORITY = ["gitleaks", "bandit", "semgrep"]

EXTERNAL_TOOLS_AVAILABLE = {}

REQUIRED_FIELDS = [
    "file", "line", "type", "severity", "gbt_mapping", 
    "description", "code_snippet", "source",
    "cwe", "status"
]

LLM_REQUIRED_FIELDS = [
    "fix"
]

SEVERITY_DESC = {
    "严重": "可能导致系统被完全控制、数据泄露或服务中断",
    "高危": "可能导致数据泄露、权限提升或服务部分中断",
    "中危": "可能导致有限的信息泄露或功能异常",
    "低危": "影响较小，可能导致轻微的信息泄露或功能异常",
}

SEVERITY_TO_ENGLISH = {
    "严重": "CRITICAL",
    "高危": "HIGH",
    "中危": "MEDIUM",
    "低危": "LOW",
}

ENGLISH_TO_SEVERITY = {v: k for k, v in SEVERITY_TO_ENGLISH.items()}

VULN_TYPE_TO_GBT_MAPPING = {
    "COMMAND_INJECTION": {
        "java": "GB/T34944-6.2.3.3 命令注入；GB/T39412-6.1.1.6 命令行注入",
        "python": "GB/T39412-6.1.1.6 命令行注入",
        "cpp": "GB/T34943-6.2.3.3 命令注入；GB/T39412-6.1.1.6 命令行注入",
        "csharp": "GB/T34946-6.2.3.3 命令注入；GB/T39412-6.1.1.6 命令行注入",
    },
    "SQL_INJECTION": {
        "java": "GB/T34944-6.2.3.4 SQL注入；GB/T39412-8.3.2 SQL注入",
        "python": "GB/T39412-8.3.2 SQL注入",
        "cpp": "GB/T34943-6.2.3.4 SQL注入；GB/T39412-8.3.2 SQL注入",
        "csharp": "GB/T34946-6.2.3.4 SQL注入；GB/T39412-8.3.2 SQL注入",
    },
    "CODE_INJECTION": {
        "java": "GB/T34944-6.2.3.5 代码注入；GB/T39412-7.3.6 暴露危险的方法或函数",
        "python": "GB/T39412-7.3.6 暴露危险的方法或函数",
        "cpp": "GB/T34943-6.2.3.5 进程控制；GB/T39412-7.3.6 暴露危险的方法或函数",
        "csharp": "GB/T34946-6.2.3.5 代码注入；GB/T39412-7.3.6 暴露危险的方法或函数",
    },
    "XPATH_INJECTION": {
        "java": "GB/T34944-6.2.3.12 XPath注入",
        "python": "GB/T39412-6.1.1.1 输入验证不足",
        "cpp": "GB/T39412-6.1.1.1 输入验证不足",
        "csharp": "GB/T34946-6.2.3.12 XPath注入",
    },
    "PATH_TRAVERSAL": {
        "java": "GB/T34944-6.2.3.1 相对路径遍历；GB/T34944-6.2.3.2 绝对路径遍历",
        "python": "GB/T39412-6.1.1.1 输入验证不足",
        "cpp": "GB/T34943-6.2.3.1 相对路径遍历；GB/T34943-6.2.3.2 绝对路径遍历",
        "csharp": "GB/T34946-6.2.3.1 相对路径遍历；GB/T34946-6.2.3.2 绝对路径遍历",
    },
    "HARD_CODE_PASSWORD": {
        "java": "GB/T34944-6.2.6.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
        "python": "GB/T39412-6.2.1.3 使用安全相关的硬编码",
        "cpp": "GB/T34943-6.2.7.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
        "csharp": "GB/T34946-6.2.6.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
    },
    "HARD_CODE_SECRET": {
        "java": "GB/T34944-6.2.6.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
        "python": "GB/T39412-6.2.1.3 使用安全相关的硬编码",
        "cpp": "GB/T34943-6.2.7.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
        "csharp": "GB/T34946-6.2.6.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
    },
    "HARDCODED_KEY": {
        "java": "GB/T34944-6.2.6.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
        "python": "GB/T39412-6.2.1.3 使用安全相关的硬编码",
        "cpp": "GB/T34943-6.2.7.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
        "csharp": "GB/T34946-6.2.6.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
    },
    "WEAK_CRYPTO": {
        "java": "GB/T34944-6.2.6.7 使用已破解或危险的加密算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        "python": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        "cpp": "GB/T34943-6.2.7.5 使用已破解或危险的加密算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        "csharp": "GB/T34946-6.2.6.7 使用已破解或危险的加密算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
    },
    "WEAK_HASH": {
        "java": "GB/T34944-6.2.6.8 可逆的散列算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        "python": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        "cpp": "GB/T34943-6.2.7.6 可逆的散列算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        "csharp": "GB/T34946-6.2.6.8 可逆的散列算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
    },
    "NO_SALT_HASH": {
        "java": "GB/T34944-6.2.6.18 未使用盐值计算散列值",
        "python": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        "cpp": "GB/T34943-6.2.3.14 未使用盐值计算散列值",
        "csharp": "GB/T34946-6.2.6.17 未使用盐值计算散列值",
    },
    "PREDICTABLE_RANDOM": {
        "java": "GB/T34944-6.2.6.10 不充分的随机数；GB/T39412-6.2.1.2 随机数安全",
        "python": "GB/T39412-6.2.1.2 随机数安全",
        "cpp": "GB/T34943-6.2.7.8 不充分的随机数；GB/T39412-6.2.1.2 随机数安全",
        "csharp": "GB/T34946-6.2.6.10 不充分的随机数；GB/T39412-6.2.1.2 随机数安全",
    },
    "FIXED_IV": {
        "java": "GB/T34944-6.2.6.9 密码分组链接模式未使用随机初始化矢量",
        "python": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        "cpp": "GB/T34943-6.2.7.7 密码分组链接模式未使用随机初始化矢量",
        "csharp": "GB/T34946-6.2.6.9 密码分组链接模式未使用随机初始化矢量",
    },
    "RSA_PADDING": {
        "java": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        "python": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
        "cpp": "GB/T34943-6.2.7.14 RSA算法未使用最优非对称加密填充",
        "csharp": "GB/T34946-6.2.6.18 RSA算法未使用最优非对称加密填充",
    },
    "PROCESS_CONTROL": {
        "java": "GB/T34944-6.2.3.6 进程控制",
        "python": "GB/T39412-7.3.6 暴露危险的方法或函数",
        "cpp": "GB/T34943-6.2.3.5 进程控制",
        "csharp": "GB/T34946-6.2.3.6 进程控制",
    },
    "DESERIALIZATION": {
        "java": "GB/T39412-7.1.5 存储不可序列化的对象到磁盘",
        "python": "GB/T39412-7.1.5 存储不可序列化的对象到磁盘",
        "cpp": "GB/T39412-7.1.5 存储不可序列化的对象到磁盘",
        "csharp": "GB/T39412-7.1.5 存储不可序列化的对象到磁盘",
    },
    "SSRF": {
        "java": "GB/T39412-6.1.1.1 输入验证不足",
        "python": "GB/T39412-6.1.1.1 输入验证不足",
        "cpp": "GB/T39412-6.1.1.1 输入验证不足",
        "csharp": "GB/T39412-6.1.1.1 输入验证不足",
    },
    "INFO_LEAK": {
        "java": "GB/T34944-6.2.3.7 信息通过错误消息泄露；GB/T34944-6.2.3.8 信息通过服务器日志文件泄露",
        "python": "GB/T39412-6.2.2.1 敏感信息暴露",
        "cpp": "GB/T34943-6.2.3.9 信息通过错误消息泄露；GB/T34943-6.2.3.10 信息通过服务器日志文件泄露",
        "csharp": "GB/T34946-6.2.3.7 信息通过错误消息泄露；GB/T34946-6.2.3.8 信息通过服务器日志文件泄露",
    },
    "SESSION_FIXATION": {
        "java": "GB/T34944-6.2.7.1 会话固定",
        "python": "GB/T39412-7.2.1 不同会话间信息泄露",
        "cpp": "GB/T39412-7.2.1 不同会话间信息泄露",
        "csharp": "GB/T34946-6.2.7.1 会话固定",
    },
    "COOKIE_MANIPULATION": {
        "java": "GB/T34944-6.2.6.5 Cookie中的敏感信息明文存储",
        "python": "GB/T39412-6.2.2.1 敏感信息暴露",
        "cpp": "GB/T39412-6.2.2.1 敏感信息暴露",
        "csharp": "GB/T34946-6.2.6.5 Cookie中的敏感信息明文存储",
    },
    "AUTH_BYPASS": {
        "java": "GB/T34944-6.2.6.4 依赖referer字段进行身份鉴别；GB/T39412-6.3.1.2 身份鉴别被绕过",
        "python": "GB/T39412-6.3.1.2 身份鉴别被绕过",
        "cpp": "GB/T39412-6.3.1.2 身份鉴别被绕过",
        "csharp": "GB/T34946-6.2.6.4 依赖Referer字段进行身份鉴别；GB/T39412-6.3.1.2 身份鉴别被绕过",
    },
    "MISSING_ACCESS_CONTROL": {
        "java": "GB/T39412-6.3.3.1 权限访问控制缺失",
        "python": "GB/T39412-6.3.3.1 权限访问控制缺失",
        "cpp": "GB/T39412-6.3.3.1 权限访问控制缺失",
        "csharp": "GB/T39412-6.3.3.1 权限访问控制缺失",
    },
    "INFINITE_LOOP": {
        "java": "GB/T39412-8.1.8 无限循环",
        "python": "GB/T39412-8.1.8 无限循环",
        "cpp": "GB/T39412-8.1.8 无限循环",
        "csharp": "GB/T39412-8.1.8 无限循环",
    },
    "RESOURCE_EXHAUSTION": {
        "java": "GB/T39412-8.1.9 算法复杂度攻击",
        "python": "GB/T39412-8.1.9 算法复杂度攻击",
        "cpp": "GB/T39412-8.1.9 算法复杂度攻击",
        "csharp": "GB/T39412-8.1.9 算法复杂度攻击",
    },
    "UNCONTROLLED_MEMORY": {
        "java": "GB/T34944-6.2.1.1 不可控的内存分配",
        "python": "GB/T39412-8.2.1 内存分配释放函数成对调用",
        "cpp": "GB/T34943-6.2.1.1 不可控的内存分配",
        "csharp": "GB/T34946-6.2.1.1 不可控的内存分配",
    },
    "IMPROPER_EXCEPTION_HANDLING": {
        "java": "GB/T39412-7.4.1 异常处理不当",
        "python": "GB/T39412-7.4.1 异常处理不当",
        "cpp": "GB/T39412-7.4.1 异常处理不当",
        "csharp": "GB/T39412-7.4.1 异常处理不当",
    },
    "WEAK_PASSWORD_POLICY": {
        "java": "GB/T34944-6.2.6.13 没有要求使用强口令",
        "python": "GB/T39412-6.3.2.4 口令复杂度要求不足",
        "cpp": "GB/T34943-6.2.7.10 没有要求使用强口令",
        "csharp": "GB/T34946-6.2.6.12 没有要求使用强口令",
    },
    "TRUST_BOUNDARY_VIOLATION": {
        "java": "GB/T34944-6.2.5.2 违反信任边界；GB/T39412-6.1.1.15 数据信任边界的违背",
        "python": "GB/T39412-6.1.1.15 数据信任边界的违背",
        "cpp": "GB/T39412-6.1.1.15 数据信任边界的违背",
        "csharp": "GB/T34946-6.2.5.1 违反信任边界",
    },
    "SESSION_TIMEOUT": {
        "java": "GB/T34944-6.2.7.2 会话永不超时",
        "python": "GB/T39412-7.2.1 不同会话间信息泄露",
        "cpp": "GB/T39412-7.2.1 不同会话间信息泄露",
        "csharp": "GB/T34946-6.2.7.2 会话永不过期",
    },
    "DNS_TRUST": {
        "java": "GB/T34944-6.2.6.11 安全关键的行为依赖反向域名解析",
        "python": "GB/T39412-6.1.1.1 输入验证不足",
        "cpp": "GB/T34943-6.2.7.9 安全关键的行为依赖反向域名解析",
        "csharp": "GB/T34946-6.2.6.11 安全关键的行为依赖反向域名解析",
    },
    "PLAINTEXT_TRANSMISSION": {
        "java": "GB/T34944-6.2.6.6 敏感信息明文传输",
        "python": "GB/T39412-6.3.2.3 明文传递口令",
        "cpp": "GB/T34943-6.2.7.4 敏感信息明文传输",
        "csharp": "GB/T34946-6.2.6.6 敏感信息明文传输",
    },
    "COOKIE_AUTH_BYPASS": {
        "java": "GB/T34944-6.2.6.15 依赖未经验证和完整性检查的cookie",
        "python": "GB/T39412-6.3.1.2 身份鉴别被绕过",
        "cpp": "GB/T39412-6.3.1.2 身份鉴别被绕过",
        "csharp": "GB/T34946-6.2.6.14 依赖未经验证和完整性检查的Cookie",
    },
    "STACK_TRACE_LEAK": {
        "java": "GB/T34944-6.2.3.7 信息通过错误消息泄露",
        "python": "GB/T39412-6.2.2.1 敏感信息暴露",
        "cpp": "GB/T34943-6.2.3.9 信息通过错误消息泄露",
        "csharp": "GB/T34946-6.2.3.7 信息通过错误消息泄露",
    },
    "ERROR_MSG_LEAK": {
        "java": "GB/T34944-6.2.3.7 信息通过错误消息泄露",
        "python": "GB/T39412-6.2.2.1 敏感信息暴露",
        "cpp": "GB/T34943-6.2.3.9 信息通过错误消息泄露",
        "csharp": "GB/T34946-6.2.3.7 信息通过错误消息泄露",
    },
    "PARAMETER_TAMPERING": {
        "java": "GB/T34944-6.2.6.12 关键参数篡改",
        "python": "GB/T39412-6.1.1.1 输入验证不足",
        "cpp": "GB/T39412-6.1.1.1 输入验证不足",
        "csharp": "GB/T39412-6.1.1.1 输入验证不足",
    },
    "PERSISTENT_COOKIE": {
        "java": "GB/T34944-6.2.3.10 信息通过持久cookie泄露",
        "python": "GB/T39412-6.2.2.1 敏感信息暴露",
        "cpp": "GB/T39412-6.2.2.1 敏感信息暴露",
        "csharp": "GB/T34946-6.2.3.10 信息通过持久Cookie泄露",
    },
    "COOKIE_SECURE_MISSING": {
        "java": "GB/T34944-6.2.6.17 HTTPS会话中的敏感cookie没有设置安全性",
        "python": "GB/T39412-6.2.2.1 敏感信息暴露",
        "cpp": "GB/T39412-6.2.2.1 敏感信息暴露",
        "csharp": "GB/T34946-6.2.6.16 HTTPS会话中的敏感cookie没有设置安全属性",
    },
    "UNRESTRICTED_UPLOAD": {
        "java": "GB/T34944-6.2.4.1 未限制危险类型文件的上传",
        "python": "GB/T39412-6.1.1.1 输入验证不足",
        "cpp": "GB/T39412-6.1.1.1 输入验证不足",
        "csharp": "GB/T34946-6.2.4.1 未限制危险类型文件的上传",
    },
    "SENSITIVE_SERIALIZATION": {
        "java": "GB/T34944-6.2.5.1 可序列化的类包含敏感数据",
        "python": "GB/T39412-7.1.2 包含敏感信息类的不可复制和不可序列化",
        "cpp": "GB/T39412-7.1.2 包含敏感信息类的不可复制和不可序列化",
        "csharp": "GB/T39412-7.1.2 包含敏感信息类的不可复制和不可序列化",
    },
    "SENSITIVE_FIELD": {
        "java": "GB/T34944-6.2.5.1 可序列化的类包含敏感数据",
        "python": "GB/T39412-7.1.2 包含敏感信息类的不可复制和不可序列化",
        "cpp": "GB/T39412-7.1.2 包含敏感信息类的不可复制和不可序列化",
        "csharp": "GB/T39412-7.1.2 包含敏感信息类的不可复制和不可序列化",
    },
    "BUFFER_OVERFLOW": {
        "java": "GB/T39412-8.2.6 内存缓冲区边界操作越界",
        "python": "GB/T39412-8.2.6 内存缓冲区边界操作越界",
        "cpp": "GB/T34943-6.2.3.6 缓冲区溢出",
        "csharp": "GB/T39412-8.2.6 内存缓冲区边界操作越界",
    },
    "FORMAT_STRING": {
        "java": "GB/T39412-7.3.1 格式化字符串",
        "python": "GB/T39412-7.3.1 格式化字符串",
        "cpp": "GB/T34943-6.2.3.7 格式化字符串漏洞",
        "csharp": "GB/T39412-7.3.1 格式化字符串",
    },
    "INTEGER_OVERFLOW": {
        "java": "GB/T39412-6.1.1.12 数值赋值越界",
        "python": "GB/T39412-6.1.1.12 数值赋值越界",
        "cpp": "GB/T34943-6.2.3.8 整数溢出",
        "csharp": "GB/T39412-6.1.1.12 数值赋值越界",
    },
    "RACE_CONDITION": {
        "java": "GB/T39412-7.2.3 共享资源的并发安全",
        "python": "GB/T39412-7.2.3 共享资源的并发安全",
        "cpp": "GB/T39412-7.2.3 共享资源的并发安全",
        "csharp": "GB/T39412-7.2.3 共享资源的并发安全",
    },
    "SESSION_INFO_LEAK": {
        "java": "GB/T39412-7.2.1 不同会话间信息泄露",
        "python": "GB/T39412-7.2.1 不同会话间信息泄露",
        "cpp": "GB/T39412-7.2.1 不同会话间信息泄露",
        "csharp": "GB/T39412-7.2.1 不同会话间信息泄露",
    },
    "AUTH_INFO_EXPOSURE": {
        "java": "GB/T39412-6.3.1.1 身份鉴别过程暴露多余信息",
        "python": "GB/T39412-6.3.1.1 身份鉴别过程暴露多余信息",
        "cpp": "GB/T39412-6.3.1.1 身份鉴别过程暴露多余信息",
        "csharp": "GB/T39412-6.3.1.1 身份鉴别过程暴露多余信息",
    },
    "PASSWORD_DISPLAY": {
        "java": "GB/T34944-6.2.6.14 没有对口令域进行掩饰",
        "python": "GB/T39412-6.3.2.1 登录口令不明文显示",
        "cpp": "GB/T34943-6.2.7.11 没有对口令域进行掩饰",
        "csharp": "GB/T34946-6.2.6.13 没有对口令域进行掩饰",
    },
    "PERSONAL_INFO_EXPOSURE": {
        "java": "GB/T39412-6.2.2.2 个人信息保护不当",
        "python": "GB/T39412-6.2.2.2 个人信息保护不当",
        "cpp": "GB/T39412-6.2.2.2 个人信息保护不当",
        "csharp": "GB/T39412-6.2.2.2 个人信息保护不当",
    },
    "SENSITIVE_OPERATION": {
        "java": "GB/T39412-6.3.3.1 权限访问控制缺失",
        "python": "GB/T39412-6.3.3.1 权限访问控制缺失",
        "cpp": "GB/T39412-6.3.3.1 权限访问控制缺失",
        "csharp": "GB/T39412-6.3.3.1 权限访问控制缺失",
    },
    "UNINITIALIZED_OBJECT": {
        "java": "GB/T39412-7.2.2 发布未完成初始化的对象",
        "python": "GB/T39412-7.2.2 发布未完成初始化的对象",
        "cpp": "GB/T39412-7.2.2 发布未完成初始化的对象",
        "csharp": "GB/T39412-7.2.2 发布未完成初始化的对象",
    },
    "THREAD_LOCAL_LEAK": {
        "java": "GB/T39412-7.2.5 释放线程专有对象",
        "python": "GB/T39412-7.2.5 释放线程专有对象",
        "cpp": "GB/T39412-7.2.5 释放线程专有对象",
        "csharp": "GB/T39412-7.2.5 释放线程专有对象",
    },
    "DOUBLE_FREE": {
        "java": "GB/T39412-8.1.1 重复释放资源",
        "python": "GB/T39412-8.1.1 重复释放资源",
        "cpp": "GB/T39412-8.1.1 重复释放资源",
        "csharp": "GB/T39412-8.1.1 重复释放资源",
    },
    "USE_AFTER_FREE": {
        "java": "GB/T39412-8.2.4 访问已释放内存",
        "python": "GB/T39412-8.2.4 访问已释放内存",
        "cpp": "GB/T39412-8.2.4 访问已释放内存",
        "csharp": "GB/T39412-8.2.4 访问已释放内存",
    },
    "TEMP_FILE_EXPOSURE": {
        "java": "GB/T39412-8.1.6 资源暴露给非授权范围",
        "python": "GB/T39412-8.1.6 资源暴露给非授权范围",
        "cpp": "GB/T39412-8.1.6 资源暴露给非授权范围",
        "csharp": "GB/T39412-8.1.6 资源暴露给非授权范围",
    },
    "MEMORY_LEAK": {
        "java": "GB/T39412-8.2.3 内存未释放",
        "python": "GB/T39412-8.2.3 内存未释放",
        "cpp": "GB/T39412-8.2.3 内存未释放",
        "csharp": "GB/T39412-8.2.3 内存未释放",
    },
    "UNCONTROLLED_RECURSION": {
        "java": "GB/T39412-8.1.7 未经控制的递归",
        "python": "GB/T39412-8.1.7 未经控制的递归",
        "cpp": "GB/T39412-8.1.7 未经控制的递归",
        "csharp": "GB/T39412-8.1.7 未经控制的递归",
    },
    "DIVIDE_BY_ZERO": {
        "java": "GB/T39412-6.1.1.13 除零错误",
        "python": "GB/T39412-6.1.1.13 除零错误",
        "cpp": "GB/T39412-6.1.1.13 除零错误",
        "csharp": "GB/T39412-6.1.1.13 除零错误",
    },
    "MISSING_BOUNDARY_CHECK": {
        "java": "GB/T39412-6.1.1.14 边界值检查缺失",
        "python": "GB/T39412-6.1.1.14 边界值检查缺失",
        "cpp": "GB/T39412-6.1.1.14 边界值检查缺失",
        "csharp": "GB/T39412-6.1.1.14 边界值检查缺失",
    },
    "DEAD_CODE": {
        "java": "GB/T39412-6.1.1.17 无法执行的死代码",
        "python": "GB/T39412-6.1.1.17 无法执行的死代码",
        "cpp": "GB/T39412-6.1.1.17 无法执行的死代码",
        "csharp": "GB/T39412-6.1.1.17 无法执行的死代码",
    },
    "MISSING_DEFAULT_CASE": {
        "java": "GB/T39412-6.1.1.16 条件语句缺失默认情况",
        "python": "GB/T39412-6.1.1.16 条件语句缺失默认情况",
        "cpp": "GB/T39412-6.1.1.16 条件语句缺失默认情况",
        "csharp": "GB/T39412-6.1.1.16 条件语句缺失默认情况",
    },
    "INSUFFICIENT_COMPARISON": {
        "java": "GB/T39412-6.1.1.10 条件比较不充分",
        "python": "GB/T39412-6.1.1.10 条件比较不充分",
        "cpp": "GB/T39412-6.1.1.10 条件比较不充分",
        "csharp": "GB/T39412-6.1.1.10 条件比较不充分",
    },
    "BYPASS_VALIDATION": {
        "java": "GB/T39412-6.1.1.3 绕过数据净化和验证",
        "python": "GB/T39412-6.1.1.3 绕过数据净化和验证",
        "cpp": "GB/T39412-6.1.1.3 绕过数据净化和验证",
        "csharp": "GB/T39412-6.1.1.3 绕过数据净化和验证",
    },
    "HTTP_HEADER_INJECTION": {
        "java": "GB/T39412-6.1.1.5 HTTP Head Web脚本特殊元素处理",
        "python": "GB/T39412-6.1.1.5 HTTP Head Web脚本特殊元素处理",
        "cpp": "GB/T39412-6.1.1.5 HTTP Head Web脚本特殊元素处理",
        "csharp": "GB/T39412-6.1.1.5 HTTP Head Web脚本特殊元素处理",
    },
    "XSS": {
        "java": "GB/T39412-6.1.2.1 跨站脚本(XSS)攻击",
        "python": "GB/T39412-6.1.2.1 跨站脚本(XSS)攻击",
        "cpp": "GB/T34943-6.2.8.1 跨站脚本",
        "csharp": "GB/T34946-6.2.8.1 跨站脚本（XSS）",
    },
    "OPEN_REDIRECT": {
        "java": "GB/T39412-6.1.2.3 URL重定向向不可信站点",
        "python": "GB/T39412-6.1.2.3 URL重定向向不可信站点",
        "cpp": "GB/T39412-6.1.2.3 URL重定向向不可信站点",
        "csharp": "GB/T34946-6.2.8.4 开放重定向",
    },
    "NO_RATE_LIMIT": {
        "java": "GB/T39412-6.3.1.3 身份鉴别尝试频率限制缺失",
        "python": "GB/T39412-6.3.1.3 身份鉴别尝试频率限制缺失",
        "cpp": "GB/T39412-6.3.1.3 身份鉴别尝试频率限制缺失",
        "csharp": "GB/T39412-6.3.1.3 身份鉴别尝试频率限制缺失",
    },
    "SINGLE_FACTOR_AUTH": {
        "java": "GB/T39412-6.3.1.4 多因素认证缺失",
        "python": "GB/T39412-6.3.1.4 多因素认证缺失",
        "cpp": "GB/T39412-6.3.1.4 多因素认证缺失",
        "csharp": "GB/T39412-6.3.1.4 多因素认证缺失",
    },
    "UNRESTRICTED_LOCK": {
        "java": "GB/T39412-6.3.3.2 未加限制的外部可访问锁",
        "python": "GB/T39412-6.3.3.2 未加限制的外部可访问锁",
        "cpp": "GB/T39412-6.3.3.2 未加限制的外部可访问锁",
        "csharp": "GB/T39412-6.3.3.2 未加限制的外部可访问锁",
    },
    "LOG_INJECTION": {
        "java": "GB/T39412-6.4.1 对输出日志中特殊元素处理",
        "python": "GB/T39412-6.4.1 对输出日志中特殊元素处理",
        "cpp": "GB/T39412-6.4.1 对输出日志中特殊元素处理",
        "csharp": "GB/T39412-6.4.1 对输出日志中特殊元素处理",
    },
    "INVALID_POINTER": {
        "java": "GB/T39412-7.5.6 无效指针使用",
        "python": "GB/T39412-7.5.6 无效指针使用",
        "cpp": "GB/T39412-7.5.6 无效指针使用",
        "csharp": "GB/T39412-7.5.6 无效指针使用",
    },
    "INCOMPATIBLE_POINTER": {
        "java": "GB/T39412-7.5.1 不兼容的指针类型",
        "python": "GB/T39412-7.5.1 不兼容的指针类型",
        "cpp": "GB/T39412-7.5.1 不兼容的指针类型",
        "csharp": "GB/T39412-7.5.1 不兼容的指针类型",
    },
    "UNSAFE_INITIALIZATION": {
        "java": "GB/T39412-8.1.2 资源或变量不安全初始化",
        "python": "GB/T39412-8.1.2 资源或变量不安全初始化",
        "cpp": "GB/T39412-8.1.2 资源或变量不安全初始化",
        "csharp": "GB/T39412-8.1.2 资源或变量不安全初始化",
    },
    "INIT_FAILURE": {
        "java": "GB/T39412-8.1.3 初始化失败后未安全退出",
        "python": "GB/T39412-8.1.3 初始化失败后未安全退出",
        "cpp": "GB/T39412-8.1.3 初始化失败后未安全退出",
        "csharp": "GB/T39412-8.1.3 初始化失败后未安全退出",
    },
    "ALGORITHM_COMPLEXITY": {
        "java": "GB/T39412-8.1.9 算法复杂度攻击",
        "python": "GB/T39412-8.1.9 算法复杂度攻击",
        "cpp": "GB/T39412-8.1.9 算法复杂度攻击",
        "csharp": "GB/T39412-8.1.9 算法复杂度攻击",
    },
    "HEAP_MEMORY_CLEANUP": {
        "java": "GB/T39412-8.2.2 堆内存释放",
        "python": "GB/T39412-8.2.2 堆内存释放",
        "cpp": "GB/T39412-8.2.2 堆内存释放",
        "csharp": "GB/T39412-8.2.2 堆内存释放",
    },
    "UNCONTROLLED_LOOP": {
        "java": "GB/T39412-6.2.3.11 未检查的输入作为循环条件",
        "python": "GB/T39412-6.2.3.11 未检查的输入作为循环条件",
        "cpp": "GB/T34943-6.2.3.12 未检查的输入作为循环条件",
        "csharp": "GB/T34946-6.2.3.11 未检查的输入作为循环条件",
    },
    "CSRF": {
        "java": "GB/T39412-6.1.1.1 输入验证不足",
        "python": "GB/T39412-6.1.1.1 输入验证不足",
        "cpp": "GB/T39412-6.1.1.1 输入验证不足",
        "csharp": "GB/T34946-6.2.8.2 跨站请求伪造（CSRF）",
    },
    "MISSING_CSRF_PROTECTION": {
        "java": "GB/T39412-6.1.1.1 输入验证不足",
        "python": "GB/T39412-6.1.1.1 输入验证不足",
        "cpp": "GB/T39412-6.1.1.1 输入验证不足",
        "csharp": "GB/T34946-6.2.8.2 跨站请求伪造（CSRF）",
    },
    "HTTP_RESPONSE_SPLITTING": {
        "java": "GB/T39412-6.1.1.5 HTTP Head Web脚本特殊元素处理",
        "python": "GB/T39412-6.1.1.5 HTTP Head Web脚本特殊元素处理",
        "cpp": "GB/T39412-6.1.1.5 HTTP Head Web脚本特殊元素处理",
        "csharp": "GB/T34946-6.2.8.3 HTTP响应拆分",
    },
    "CLICKJACKING": {
        "java": "GB/T39412-6.1.1.1 输入验证不足",
        "python": "GB/T39412-6.1.1.1 输入验证不足",
        "cpp": "GB/T39412-6.1.1.1 输入验证不足",
        "csharp": "GB/T39412-6.1.1.1 输入验证不足",
    },
    "FILENAME_EXTENSION_TRUST": {
        "java": "GB/T39412-6.1.1.2 数据真实性验证不足",
        "python": "GB/T39412-6.1.1.2 数据真实性验证不足",
        "cpp": "GB/T39412-6.1.1.2 数据真实性验证不足",
        "csharp": "GB/T34946-6.2.8.5 依赖外部提供的文件的名称或扩展名",
    },
}

def get_gbt_mapping(vuln_type: str, language: str) -> str:
    """获取漏洞类型对应的国标映射
    
    Args:
        vuln_type: 漏洞类型
        language: 语言
        
    Returns:
        str: 国标映射字符串
    """
    if vuln_type in VULN_TYPE_TO_GBT_MAPPING:
        lang_mapping = VULN_TYPE_TO_GBT_MAPPING[vuln_type]
        if language in lang_mapping:
            return lang_mapping[language]
        elif "python" in lang_mapping:
            return lang_mapping["python"]
    return "GB/T39412-6.1.1.1 输入验证不足"