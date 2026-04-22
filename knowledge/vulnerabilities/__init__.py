"""
漏洞知识库索引

按漏洞类型组织的知识库，方便快速检索
"""

from pathlib import Path
from typing import Dict, List, Optional

VULNERABILITY_CATEGORIES = {
    "sql_injection": {
        "name": "SQL注入",
        "severity": "严重",
        "cwe": ["CWE-89", "CWE-943"],
        "files": ["sql_injection.md"],
    },
    "command_injection": {
        "name": "命令注入",
        "severity": "严重",
        "cwe": ["CWE-78", "CWE-88"],
        "files": ["command_injection.md"],
    },
    "code_injection": {
        "name": "代码注入",
        "severity": "严重",
        "cwe": ["CWE-94", "CWE-95"],
        "files": ["code_injection.md"],
    },
    "deserialization": {
        "name": "反序列化",
        "severity": "严重",
        "cwe": ["CWE-502", "CWE-915"],
        "files": ["deserialization.md"],
    },
    "hardcoded_credentials": {
        "name": "硬编码密码/密钥",
        "severity": "严重",
        "cwe": ["CWE-259", "CWE-321", "CWE-798"],
        "files": ["hardcoded_credentials.md"],
    },
    "path_traversal": {
        "name": "路径遍历",
        "severity": "高危",
        "cwe": ["CWE-22", "CWE-23", "CWE-36"],
        "files": ["path_traversal.md"],
    },
    "weak_crypto": {
        "name": "弱哈希/弱加密",
        "severity": "高危",
        "cwe": ["CWE-327", "CWE-328", "CWE-835"],
        "files": ["weak_crypto.md"],
    },
    "xss": {
        "name": "跨站脚本(XSS)",
        "severity": "中危",
        "cwe": ["CWE-79", "CWE-80", "CWE-81"],
        "files": [],
    },
    "csrf": {
        "name": "跨站请求伪造",
        "severity": "中危",
        "cwe": ["CWE-352"],
        "files": [],
    },
    "buffer_overflow": {
        "name": "缓冲区溢出",
        "severity": "严重",
        "cwe": ["CWE-119", "CWE-120", "CWE-122"],
        "files": [],
    },
    "format_string": {
        "name": "格式化字符串",
        "severity": "高危",
        "cwe": ["CWE-134"],
        "files": [],
    },
    "ssrf": {
        "name": "服务器端请求伪造",
        "severity": "高危",
        "cwe": ["CWE-918"],
        "files": [],
    },
    "xxe": {
        "name": "XML外部实体注入",
        "severity": "高危",
        "cwe": ["CWE-611"],
        "files": [],
    },
}


def get_knowledge_dir() -> Path:
    """获取知识库目录路径"""
    return Path(__file__).parent


def load_vulnerability_knowledge(vuln_type: str) -> Optional[str]:
    """加载指定漏洞类型的知识文档

    Args:
        vuln_type: 漏洞类型标识符

    Returns:
        知识文档内容，如果不存在返回 None
    """
    if vuln_type not in VULNERABILITY_CATEGORIES:
        return None

    category = VULNERABILITY_CATEGORIES[vuln_type]
    if not category["files"]:
        return None

    knowledge_dir = get_knowledge_dir()
    file_path = knowledge_dir / "vulnerabilities" / category["files"][0]

    if file_path.exists():
        return file_path.read_text(encoding="utf-8")
    return None


def get_all_vulnerability_types() -> List[str]:
    """获取所有漏洞类型列表"""
    return list(VULNERABILITY_CATEGORIES.keys())


def search_knowledge_by_cwe(cwe_id: str) -> Optional[str]:
    """根据 CWE ID 搜索漏洞知识

    Args:
        cwe_id: CWE ID (如 "CWE-89")

    Returns:
        匹配的知识文档内容
    """
    for vuln_type, category in VULNERABILITY_CATEGORIES.items():
        if cwe_id in category.get("cwe", []):
            return load_vulnerability_knowledge(vuln_type)
    return None


def get_knowledge_summary() -> Dict:
    """获取知识库摘要信息"""
    summary = {
        "total_types": len(VULNERABILITY_CATEGORIES),
        "with_docs": sum(1 for c in VULNERABILITY_CATEGORIES.values() if c["files"]),
        "categories": [],
    }

    for vuln_type, category in VULNERABILITY_CATEGORIES.items():
        summary["categories"].append({
            "id": vuln_type,
            "name": category["name"],
            "severity": category["severity"],
            "has_doc": bool(category["files"]),
            "cwe": category.get("cwe", []),
        })

    return summary
