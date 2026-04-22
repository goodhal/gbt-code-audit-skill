"""
安全知识库

按漏洞类型组织的知识库，包含危险模式、安全实践、修复示例
"""

from .vulnerabilities import (
    VULNERABILITY_CATEGORIES,
    get_knowledge_dir,
    load_vulnerability_knowledge,
    get_all_vulnerability_types,
    search_knowledge_by_cwe,
    get_knowledge_summary,
)

__all__ = [
    "VULNERABILITY_CATEGORIES",
    "get_knowledge_dir",
    "load_vulnerability_knowledge",
    "get_all_vulnerability_types",
    "search_knowledge_by_cwe",
    "get_knowledge_summary",
]
