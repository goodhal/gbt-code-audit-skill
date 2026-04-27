"""
快速扫描模式模块
支持从 YAML 配置文件加载漏洞检测规则
"""
import re
import os
from typing import Dict, List, Optional
from pathlib import Path

import yaml

_COMPILED_PATTERNS: Dict[str, List[tuple]] = {}
_RULES_VERSION: str = ""
_RULES_PATH: Optional[str] = None

def get_rules_path() -> str:
    """获取规则文件路径"""
    global _RULES_PATH
    if _RULES_PATH:
        return _RULES_PATH

    script_dir = Path(__file__).parent.resolve()
    default_path = script_dir / "vulnerability_rules.yaml"

    env_path = os.environ.get("AUDIT_RULES_PATH")
    if env_path and Path(env_path).exists():
        _RULES_PATH = env_path
    elif default_path.exists():
        _RULES_PATH = str(default_path)
    else:
        raise FileNotFoundError(f"规则文件未找到: {default_path}")

    return _RULES_PATH

def load_rules_from_yaml() -> Dict[str, List[Dict]]:
    """从 YAML 文件加载规则

    Returns:
        Dict[str, List[Dict]]: 语言到规则列表的映射
    """
    rules_path = get_rules_path()
    with open(rules_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    global _RULES_VERSION
    _RULES_VERSION = data.get("version", "1.0")

    return data.get("rules", {})

def quick_scan_patterns() -> Dict[str, List[tuple]]:
    """快速扫描模式

    负责发现高风险函数调用，如命令注入、SQL注入、缓冲区溢出等。
    这些漏洞特征明显，可以通过正则表达式快速识别。

    Returns:
        Dict[str, List[tuple]]: 语言到模式的映射
    """
    raw_rules = load_rules_from_yaml()

    patterns = {}
    for lang, rules in raw_rules.items():
        lang_patterns = []
        for rule in rules:
            pattern = rule.get("pattern", "")
            vuln_type = rule.get("vuln_type", "UNKNOWN")
            cwe = rule.get("cwe", "CWE-000")
            severity = rule.get("severity", "未知")
            lang_patterns.append((pattern, vuln_type, cwe, severity))
        patterns[lang] = lang_patterns

    return patterns

def _init_compiled_patterns():
    """模块加载时预编译所有正则表达式"""
    pattern_strings = quick_scan_patterns()
    for lang, patterns in pattern_strings.items():
        compiled = []
        for pattern, vuln_type, cwe, severity in patterns:
            try:
                compiled.append((re.compile(pattern), vuln_type, cwe, severity))
            except re.error as e:
                print(f"警告: 语言 {lang} 的正则表达式编译失败: {pattern}, 错误: {e}")
        _COMPILED_PATTERNS[lang] = compiled

_init_compiled_patterns()

def get_compiled_patterns() -> Dict[str, List[tuple]]:
    """获取预编译的模式

    Returns:
        Dict[str, List[tuple]]: 语言到编译后模式的映射
    """
    return _COMPILED_PATTERNS

def get_rules_version() -> str:
    """获取当前加载的规则版本

    Returns:
        str: 规则版本号
    """
    return _RULES_VERSION

def get_supported_languages() -> List[str]:
    """获取支持的语言列表

    Returns:
        List[str]: 语言列表
    """
    return list(_COMPILED_PATTERNS.keys())

def get_rule_count() -> Dict[str, int]:
    """获取各语言的规则数量

    Returns:
        Dict[str, int]: 语言到规则数量的映射
    """
    return {lang: len(patterns) for lang, patterns in _COMPILED_PATTERNS.items()}

def reload_rules():
    """重新加载规则（用于热更新）"""
    global _COMPILED_PATTERNS, _RULES_VERSION, _RULES_PATH
    _COMPILED_PATTERNS = {}
    _RULES_VERSION = ""
    _RULES_PATH = None
    _init_compiled_patterns()
