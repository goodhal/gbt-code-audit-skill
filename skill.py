#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代码安全审计技能

支持基于中国国家标准的代码安全审计，利用 Agent 的 LLM 进行智能审计。
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any

# Windows GBK 修复：强制 stdout 使用 UTF-8
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

PROJECT_ROOT = Path(__file__).parent
RULES_DIR = PROJECT_ROOT / "rules"

# 语言到标准的映射
LANGUAGE_STANDARD_MAP = {
    "java": ["34944"],
    "cpp": ["34943"],
    "c++": ["34943"],
    "csharp": ["34946"],
    "c#": ["34946"],
    "python": ["39412"],
    "javascript": ["39412"],
    "typescript": ["39412"],
    "go": ["39412"],
}

# 标准文件映射
STANDARD_FILES = {
    "34943": "GBT_34943-2017.md",
    "34944": "GBT_34944-2017.md",
    "34946": "GBT_34946-2017.md",
    "39412": "GBT_39412-2020.md",
}

# 标准中文名
STANDARD_NAMES = {
    "34943": "GB/T 34943-2017 C/C++ 语言",
    "34944": "GB/T 34944-2017 Java 语言",
    "34946": "GB/T 34946-2017 C# 语言",
    "39412": "GB/T 39412-2020 通用",
}


def detect_language(target_path: str) -> Dict:
    """检测代码目录使用的语言"""
    target = Path(target_path)
    if not target.exists():
        return {"success": False, "error": f"路径不存在: {target_path}"}

    language_signatures = {
        "java": ["*.java"],
        "cpp": ["*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp"],
        "csharp": ["*.cs"],
        "python": ["*.py"],
        "javascript": ["*.js", "*.jsx"],
        "typescript": ["*.ts", "*.tsx"],
        "go": ["*.go"],
    }

    counts = {}
    for lang, patterns in language_signatures.items():
        count = 0
        for pattern in patterns:
            count += len(list(target.rglob(pattern)))
        if count > 0:
            counts[lang] = count

    if not counts:
        return {"success": False, "error": "未检测到已知语言代码"}

    sorted_langs = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    detected_languages = [lang for lang, _ in sorted_langs]

    # 映射到标准
    standards = []
    for lang in detected_languages:
        for std in LANGUAGE_STANDARD_MAP.get(lang, []):
            if std not in standards:
                standards.append(std)

    # 确保包含通用基线标准 39412
    if "39412" not in standards:
        standards.append("39412")

    return {
        "success": True,
        "target": str(target),
        "languages": detected_languages,
        "standards": standards,
        "file_counts": counts,
        "standard_names": [STANDARD_NAMES.get(s, s) for s in standards],
    }


def get_standards(languages: List[str] = None, target_path: str = None) -> Dict:
    """获取语言对应的审计标准"""
    if not languages and target_path:
        lang_result = detect_language(target_path)
        languages = lang_result.get("languages", ["java"]) if lang_result["success"] else ["java"]

    if not languages:
        languages = ["java"]

    result = []
    for lang in languages:
        lang_lower = lang.lower()
        for std_code in LANGUAGE_STANDARD_MAP.get(lang_lower, []):
            rule_count = get_rule_count(std_code)
            result.append({
                "code": std_code,
                "name": STANDARD_NAMES.get(std_code, std_code),
                "language": lang,
                "rule_count": rule_count,
            })

    # 添加通用标准
    has_general = any(s["code"] == "39412" for s in result)
    if not has_general:
        result.append({
            "code": "39412",
            "name": "GB/T 39412-2020 通用",
            "language": "all",
            "rule_count": get_rule_count("39412"),
        })

    return {"success": True, "standards": result}


def get_rule_count(standard: str) -> int:
    """获取标准的规则数量"""
    rules_file = RULES_DIR / STANDARD_FILES.get(standard, "")
    if not rules_file.exists():
        return 0

    try:
        content = rules_file.read_text(encoding="utf-8")
        # 从文件头部读取
        m = re.search(r"\*\*规则数量\*\*[：:]\s*(\d+)", content)
        if m:
            return int(m.group(1))
        # 否则统计 ### 标题数
        return len(re.findall(r"^### ", content, re.MULTILINE))
    except Exception:
        return 0


def get_rules(standard: str = "34944", format: str = "summary") -> Dict:
    """获取标准的完整规则"""
    try:
        rules = []
        
        # 首先读取传入的标准号对应的规则
        if standard in STANDARD_FILES:
            rules_file = RULES_DIR / STANDARD_FILES[standard]
            if rules_file.exists():
                content = rules_file.read_text(encoding="utf-8")
                # 匹配规则块
                pattern = re.compile(
                    r"^###\s+问题分类(GB/T\d+-\d+[\d.-]*)\s+.*?\n"
                    r"\*\*严重级别\*\*[：:]\s*(\w+)"
                    r".*?\*\*CWE\*\*[：:]\s*\[?(CWE-\d+)\]?",
                    re.MULTILINE | re.DOTALL,
                )

                sev_map = {
                    "CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危", "LOW": "低危",
                    "严重": "严重", "高危": "高危", "中危": "中危", "低危": "低危",
                }

                for m in pattern.finditer(content):
                    code = m.group(1)
                    sev_raw = m.group(2).upper()
                    cwe = m.group(3)
                    sev = sev_map.get(sev_raw, "中危")

                    # 提取规则名
                    title_match = re.search(rf"^###\s+问题分类{re.escape(code)}\s+(.*?)\s*$", content, re.MULTILINE)
                    name = ""
                    if title_match:
                        name = re.sub(r"[🔴🟠🟡🟢🔵⚪\s]+", "", title_match.group(1)).strip()

                    rule = {"code": code, "cwe": cwe, "name": name, "severity": sev}
                    
                    if format == "full":
                        # 提取完整块内容
                        block_start = m.start()
                        next_rule = re.search(r"^### ", content[m.end():], re.MULTILINE)
                        block_end = m.end() + next_rule.start() if next_rule else len(content)
                        rule["description"] = content[block_start:block_end].strip()
                    
                    rules.append(rule)
        
        # 如果没有规则，返回错误
        if not rules:
            return {
                "success": False,
                "error": f"标准文件不存在: {standard}",
                "available": list(STANDARD_FILES.keys()),
            }

        return {
            "success": True,
            "standard": standard,
            "name": STANDARD_NAMES.get(standard, standard),
            "rule_count": len(rules),
            "rules": rules,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def get_audit_prompt() -> Dict:
    """返回完整的 audit_prompt.md 内容，供 LLM 参考"""
    prompt_file = PROJECT_ROOT / "mcp" / "audit_prompt.md"

    if not prompt_file.exists():
        return {
            "success": False,
            "error": "audit_prompt.md 文件不存在",
            "hint": "请确保 audit_prompt.md 在 mcp/ 目录下"
        }

    try:
        content = prompt_file.read_text(encoding="utf-8")
        return {
            "success": True, 
            "prompt": content, 
            "source": "audit_prompt.md",
            "message": "提示词读取成功，请按照审计指南中的步骤执行后续操作"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_report_template() -> Dict:
    """返回标准的报告模板，供 LLM 生成报告时参考"""
    try:
        template_file = PROJECT_ROOT / "mcp" / "report_template.md"
        
        if not template_file.exists():
            return {
                "success": False, 
                "error": "报告模板文件 report_template.md 不存在"
            }
        
        content = template_file.read_text(encoding="utf-8")
        return {"success": True, "template": content, "source": "report_template.md"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def scan(target_path: str, bytecode: bool = False) -> Dict:
    """执行工具扫描（SpotBugs 字节码扫描）"""
    target = Path(target_path)
    if not target.exists():
        return {"success": False, "error": f"路径不存在: {target_path}"}

    try:
        import subprocess
        import tempfile
        import os
        
        # 检查 Java 环境
        try:
            java_version = subprocess.run(
                ["java", "-version"],
                capture_output=True,
                text=True
            )
            if java_version.returncode != 0:
                return {
                    "success": False,
                    "error": "Java environment not installed or configured correctly",
                    "details": "Please install JDK 8 or higher version, and ensure java command is in system PATH"
                }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "Java command not found",
                "details": "Please install JDK 8 or higher version, and ensure java command is in system PATH"
            }
        
        # 检查是否有 Java 文件需要扫描
        java_files = list(target.rglob("*.java"))
        if not java_files:
            return {
                "success": False,
                "error": "No Java files found",
                "details": "SpotBugs can only scan Java bytecode files, no .java files found in target directory"
            }
        
        # 检查是否有编译好的字节码文件
        class_files = list(target.rglob("*.class"))
        if not class_files:
            return {
                "success": False,
                "error": "No compiled Java bytecode files found",
                "details": "SpotBugs requires compiled .class files to scan, please compile Java code first"
            }
        
        # 检查 SpotBugs JAR 文件是否存在
        spotbugs_dir = PROJECT_ROOT / "vendor" / "spotbugs"
        spotbugs_jar = spotbugs_dir / "spotbugs.jar"
        if not spotbugs_jar.exists():
            return {
                "success": False,
                "error": "SpotBugs JAR 文件未找到",
                "details": f"请确保 SpotBugs JAR 文件存在于 {spotbugs_jar}"
            }
        
        # 构建类路径
        classpath = []
        for jar_file in spotbugs_dir.glob("*.jar"):
            classpath.append(str(jar_file))
        classpath_str = ";".join(classpath)  # Windows 用分号分隔
        
        # 执行 SpotBugs 扫描
        with tempfile.TemporaryDirectory() as temp_dir:
            # 构建 SpotBugs 命令（使用 Java 直接运行 JAR 文件）
            # 使用 -jar 参数直接运行 spotbugs.jar，Java 会自动使用清单文件中指定的主类
            spotbugs_jar = spotbugs_dir / "spotbugs.jar"
            # 确保工作目录设置为 spotbugs 目录，这样它可以找到依赖的 JAR 文件
            spotbugs_cmd = [
                "java",
                "-jar", str(spotbugs_jar),
                "-textui",
                "-xml:withMessages",
                "-outputFile", os.path.join(temp_dir, "spotbugs-result.xml"),
                str(target)
            ]
            
            # 执行扫描，不设置工作目录，使用绝对路径
            scan_result = subprocess.run(
                spotbugs_cmd,
                capture_output=True,
                text=True
            )
            
            # 读取扫描结果
            result_file = os.path.join(temp_dir, "spotbugs-result.xml")
            if os.path.exists(result_file):
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(result_file)
                    root = tree.getroot()
                    
                    # 解析 XML 结果
                    findings = []
                    for bug_instance in root.findall(".//BugInstance"):
                        bug_type = bug_instance.get("type")
                        cwe = bug_instance.get("cweId")
                        
                        # 查找源文件和行号
                        source_line = bug_instance.find(".//SourceLine")
                        if source_line is not None:
                            file_name = source_line.get("sourcepath") or source_line.get("classname")
                            line_number = source_line.get("start")
                            
                            findings.append({
                                "type": bug_type,
                                "file": file_name,
                                "line": int(line_number) if line_number else 0,
                                "cwe": f"CWE-{cwe}" if cwe else "Unknown"
                            })
                    
                    return {
                        "success": True,
                        "target": str(target),
                        "bytecode": bytecode,
                        "findings": findings,
                        "summary": {
                            "total": len(findings),
                            "java": len(findings),
                            "cpp": 0,
                            "csharp": 0,
                            "python": 0
                        },
                        "scan_output": scan_result.stdout,
                        "scan_error": scan_result.stderr
                    }
                except ET.ParseError as e:
                    return {
                        "success": False,
                        "error": f"扫描结果解析失败: {str(e)}",
                        "details": "SpotBugs 扫描完成，但生成的扫描结果文件格式不正确",
                        "scan_output": scan_result.stdout,
                        "scan_error": scan_result.stderr
                    }
            else:
                return {
                    "success": False,
                    "error": "SpotBugs 扫描失败",
                    "details": f"扫描命令执行失败: {scan_result.stderr}"
                }
    except Exception as e:
        return {
            "success": False,
            "error": f"扫描过程中发生错误: {str(e)}",
            "details": "请检查 Java 环境和 SpotBugs 配置"
        }

def audit_code(target_path: str, languages: List[str] = None, standards: List[str] = None) -> Dict:
    """使用 LLM 对代码进行安全审计"""
    target = Path(target_path)
    if not target.exists():
        return {"success": False, "error": f"路径不存在: {target_path}"}
    
    # 如果未指定语言，自动检测
    if not languages:
        lang_result = detect_language(target_path)
        if not lang_result["success"]:
            return lang_result
        languages = lang_result["languages"]
    
    # 如果未指定标准，根据语言自动选择
    if not standards:
        std_result = get_standards(languages=languages)
        if not std_result["success"]:
            return std_result
        standards = [std["code"] for std in std_result["standards"]]
    
    # 收集代码文件
    code_files = []
    language_extensions = {
        "java": [".java"],
        "cpp": [".cpp", ".cc", ".cxx", ".h", ".hpp"],
        "csharp": [".cs"],
        "python": [".py"],
        "javascript": [".js", ".jsx"],
        "typescript": [".ts", ".tsx"],
        "go": [".go"],
    }
    
    for lang in languages:
        extensions = language_extensions.get(lang, [])
        for ext in extensions:
            code_files.extend(list(target.rglob(f"*{ext}")))
    
    if not code_files:
        return {"success": False, "error": "未找到代码文件"}
    
    # 构建审计提示
    audit_prompt = get_audit_prompt()
    if not audit_prompt["success"]:
        return audit_prompt
    
    # 构建规则信息
    rules_info = []
    for std in standards:
        std_rules = get_rules(standard=std, format="summary")
        if std_rules["success"]:
            rules_info.append({
                "standard": std,
                "name": std_rules["name"],
                "rules": std_rules["rules"]
            })
    
    # 构建代码审计请求
    audit_request = {
        "target": str(target),
        "languages": languages,
        "standards": standards,
        "code_files": [str(f) for f in code_files[:50]],  # 限制文件数量
        "file_count": len(code_files),
        "rules_info": rules_info,
        "audit_guideline": audit_prompt["prompt"],
        "instructions": """
请按照以下步骤进行代码安全审计：
1. 分析提供的代码文件，识别潜在的安全漏洞
2. 对照相关国家标准规则，对每个漏洞进行分类和评级
3. 提供详细的漏洞描述、风险分析和修复建议
4. 生成符合标准格式的审计报告

重点关注以下类型的安全问题：
- 输入验证与数据清洗
- 错误处理与异常安全
- 代码质量与内存管理
- 封装与序列化安全
- Web 安全（XSS、CSRF、SSRF）
- SQL/命令/代码注入
- 敏感数据保护
- 加密与密钥管理
- 线程安全与并发
- 会话管理

请确保审计结果符合中国国家标准（GB/T 34943/34944/34946/39412）的要求。
"""
    }
    
    return {
        "success": True,
        "audit_request": audit_request,
        "message": "代码审计请求已准备就绪，请使用 LLM 进行智能审计",
        "hint": "请将此请求传递给 LLM，并根据 LLM 的输出生成最终审计报告"
    }


def main():
    """技能主入口"""
    if len(sys.argv) < 2:
        print(json.dumps({
            "success": False,
            "error": "缺少命令参数",
            "usage": "python skill.py <command> [args]"
        }, ensure_ascii=False))
        return
    
    command = sys.argv[1]
    
    if command == "detect_language":
        if len(sys.argv) < 3:
            print(json.dumps({"success": False, "error": "缺少 target 参数"}, ensure_ascii=False))
            return
        result = detect_language(sys.argv[2])
    
    elif command == "get_standards":
        languages = None
        target = None
        if len(sys.argv) > 2:
            if sys.argv[2].startswith("--languages="):
                languages = sys.argv[2].split("=")[1].split(",")
            elif sys.argv[2].startswith("--target="):
                target = sys.argv[2].split("=")[1]
        result = get_standards(languages=languages, target_path=target)
    
    elif command == "get_rules":
        standard = "34944"
        format = "summary"
        if len(sys.argv) > 2:
            for arg in sys.argv[2:]:
                if arg.startswith("--standard="):
                    standard = arg.split("=")[1]
                elif arg.startswith("--format="):
                    format = arg.split("=")[1]
        result = get_rules(standard=standard, format=format)
    
    elif command == "scan":
        if len(sys.argv) < 3:
            print(json.dumps({"success": False, "error": "缺少 target 参数"}, ensure_ascii=False))
            return
        target = sys.argv[2]
        bytecode = False
        if len(sys.argv) > 3 and sys.argv[3] == "--bytecode":
            bytecode = True
        result = scan(target_path=target, bytecode=bytecode)
    
    elif command == "get_audit_prompt":
        result = get_audit_prompt()
    
    elif command == "get_report_template":
        result = get_report_template()
    
    elif command == "audit_code":
        if len(sys.argv) < 3:
            print(json.dumps({"success": False, "error": "缺少 target 参数"}, ensure_ascii=False))
            return
        target = sys.argv[2]
        languages = None
        standards = None
        if len(sys.argv) > 3:
            for arg in sys.argv[3:]:
                if arg.startswith("--languages="):
                    languages = arg.split("=")[1].split(",")
                elif arg.startswith("--standards="):
                    standards = arg.split("=")[1].split(",")
        result = audit_code(target_path=target, languages=languages, standards=standards)
    
    else:
        result = {"success": False, "error": f"未知命令: {command}"}
    
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
